#!/usr/bin/env python3
"""
Mint console for OpenSea SeaDrop collections.

Reads a drop straight from the chain, benchmarks the RPC, then mints from a
wallet you already control.

On Arbitrum Orbit chains (Robinhood among them) the sequencer orders by
ARRIVAL, not by fee -- eth_maxPriorityFeePerGas returns 0 and there is no
mempool, so you cannot outbid anyone and nobody can outbid you. Measurement
from Singapore puts TCP+TLS at ~75ms but time-to-first-byte between 350ms and
1,645ms, so the backend's variance dominates by an order of magnitude.

That shapes the whole design: the transaction is signed up front and the same
signed bytes are fired down several pre-warmed connections at once. You are
not trying to be physically closer; you are drawing several samples from a
wide latency distribution and keeping the best one. Duplicate submissions of
one signed transaction are safe -- same nonce, same hash, so at most one can
ever land.
"""
import http.server, socketserver, json, subprocess, urllib.request, urllib.parse
import ssl, http.client, threading, time, os, re, socket, secrets, hmac, hashlib, base64

PORT = int(os.environ.get('PORT', '8899'))
HERE = os.path.dirname(os.path.abspath(__file__))
BIND = os.environ.get('BIND', '127.0.0.1')

# Every endpoint can sign with whatever key material is on this host, so the
# whole surface is gated. A token is generated on first run if none is set;
# WASABI_TOKEN overrides it. Loopback-only deployments are still gated, because
# any page in the browser can reach 127.0.0.1.
TOKEN = os.environ.get('WASABI_TOKEN') or secrets.token_urlsafe(24)

# Wallet files may only be read from inside these roots. The path parameter
# previously accepted absolute paths and "..", which on an exposed host is a
# read primitive aimed at exactly the files that must never leak.
WALLET_ROOTS = []

# --------------------------------------------------------------------- auth
# Accounts do not make a signing service safer on their own -- everyone who
# gets in can sign with the same wallet files. They are worth it only because
# they replace a token in the URL (which leaks into history, referrers and
# screenshots) and because entry is restricted to an allowlist. Open signup
# would mean custodying other people's keys on an internet-facing host.
USERS_FILE = os.path.join(HERE, 'users.json')
SESSION_TTL = int(os.environ.get('SESSION_TTL', 60 * 60 * 12))
ALLOWED = {e.strip().lower() for e in
           os.environ.get('WASABI_ALLOWED_EMAILS', '').split(',') if e.strip()}
GOOGLE_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
PUBLIC_URL = os.environ.get('PUBLIC_URL', '').rstrip('/')
_sessions = {}          # sid -> {email, exp}
_oauth_states = {}      # state -> exp
_authlock = threading.Lock()


def _users():
    try:
        return json.load(open(USERS_FILE))
    except Exception:
        return {}


def _save_users(d):
    old = os.umask(0o077)
    try:
        json.dump(d, open(USERS_FILE, 'w'), indent=2)
    finally:
        os.umask(old)


# scrypt is preferred but is missing from some Python builds (notably the
# macOS system interpreter, whose libressl does not expose it), so the format
# carries its algorithm and PBKDF2 is used where scrypt is unavailable.
HAVE_SCRYPT = hasattr(hashlib, 'scrypt')
PBKDF2_ROUNDS = 600_000


def _derive(pw, salt, alg):
    if alg == 'scrypt':
        return hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, PBKDF2_ROUNDS, dklen=32)


def hash_pw(pw, salt=None):
    alg = 'scrypt' if HAVE_SCRYPT else 'pbkdf2'
    salt = salt or secrets.token_bytes(16)
    dk = _derive(pw, salt, alg)
    return f'{alg}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}'


def check_pw(pw, stored):
    try:
        parts = stored.split('$')
        if len(parts) == 2:            # pre-tag records were scrypt
            alg, s64, d64 = 'scrypt', parts[0], parts[1]
        else:
            alg, s64, d64 = parts
        if alg == 'scrypt' and not HAVE_SCRYPT:
            return False
        dk = _derive(pw, base64.b64decode(s64), alg)
        return hmac.compare_digest(dk, base64.b64decode(d64))
    except Exception:
        return False


def email_allowed(email):
    """An empty allowlist means first-run claim: the first account owns it."""
    email = (email or '').lower()
    if ALLOWED:
        return email in ALLOWED
    return not _users()


def new_session(email):
    with _authlock:
        for sid, v in list(_sessions.items()):     # drop expired
            if v['exp'] < time.time():
                _sessions.pop(sid, None)
        sid = secrets.token_urlsafe(32)
        _sessions[sid] = {'email': email, 'exp': time.time() + SESSION_TTL}
    return sid


def session_email(sid):
    v = _sessions.get(sid or '')
    if not v or v['exp'] < time.time():
        return None
    return v['email']


def google_auth_url(state, redirect_uri):
    q = urllib.parse.urlencode({
        'client_id': GOOGLE_ID, 'redirect_uri': redirect_uri,
        'response_type': 'code', 'scope': 'openid email profile',
        'state': state, 'access_type': 'online', 'prompt': 'select_account'})
    return 'https://accounts.google.com/o/oauth2/v2/auth?' + q


def google_exchange(code, redirect_uri):
    """Swap the code for a token, then ask Google who it belongs to.

    Reading userinfo over TLS avoids verifying the id_token's RSA signature,
    which the standard library cannot do -- the answer comes straight from
    Google either way.
    """
    body = urllib.parse.urlencode({
        'code': code, 'client_id': GOOGLE_ID, 'client_secret': GOOGLE_SECRET,
        'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'}).encode()
    req = urllib.request.Request('https://oauth2.googleapis.com/token', body,
                                 {'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=20) as r:
        tok = json.load(r)
    at = tok.get('access_token')
    if not at:
        raise ValueError('google did not return an access token')
    req = urllib.request.Request('https://openidconnect.googleapis.com/v1/userinfo',
                                 headers={'Authorization': 'Bearer ' + at})
    with urllib.request.urlopen(req, timeout=20) as r:
        info = json.load(r)
    if not info.get('email_verified'):
        raise ValueError('google account has no verified email')
    return info


def load_env():
    """Read KEY=VALUE from nearby .env files so the key need not be sourced.

    Anything already in the environment wins, so an explicit
    OPENSEA_API_KEY=... on the command line still overrides the file.
    """
    for name in ('.env', '.env.arrowbow',
                 os.path.join('..', '.env'), os.path.join('..', '.env.arrowbow')):
        path = os.path.join(HERE, name)
        if not os.path.isfile(path):
            continue
        try:
            for line in open(path):
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k, v = k.strip(), v.strip().strip('\'"')
                if k and v and k not in os.environ:
                    os.environ[k] = v
        except Exception:
            pass


load_env()
CACHE = os.path.join(HERE, 'collections.json')
WALLET_ROOTS.extend([os.path.realpath(os.path.join(HERE, '..', 'wallets')),
                     os.path.realpath(os.path.join(HERE, 'wallets'))])


def safe_wallet_path(path):
    """Resolve a user-supplied wallet path, or refuse.

    Absolute paths and traversal are rejected outright; what remains must
    resolve inside WALLET_ROOTS after symlinks, so a symlink planted in the
    wallets directory cannot reach outside it either.
    """
    if not path or not isinstance(path, str):
        raise ValueError('no wallet file given')
    if os.path.isabs(path) or '..' in path.replace('\\', '/').split('/'):
        raise ValueError('wallet path must be relative and inside the wallets directory')
    for root in WALLET_ROOTS:
        cand = os.path.realpath(os.path.join(root, os.path.basename(path)))
        if cand.startswith(root + os.sep) and os.path.isfile(cand):
            return cand
    raise ValueError('wallet file not found in ' +
                     ' or '.join(WALLET_ROOTS) + ' (filename only, no directories)')
KEYFILE = os.path.join(HERE, 'apikey.json')
_keylock = threading.Lock()


def api_key():
    """An OpenSea key, minted on demand.

    OpenSea issues free agent keys with no signup at POST /api/v2/auth/keys:
    600 reads an hour, valid seven days. The creation endpoint is itself
    rate-limited to a couple of calls, and extra keys do not raise throughput,
    so one key is minted, written to disk and reused until it is nearly
    expired. OPENSEA_API_KEY overrides all of this.
    """
    env = os.environ.get('OPENSEA_API_KEY')
    if env:
        return env
    with _keylock:
        try:
            d = json.load(open(KEYFILE))
            exp = d.get('expires_at', '')
            # refresh inside the last 12h rather than failing mid-session
            left = (time.mktime(time.strptime(exp[:19], '%Y-%m-%dT%H:%M:%S'))
                    - time.time()) if exp else -1
            if d.get('api_key') and left > 12 * 3600:
                return d['api_key']
        except Exception:
            pass
        try:
            req = urllib.request.Request('https://api.opensea.io/api/v2/auth/keys',
                                         b'', UA, method='POST')
            with urllib.request.urlopen(req, timeout=20) as r:
                d = json.load(r)
            if d.get('api_key'):
                old = os.umask(0o077)
                try:
                    json.dump(d, open(KEYFILE, 'w'), indent=2)
                finally:
                    os.umask(old)
                return d['api_key']
        except Exception:
            pass
    return None


def os_get(path, timeout=20):
    """GET an OpenSea endpoint with the key attached; surfaces 429 politely."""
    hdr = dict(UA)
    k = api_key()
    if k:
        hdr['X-API-KEY'] = k
    req = urllib.request.Request(f'https://api.opensea.io/api/v2/{path}', headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), dict(r.headers)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise ValueError('OpenSea rate limit reached; retry after '
                             + (e.headers.get('Retry-After') or 'a moment') + 's')
        raise


def cache_load():
    try:
        return json.load(open(CACHE))
    except Exception:
        return {}


def cache_put(slug, rec):
    d = cache_load()
    d[slug.lower()] = rec
    try:
        json.dump(d, open(CACHE, 'w'), indent=2)
    except Exception:
        pass

CHAINS = {
    'robinhood': ('https://rpc.mainnet.chain.robinhood.com', 4663),
    'ethereum':  ('https://ethereum-rpc.publicnode.com', 1),
    'base':      ('https://mainnet.base.org', 8453),
    'arbitrum':  ('https://arb1.arbitrum.io/rpc', 42161),
    'optimism':  ('https://mainnet.optimism.io', 10),
    'polygon':   ('https://polygon-bor-rpc.publicnode.com', 137),
}
SEADROP = '0x00005EA00Ac477B1030CE78506496e8C2dE24bf5'
# Submit-only sequencer endpoints. Orbit chains order by ARRIVAL at the
# sequencer, so the public RPC -- Cloudflare, then a gateway, then the same
# sequencer -- is pure added latency on the write path. Measured from
# Singapore: public RPC 830ms median with a 284ms spread, sequencer 266ms with
# an 18ms spread. It accepts eth_sendRawTransaction and rejects reads.
SUBMIT = {'robinhood': 'https://sequencer.mainnet.chain.robinhood.com'}
EXPLORER = {
    'robinhood': 'https://robinhoodchain.blockscout.com',
    'ethereum': 'https://etherscan.io', 'base': 'https://basescan.org',
    'arbitrum': 'https://arbiscan.io', 'optimism': 'https://optimistic.etherscan.io',
    'polygon': 'https://polygonscan.com',
}
OS_CHAIN = {'polygon': 'matic'}          # OpenSea's slug differs for a few
# How far back to scan for mint events, per chain. Block times differ by two
# orders of magnitude, so a fixed block count would be four days on Robinhood
# and eighteen months on Ethereum.
LOOKBACK = {'robinhood': 4_000_000, 'ethereum': 220_000, 'base': 1_300_000,
            'arbitrum': 8_000_000, 'optimism': 1_300_000, 'polygon': 1_300_000}
SEADROP_MINT = '0xe90cf9cc0a552cf52ea6ff74ece0f1c8ae8cc9ad630d3181f55ac43ca076b7d6'

SEL = {
    'name': '0x06fdde03', 'symbol': '0x95d89b41', 'totalSupply': '0x18160ddd',
    'maxSupply': '0xd5abeb01', 'owner': '0x8da5cb5b', 'baseURI': '0x6c0360eb',
    'contractURI': '0xe8a3d485', 'provenanceHash': '0xc6ab67a3',
    'royaltyInfo': '0x2a55205a', 'getMintStats': '0x840e15d4',
    'getPublicDrop': '0xbc6a629c', 'getAllowListMerkleRoot': '0x32bf11f5',
    'getCreatorPayoutAddress': '0x5cb3c4d3', 'getSigners': '0x7e3ba6af',
    'getPayers': '0x7c35b982',
}


def word(x):
    if isinstance(x, str):
        return x.lower().replace('0x', '').rjust(64, '0')
    return format(x, '064x')


def dec_uint(h, i=0):
    return int(h[i*64:(i+1)*64] or '0', 16)


def dec_addr(h, i=0):
    w = h[i*64:(i+1)*64]
    return '0x' + w[24:] if w else None


def dec_str(h):
    """ABI dynamic string: offset, length, then padded bytes."""
    try:
        off = int(h[:64], 16) * 2
        ln = int(h[off:off+64], 16) * 2
        return bytes.fromhex(h[off+64:off+64+ln]).decode('utf-8', 'replace')
    except Exception:
        return None


def dec_addr_array(h):
    try:
        off = int(h[:64], 16) * 2
        n = int(h[off:off+64], 16)
        return ['0x' + h[off+64+i*64+24: off+64+(i+1)*64] for i in range(n)]
    except Exception:
        return []


def batch_calls(rpcurl, calls, timeout=40):
    """One HTTP round trip for every read.

    Sequential `cast call` meant a subprocess plus a ~1s round trip each; a
    dozen of them took 44 seconds. JSON-RPC batching collapses that to one
    request, at the cost of decoding returns by hand below.
    """
    payload = [{'jsonrpc': '2.0', 'id': cid,
                'method': 'eth_call', 'params': [{'to': to, 'data': data}, 'latest']}
               for cid, to, data in calls]
    req = urllib.request.Request(rpcurl, json.dumps(payload).encode(), UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.load(r)
    return {o['id']: (o.get('result') or '')[2:] for o in out}
OS_FEE  = '0x0000a26b00c1F0DF003000390027140000fAa719'
UA      = {'User-Agent': 'curl/8.7.1', 'Content-Type': 'application/json'}


def rpc(url, method, params, timeout=20):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
    req = urllib.request.Request(url, body.encode(), UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def cast(args, timeout=25):
    p = subprocess.run(['cast'] + args, capture_output=True, text=True, timeout=timeout)
    return (p.stdout.strip() if p.returncode == 0 else None,
            p.stderr.strip() if p.returncode else '')


def find_chains(contract):
    """Every configured chain with bytecode at this address.

    Returns a list, not a single name, because the same address routinely
    holds DIFFERENT contracts on different chains -- BAYC's mainnet address
    also has code on Base. Picking the first match silently would read one
    chain's drop and sign for another, so an ambiguous address is handed back
    to the caller to choose.
    """
    hits, dead = [], []
    for name, (url, _) in CHAINS.items():
        try:
            code = rpc(url, 'eth_getCode', [contract, 'latest'], timeout=10).get('result')
            if code and code != '0x':
                hits.append(name)
        except Exception:
            dead.append(name)
    return hits, dead


def resolve(url_or_slug):
    """Accepts an OpenSea URL/slug, or a bare 0x contract address.

    OpenSea's API needs a key, but their CDN serves hot collections from cache
    without one -- so the same call succeeds for a trending drop and 401s for
    everything else. Treat the API as a nicety: a contract address always
    works, and the chain is found by looking for bytecode.
    """
    s = url_or_slug.strip().rstrip('/')

    m = re.search(r'(0x[a-fA-F0-9]{40})', s)
    if m and not re.search(r'opensea\.io/(?:assets/[^/]+/)?collection/', s):
        contract = m.group(1)
        hits, dead = find_chains(contract)
        if not hits:
            raise ValueError('no contract code at that address on any configured chain'
                             + (f' (unreachable: {", ".join(dead)})' if dead else ''))
        return {'slug': None, 'name': None, 'contract': contract, 'chain': hits[0],
                'owner': None, 'site': None, 'image': None, 'others': [],
                'via': 'address', 'chainCandidates': hits, 'chainsUnreachable': dead,
                'ambiguous': len(hits) > 1}

    m = re.search(r'opensea\.io/(?:assets/[^/]+/)?collection/([^/?#]+)', s)
    slug = m.group(1) if m else s.split('/')[-1]
    try:
        d, _ = os_get(f'collections/{urllib.parse.quote(slug)}')
    except urllib.error.HTTPError as e:
        # Their CDN serves trending collections without a key and everything
        # else 401s -- and a slug can flip between the two as the cache warms
        # and expires. Anything resolved once is kept locally so the same slug
        # keeps working afterwards.
        hit = cache_load().get(slug.lower())
        if hit:
            return dict(hit, via='cache')
        if e.code in (401, 403):
            raise ValueError(
                f'OpenSea has no cached copy of "{slug}" right now and their API '
                f'needs a key. Paste the contract address instead -- the chain is '
                f'detected and everything that matters for minting is read from it. '
                f'For names and images, set OPENSEA_API_KEY (free from '
                f'opensea.io/account/developer) before starting the server.')
        raise
    cs = d.get('contracts') or []
    if not cs:
        raise ValueError('no contract listed for this collection')
    rec = {'slug': slug, 'name': d.get('name'), 'contract': cs[0]['address'],
           'chain': cs[0]['chain'], 'owner': d.get('owner'),
           'site': d.get('project_url'), 'image': d.get('image_url'),
           'others': cs[1:]}
    cache_put(slug, rec)
    return dict(rec, via='opensea')


def read_drop(contract, chain):
    rpcurl, chainid = CHAINS.get(chain, (None, None))
    if not rpcurl:
        raise ValueError(f'chain "{chain}" not configured')
    out = {'rpc': rpcurl, 'chainId': chainid, 'contract': contract, 'chain': chain}

    calls = [(k, contract, SEL[k]) for k in
             ('name', 'symbol', 'totalSupply', 'maxSupply', 'owner',
              'baseURI', 'contractURI', 'provenanceHash')]
    calls.append(('royaltyInfo', contract, SEL['royaltyInfo'] + word(1) + word(10000)))
    for k in ('getPublicDrop', 'getAllowListMerkleRoot', 'getCreatorPayoutAddress',
              'getSigners', 'getPayers'):
        calls.append((k, SEADROP, SEL[k] + word(contract)))
    try:
        r = batch_calls(rpcurl, calls)
    except Exception as e:
        return dict(out, error=f'rpc batch failed: {e}')

    out['name'] = dec_str(r.get('name', ''))
    out['symbol'] = dec_str(r.get('symbol', ''))
    out['totalSupply'] = str(dec_uint(r.get('totalSupply', '')))
    out['maxSupply'] = str(dec_uint(r.get('maxSupply', '')))
    out['owner'] = dec_addr(r.get('owner', ''))
    out['baseURI'] = dec_str(r.get('baseURI', ''))
    out['contractURI'] = dec_str(r.get('contractURI', ''))
    pv = r.get('provenanceHash', '')
    out['provenanceHash'] = '0x' + pv[:64] if pv else None
    ri = r.get('royaltyInfo', '')
    if ri:
        out['royalty'] = {'receiver': dec_addr(ri, 0), 'bps': dec_uint(ri, 1)}
    pd = r.get('getPublicDrop', '')
    if pd:
        out['publicDrop'] = {
            'price': dec_uint(pd, 0), 'start': dec_uint(pd, 1), 'end': dec_uint(pd, 2),
            'perWallet': dec_uint(pd, 3), 'feeBps': dec_uint(pd, 4),
            'restrictFeeRecipients': bool(dec_uint(pd, 5))}
    al = r.get('getAllowListMerkleRoot', '')
    out['allowListRoot'] = '0x' + al[:64] if al else None
    out['creatorPayout'] = dec_addr(r.get('getCreatorPayoutAddress', ''))
    out['signers'] = json.dumps(dec_addr_array(r.get('getSigners', '')))
    out['payers'] = json.dumps(dec_addr_array(r.get('getPayers', '')))
    out['explorer'] = EXPLORER.get(chain)
    out['now'] = int(time.time())
    return out


def _read_drop_via_cast(contract, chain):
    rpcurl, chainid = CHAINS.get(chain, (None, None))
    out = {'rpc': rpcurl, 'chainId': chainid, 'contract': contract, 'chain': chain}
    for key, sig in (('name', 'name()(string)'), ('symbol', 'symbol()(string)'),
                     ('totalSupply', 'totalSupply()(uint256)'),
                     ('maxSupply', 'maxSupply()(uint256)'),
                     ('owner', 'owner()(address)')):
        v, _ = cast(['call', contract, sig, '--rpc-url', rpcurl])
        out[key] = (v or '').strip('"') if v else None
    v, _ = cast(['call', SEADROP, 'getPublicDrop(address)((uint80,uint48,uint48,uint16,uint16,bool))',
                 contract, '--rpc-url', rpcurl])
    out['publicDropRaw'] = v
    if v:
        # cast annotates large ints as "1791023400 [1.791e9]" -- strip those
        # brackets first or their digits get parsed as separate fields.
        clean = re.sub(r'\[[^\]]*\]', ' ', v)
        nums = re.findall(r'(\d+)|\b(true|false)\b', clean.replace(',', ' '))
        flat = [a or b for a, b in nums]
        if len(flat) >= 6:
            out['publicDrop'] = {
                'price': int(flat[0]), 'start': int(flat[1]), 'end': int(flat[2]),
                'perWallet': int(flat[3]), 'feeBps': int(flat[4]),
                'restrictFeeRecipients': flat[5] == 'true'}
    v, _ = cast(['call', SEADROP, 'getAllowListMerkleRoot(address)(bytes32)', contract,
                 '--rpc-url', rpcurl])
    out['allowListRoot'] = v

    for key, sig in (('baseURI', 'baseURI()(string)'),
                     ('contractURI', 'contractURI()(string)'),
                     ('provenanceHash', 'provenanceHash()(bytes32)')):
        v, _ = cast(['call', contract, sig, '--rpc-url', rpcurl])
        out[key] = (v or '').strip('"') if v else None

    v, _ = cast(['call', contract, 'royaltyInfo(uint256,uint256)(address,uint256)',
                 '1', '10000', '--rpc-url', rpcurl])
    if v:
        parts = re.sub(r'\[[^\]]*\]', ' ', v).split()
        if len(parts) >= 2:
            out['royalty'] = {'receiver': parts[0], 'bps': int(parts[1])}

    for key, sig in (('creatorPayout', 'getCreatorPayoutAddress(address)(address)'),
                     ('signers', 'getSigners(address)(address[])'),
                     ('payers', 'getPayers(address)(address[])')):
        v, _ = cast(['call', SEADROP, sig, contract, '--rpc-url', rpcurl])
        out[key] = v
    out['explorer'] = EXPLORER.get(chain)
    out['now'] = int(time.time())
    return out


def eligibility(contract, chain, wallet, qty):
    """Can this wallet mint this quantity right now, and if not, why not?

    getMintStats is the authority on what the wallet has already taken -- the
    per-wallet cap counts minted tokens, not current balance, so a wallet that
    minted its limit and transferred everything away still cannot mint again.
    """
    rpcurl, _ = CHAINS[chain]
    d = {'wallet': wallet, 'qty': qty, 'checks': []}
    r = batch_calls(rpcurl, [
        ('stats', contract, SEL['getMintStats'] + word(wallet)),
        ('drop', SEADROP, SEL['getPublicDrop'] + word(contract))])
    st = r.get('stats', '')
    if st:
        d['minted'], d['supply'], d['maxSupply'] = (dec_uint(st, 0), dec_uint(st, 1),
                                                    dec_uint(st, 2))
    pd = r.get('drop', '')
    now = int(time.time())
    if pd:
        start, end, per = dec_uint(pd, 1), dec_uint(pd, 2), dec_uint(pd, 3)
        d['start'], d['end'], d['perWallet'] = start, end, per
        d['checks'].append({'label': 'Stage is open', 'ok': start <= now < end,
                            'detail': 'not started' if now < start else
                                      ('ended' if now >= end else 'live')})
        room = per - d.get('minted', 0)
        d['checks'].append({'label': f'Wallet can take {qty}', 'ok': room >= qty,
                            'detail': f"{d.get('minted',0)} of {per} already minted, {max(0,room)} left"})
    left = d.get('maxSupply', 0) - d.get('supply', 0)
    d['checks'].append({'label': f'Supply covers {qty}', 'ok': left >= qty,
                        'detail': f'{left} unminted'})
    d['canMint'] = all(c['ok'] for c in d['checks'])
    d['maxNow'] = max(0, min(d.get('perWallet', 0) - d.get('minted', 0), left))
    return d


def stages(contract, chain):
    """Real per-stage mint activity, rebuilt from SeaDropMint events.

    OpenSea shows friendly stage names (Team, Pre-sale, GTD) but those live in
    their database, not the contract -- there is no public API for them. What
    IS on chain is every mint, each carrying its dropStageIndex, so the stages
    can be reconstructed from activity: how many tokens each one actually
    produced, across how many wallets, at what price. That is the ground truth
    the names are attached to.
    """
    rpcurl, _ = CHAINS[chain]
    head = int(rpc(rpcurl, 'eth_blockNumber', [])['result'], 16)
    frm = max(0, head - LOOKBACK.get(chain, 1_000_000))
    topic = '0x' + contract[2:].lower().rjust(64, '0')
    r = rpc(rpcurl, 'eth_getLogs', [{'address': SEADROP, 'topics': [SEADROP_MINT, topic],
            'fromBlock': hex(frm), 'toBlock': 'latest'}], timeout=120)
    if 'error' in r:
        return {'error': r['error'].get('message'), 'scannedFrom': frm, 'head': head}
    agg = {}
    for L in r['result']:
        d = L['data'][2:]
        w = [int(d[i*64:(i+1)*64], 16) for i in range(len(d)//64)]
        if len(w) < 5:
            continue
        qty, price, feebps, idx = w[1], w[2], w[3], w[4]
        a = agg.setdefault(idx, {'stage': idx, 'txs': 0, 'tokens': 0,
                                 'wallets': set(), 'price': price, 'feeBps': feebps,
                                 'firstBlock': None, 'lastBlock': None})
        a['txs'] += 1; a['tokens'] += qty; a['wallets'].add(L['topics'][2][-40:])
        b = int(L['blockNumber'], 16)
        a['firstBlock'] = b if a['firstBlock'] is None else min(a['firstBlock'], b)
        a['lastBlock'] = b if a['lastBlock'] is None else max(a['lastBlock'], b)
    out = []
    for a in sorted(agg.values(), key=lambda x: x['firstBlock'] or 0):
        a = dict(a); a['wallets'] = len(a['wallets']); out.append(a)
    return {'stages': out, 'totalTokens': sum(a['tokens'] for a in out),
            'totalTxs': sum(a['txs'] for a in out),
            'scannedBlocks': head - frm, 'head': head}


def market(slug):
    """Floor and volume from OpenSea. Needs a key unless the CDN has it cached."""
    try:
        d, _ = os_get(f'collections/{urllib.parse.quote(slug)}/stats', timeout=15)
    except Exception as e:
        return {'unavailable': str(e)[:140]}
    t = d.get('total', {})
    out = {'floor': t.get('floor_price'), 'floorSymbol': t.get('floor_price_symbol'),
           'volume': t.get('volume'), 'volumeSymbol': t.get('volume_symbol'),
           'sales': t.get('sales'), 'owners': t.get('num_owners')}
    for iv in d.get('intervals', []):
        if iv.get('interval') == 'one_day':
            out['volume24h'] = iv.get('volume')
            out['sales24h'] = iv.get('sales')
    try:        # cheapest listing -- OpenSea's "floor" lags on quiet collections
        b, _ = os_get(f'listings/collection/{urllib.parse.quote(slug)}/best?limit=1', 15)
        L = (b.get('listings') or [])
        out['listingCount'] = len(L)
        if L:
            cons = L[0]['protocol_data']['parameters'].get('consideration') or []
            amt = sum(int(c.get('startAmount', 0)) for c in cons)
            out['bestListing'] = amt / 1e18
    except Exception:
        pass
    return out


def bench_submit(rpcurl, chain=None, n=10):
    """Time the WRITE path on both routes with a payload that cannot land.

    "0x02f8" is a truncated typed transaction: the sequencer parses the method,
    fails to decode it and returns an error. The request still travels the full
    path, so it measures submission latency without risking a real send.
    """
    out = {}
    body = json.dumps({'jsonrpc': '2.0', 'id': 1,
                       'method': 'eth_sendRawTransaction', 'params': ['0x02f8']})
    ctx = ssl.create_default_context()
    routes = [('publicRpc', rpcurl)]
    direct = submit_url(rpcurl, chain)
    if direct != rpcurl:
        routes.append(('sequencer', direct))
    for name, url in routes:
        host = urllib.parse.urlparse(url).netloc
        path = urllib.parse.urlparse(url).path or '/'
        ts = []
        try:
            c = http.client.HTTPSConnection(host, 443, context=ctx, timeout=20)
            c.connect()
            for _ in range(n):
                t = time.perf_counter()
                try:
                    c.request('POST', path, body, UA); c.getresponse().read()
                    ts.append((time.perf_counter() - t) * 1000)
                except Exception:
                    c.close(); c = http.client.HTTPSConnection(host, 443, context=ctx, timeout=20)
            c.close()
        except Exception:
            pass
        if ts:
            v = sorted(ts)
            out[name] = {'url': url, 'min': round(v[0]), 'med': round(v[len(v)//2]),
                         'max': round(v[-1]), 'spread': round(v[-1] - v[0]), 'n': len(v)}
    # raw TCP handshake separates network distance from server processing
    try:
        ip = socket.gethostbyname(urllib.parse.urlparse(direct).netloc)
        ts = []
        for _ in range(5):
            sk = socket.socket(); sk.settimeout(5); t = time.perf_counter()
            try:
                sk.connect((ip, 443)); ts.append((time.perf_counter() - t) * 1000)
            except Exception:
                pass
            sk.close()
        if ts:
            out['tcp'] = {'ip': ip, 'min': round(min(ts)), 'med': round(sorted(ts)[len(ts)//2])}
    except Exception:
        pass
    return out


def bench(rpcurl, n=12):
    """Latency distribution. Separate connection each time, like a cold fire."""
    host = urllib.parse.urlparse(rpcurl).netloc
    path = urllib.parse.urlparse(rpcurl).path or '/'
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_blockNumber', 'params': []})
    ctx = ssl.create_default_context()
    warm, cold = [], []
    conn = http.client.HTTPSConnection(host, 443, context=ctx, timeout=20)
    for i in range(n):
        t = time.perf_counter()
        try:
            conn.request('POST', path, body, UA); conn.getresponse().read()
            warm.append((time.perf_counter() - t) * 1000)
        except Exception:
            conn.close(); conn = http.client.HTTPSConnection(host, 443, context=ctx, timeout=20)
    conn.close()
    for i in range(min(n, 6)):
        t = time.perf_counter()
        try:
            c = http.client.HTTPSConnection(host, 443, context=ctx, timeout=20)
            c.request('POST', path, body, UA); c.getresponse().read(); c.close()
            cold.append((time.perf_counter() - t) * 1000)
        except Exception:
            pass
    f = lambda xs: ({'min': round(min(xs)), 'med': round(sorted(xs)[len(xs)//2]),
                     'max': round(max(xs)), 'n': len(xs)} if xs else None)
    return {'warm': f(warm), 'cold': f(cold), 'samples': [round(x) for x in warm]}


def prepare(contract, chain, qty, account, to_self=True):
    """Sign the mint offline. Returns raw hex ready to fire."""
    rpcurl, chainid = CHAINS[chain]
    addr, err = cast(['wallet', 'address', '--account', account], timeout=120)
    if not addr:
        return {'error': f'could not unlock {account}: {err}'}
    nonce, _ = cast(['nonce', addr, '--rpc-url', rpcurl])
    gp, _ = cast(['gas-price', '--rpc-url', rpcurl])
    raw, err = cast(['mktx', SEADROP,
                     'mintPublic(address,address,address,uint256)',
                     contract, OS_FEE, '0x' + '0'*40, str(qty),
                     '--account', account, '--rpc-url', rpcurl,
                     '--nonce', nonce, '--gas-limit', '400000'], timeout=120)
    if not raw:
        return {'error': err or 'mktx failed'}
    h, _ = cast(['keccak', raw])
    return {'from': addr, 'nonce': int(nonce), 'gasPrice': gp, 'raw': raw,
            'txHash': h, 'qty': qty, 'rpc': rpcurl, 'chainId': chainid}


def submit_url(rpcurl, chain=None):
    if chain and chain in SUBMIT:
        return SUBMIT[chain]
    for c, (u, _) in CHAINS.items():          # map an rpc url back to its chain
        if u == rpcurl and c in SUBMIT:
            return SUBMIT[c]
    return rpcurl


def burst(rpcurl, raw, at, chain=None, lead=0.4, interval=0.025, window=4.0,
          cond=True, timestamp_min=None):
    """Hammer the boundary without burning the nonce.

    A mint that arrives before startTime reverts, and a revert CONSUMES the
    nonce -- the next attempt needs a freshly signed transaction, which in a
    hot race is the thing that loses the spot.

    eth_sendRawTransactionConditional takes a timestampMin. If the chain has
    not reached it the submission is refused at the gate instead of landing
    and reverting, so the nonce survives and the same signed bytes can be sent
    again immediately. That makes it safe to start firing BEFORE the stage
    opens and simply keep going until one is accepted.

    Falls back to plain eth_sendRawTransaction if the conditional form is
    unavailable, in which case firing starts at `at` rather than before it.
    """
    target = submit_url(rpcurl, chain)
    host = urllib.parse.urlparse(target).netloc
    path = urllib.parse.urlparse(target).path or '/'
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, 443, context=ctx, timeout=20)
    conn.connect()                                   # handshake before T-0

    tmin = timestamp_min if timestamp_min is not None else int(at)
    def payload(use_cond):
        if use_cond:
            return json.dumps({'jsonrpc': '2.0', 'id': 1,
                               'method': 'eth_sendRawTransactionConditional',
                               'params': [raw, {'timestampMin': tmin}]})
        return json.dumps({'jsonrpc': '2.0', 'id': 1,
                           'method': 'eth_sendRawTransaction', 'params': [raw]})

    use_cond = cond
    start = at - lead if use_cond else at
    while time.time() < start - 0.002:
        time.sleep(0.0005)

    attempts, t0, deadline = [], time.perf_counter(), time.time() + window
    txhash = None
    while time.time() < deadline and txhash is None:
        sent = time.time()
        try:
            conn.request('POST', path, payload(use_cond), UA)
            txt = conn.getresponse().read().decode()
        except Exception as e:
            conn.close()
            conn = http.client.HTTPSConnection(host, 443, context=ctx, timeout=20)
            attempts.append({'at': round(sent - at, 3), 'error': str(e)[:90]}); continue
        try:
            jr = json.loads(txt)
        except Exception:
            jr = {'error': {'message': txt[:90]}}
        err = (jr.get('error') or {}).get('message')
        if jr.get('result'):
            txhash = jr['result']
            attempts.append({'at': round(sent - at, 3), 'ms': round((time.perf_counter()-t0)*1000),
                             'result': txhash}); break
        if err and 'does not exist' in err and use_cond:
            use_cond = False                          # no conditional support here
            attempts.append({'at': round(sent - at, 3), 'note': 'conditional unsupported, falling back'})
            if time.time() < at:
                while time.time() < at - 0.002:
                    time.sleep(0.0005)
            continue
        attempts.append({'at': round(sent - at, 3), 'error': (err or '')[:90]})
        if err and ('nonce too low' in err or 'already known' in err):
            break                                     # it landed, or a prior one did
        time.sleep(interval)
    try:
        conn.close()
    except Exception:
        pass
    return {'txHash': txhash, 'attempts': attempts, 'tries': len(attempts),
            'target': target, 'conditional': use_cond,
            'firstAt': attempts[0]['at'] if attempts else None}


# ---------------------------------------------------------------- batch mint
# One transaction per wallet, each taking its own allowance. These are N
# DIFFERENT transactions with different senders and nonces, so unlike the
# lane duplication they should ALL land -- parallel submission here is real
# throughput, not redundancy.

def read_wallet_file(path):
    """Addresses and keys from a wallet file. Keys never leave this process."""
    path = safe_wallet_path(path)
    txt = open(path, errors='ignore').read()
    pairs = re.findall(r'(0x[a-fA-F0-9]{40})\s+(0x[a-fA-F0-9]{64})', txt)
    if not pairs:   # "Address : 0x..\nPrivate key : 0x.." layout
        addrs = re.findall(r'Address\s*:\s*(0x[a-fA-F0-9]{40})', txt)
        keys = re.findall(r'Private key\s*:\s*(0x[a-fA-F0-9]{64})', txt)
        pairs = list(zip(addrs, keys))
    seen, out = set(), []
    for a, k in pairs:
        if a.lower() in seen:
            continue
        seen.add(a.lower()); out.append((a, k))
    return out


def batch_preflight(path, contract, chain, qty):
    """Per-wallet gas and allowance, before anything is signed."""
    rpcurl, _ = CHAINS[chain]
    wallets = read_wallet_file(path)
    reqs = []
    for i, (a, _) in enumerate(wallets):
        reqs.append({'jsonrpc': '2.0', 'id': f'b{i}', 'method': 'eth_getBalance',
                     'params': [a, 'latest']})
        reqs.append({'jsonrpc': '2.0', 'id': f's{i}', 'method': 'eth_call',
                     'params': [{'to': contract, 'data': SEL['getMintStats'] + word(a)},
                                'latest']})
    # The RPC 429s on very large batches, so send them in chunks with backoff.
    res = {}
    CH = 40
    for i in range(0, len(reqs), CH):
        part = reqs[i:i + CH]
        for attempt in range(6):
            try:
                req = urllib.request.Request(rpcurl, json.dumps(part).encode(), UA)
                with urllib.request.urlopen(req, timeout=60) as r:
                    res.update({o['id']: o for o in json.load(r)})
                break
            except Exception:
                if attempt == 5:
                    raise
                time.sleep(1.5 * (attempt + 1))
        time.sleep(0.25)
    pd = batch_calls(rpcurl, [('d', SEADROP, SEL['getPublicDrop'] + word(contract))]).get('d', '')
    per = dec_uint(pd, 3) if pd else 0
    price = dec_uint(pd, 0) if pd else 0
    rows, ready = [], 0
    for i, (a, _) in enumerate(wallets):
        bal = int((res[f'b{i}'].get('result') or '0x0'), 16)
        st = (res[f's{i}'].get('result') or '')[2:]
        minted = dec_uint(st, 0) if st else 0
        want = min(qty, max(0, per - minted))
        gas_ok = bal > 0
        rows.append({'address': a, 'balanceEth': bal / 1e18, 'minted': minted,
                     'room': max(0, per - minted), 'want': want,
                     'gas': gas_ok, 'ready': gas_ok and want > 0})
        if gas_ok and want > 0:
            ready += 1
    return {'wallets': rows, 'count': len(rows), 'ready': ready,
            'perWallet': per, 'price': price,
            'totalTokens': sum(r['want'] for r in rows if r['ready'])}


def batch_prepare(path, contract, chain, qty):
    """Sign one mint per wallet. Returns raw bytes only -- never the keys."""
    rpcurl, chainid = CHAINS[chain]
    wallets = read_wallet_file(path)
    pre = batch_preflight(path, contract, chain, qty)
    bywant = {w['address'].lower(): w for w in pre['wallets']}
    out, errs = [], []
    for a, k in wallets:
        info = bywant.get(a.lower(), {})
        if not info.get('ready'):
            errs.append({'address': a,
                         'why': 'no gas' if not info.get('gas') else 'no allowance left'})
            continue
        nonce, _ = cast(['nonce', a, '--rpc-url', rpcurl])
        raw, err = cast(['mktx', SEADROP,
                         'mintPublic(address,address,address,uint256)',
                         contract, OS_FEE, '0x' + '0'*40, str(info['want']),
                         '--private-key', k, '--rpc-url', rpcurl,
                         '--nonce', nonce or '0', '--gas-limit', '400000'], timeout=60)
        if not raw:
            errs.append({'address': a, 'why': (err or 'sign failed')[:90]}); continue
        h, _ = cast(['keccak', raw])
        out.append({'address': a, 'qty': info['want'], 'nonce': int(nonce or 0),
                    'raw': raw, 'txHash': h})
    return {'signed': out, 'errors': errs, 'count': len(out),
            'tokens': sum(o['qty'] for o in out), 'rpc': rpcurl, 'chain': chain}


def batch_fire(rpcurl, items, at=None, chain=None):
    """Submit every signed transaction at once, one connection each."""
    target = submit_url(rpcurl, chain)
    host = urllib.parse.urlparse(target).netloc
    path = urllib.parse.urlparse(target).path or '/'
    ctx = ssl.create_default_context()
    conns = []
    for it in items:
        try:
            c = http.client.HTTPSConnection(host, 443, context=ctx, timeout=25)
            c.connect(); conns.append((it, c))
        except Exception:
            conns.append((it, None))
    if at:
        while time.time() < at - 0.002:
            time.sleep(0.0005)
    results, lock, t0 = [], threading.Lock(), time.perf_counter()

    def shoot(it, c):
        r = {'address': it['address'], 'qty': it['qty']}
        try:
            body = json.dumps({'jsonrpc': '2.0', 'id': 1,
                               'method': 'eth_sendRawTransaction', 'params': [it['raw']]})
            c.request('POST', path, body, UA)
            jr = json.loads(c.getresponse().read().decode())
            r['ms'] = round((time.perf_counter() - t0) * 1000, 1)
            r['result'] = jr.get('result')
            r['error'] = (jr.get('error') or {}).get('message')
        except Exception as e:
            r['ms'] = round((time.perf_counter() - t0) * 1000, 1)
            r['error'] = str(e)[:110]
        with lock:
            results.append(r)

    ts = [threading.Thread(target=shoot, args=(it, c)) for it, c in conns if c]
    for t in ts: t.start()
    for t in ts: t.join(timeout=40)
    for _, c in conns:
        try: c.close()
        except Exception: pass
    results.sort(key=lambda r: r.get('ms', 0))
    landed = [r for r in results if r.get('result')]
    return {'results': results, 'landed': len(landed), 'target': target,
            'tokens': sum(r['qty'] for r in landed)}


def fire(rpcurl, raw, lanes=8, at=None, chain=None):
    """Send the same signed bytes down `lanes` warm connections at once.

    Identical nonce and hash on every lane, so at most one can be included --
    the rest come back as duplicates. The winner is whichever lane the backend
    happens to serve fastest on this attempt.
    """
    target = submit_url(rpcurl, chain)
    host = urllib.parse.urlparse(target).netloc
    path = urllib.parse.urlparse(target).path or '/'
    body = json.dumps({'jsonrpc': '2.0', 'id': 1,
                       'method': 'eth_sendRawTransaction', 'params': [raw]})
    ctx = ssl.create_default_context()
    conns = []
    for _ in range(lanes):                      # warm: handshake before T-0
        try:
            c = http.client.HTTPSConnection(host, 443, context=ctx, timeout=25)
            c.connect(); conns.append(c)
        except Exception:
            pass
    if at:                                      # spin to the exact timestamp
        while time.time() < at - 0.002:
            time.sleep(0.0005)
    results, lock, t0 = [], threading.Lock(), time.perf_counter()

    def shoot(i, c):
        try:
            c.request('POST', path, body, UA)
            txt = c.getresponse().read().decode()
            ms = (time.perf_counter() - t0) * 1000
            try: j = json.loads(txt)
            except Exception: j = {'raw': txt[:200]}
            r = {'lane': i, 'ms': round(ms, 1),
                 'result': j.get('result'),
                 'error': (j.get('error') or {}).get('message')}
        except Exception as e:
            r = {'lane': i, 'ms': round((time.perf_counter()-t0)*1000, 1), 'error': str(e)[:120]}
        with lock: results.append(r)

    ts = [threading.Thread(target=shoot, args=(i, c)) for i, c in enumerate(conns)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=30)
    for c in conns:
        try: c.close()
        except Exception: pass
    results.sort(key=lambda r: r['ms'])
    won = next((r for r in results if r.get('result')), None)
    return {'lanes': len(conns), 'results': results, 'winner': won,
            'target': target, 'direct': target != rpcurl,
            'txHash': won['result'] if won else None}


class H(http.server.BaseHTTPRequestHandler):
    server_version = 'wasabi'
    sys_version = ''

    def log_message(self, *a): pass

    # -------------------------------------------------- auth / csrf
    def _cookie(self, name):
        for part in (self.headers.get('Cookie') or '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == name:
                return v.strip()
        return ''

    def _who(self):
        return session_email(self._cookie('wsid'))

    def _authed(self):
        return bool(self._who()) or self._token_ok()

    def _base(self):
        if PUBLIC_URL:
            return PUBLIC_URL
        host = self.headers.get('Host') or f'127.0.0.1:{PORT}'
        proto = 'https' if self.headers.get('X-Forwarded-Proto') == 'https' else 'http'
        return f'{proto}://{host}'

    def _token_ok(self):
        sent = (self.headers.get('X-Wasabi-Token') or '').strip()
        if not sent:
            for part in (self.headers.get('Cookie') or '').split(';'):
                k, _, v = part.strip().partition('=')
                if k == 'wasabi':
                    sent = v.strip(); break
        if not sent:
            sent = (urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query).get('token') or [''])[0]
        return bool(sent) and hmac.compare_digest(sent, TOKEN)

    def _origin_ok(self):
        """Reject cross-site POSTs. A browser always sends Origin on these;
        curl sends none, which is allowed so the CLI keeps working."""
        o = self.headers.get('Origin')
        if not o:
            return True
        try:
            return urllib.parse.urlparse(o).netloc == (self.headers.get('Host') or '')
        except Exception:
            return False

    def _deny(self, code, msg):
        b = json.dumps({'error': msg}).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def _secure_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')

    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self._secure_headers()
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path.startswith('/auth/'):
            return self._auth_get(u, q)
        if not self._authed():
            if u.path in ('/', '/index.html'):
                b = open(os.path.join(HERE, 'login.html'), 'rb').read()
                self.send_response(401)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(b)))
                self._secure_headers(); self.end_headers(); self.wfile.write(b); return
            return self._deny(401, 'unauthorised: supply ?token= or X-Wasabi-Token')
        try:
            if u.path in ('/', '/index.html'):
                b = open(os.path.join(HERE, 'index.html'), 'rb').read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-store, must-revalidate')
                self.send_header('Content-Length', str(len(b)))
                # remember the token so the page's own fetches authenticate
                self.send_header('Set-Cookie',
                                 f'wasabi={TOKEN}; Path=/; HttpOnly; SameSite=Strict')
                self._secure_headers()
                self.end_headers(); self.wfile.write(b); return
            if u.path == '/api/resolve':
                return self._send(resolve(q['url'][0]))
            if u.path == '/api/drop':
                return self._send(read_drop(q['contract'][0], q['chain'][0]))
            if u.path == '/api/bench':
                return self._send(bench(q.get('rpc', [CHAINS['robinhood'][0]])[0],
                                        int(q.get('n', ['12'])[0])))
            if u.path == '/api/eligibility':
                return self._send(eligibility(q['contract'][0], q['chain'][0],
                                              q['wallet'][0], int(q.get('qty', ['1'])[0])))
            if u.path == '/api/stages':
                return self._send(stages(q['contract'][0], q['chain'][0]))
            if u.path == '/api/market':
                return self._send(market(q['slug'][0]))
            if u.path == '/api/address':
                out, _ = cast(['wallet', 'address', '--account', q['account'][0]], timeout=120)
                return self._send({'address': out})
            if u.path == '/api/submitbench':
                return self._send(bench_submit(q['rpc'][0], q.get('chain', [None])[0],
                                               int(q.get('n', ['10'])[0])))
            if u.path == '/api/batch/preflight':
                return self._send(batch_preflight(q['path'][0], q['contract'][0],
                                                  q['chain'][0], int(q.get('qty', ['10'])[0])))
            if u.path == '/api/key':
                k = api_key()
                try:
                    meta = json.load(open(KEYFILE))
                except Exception:
                    meta = {}
                return self._send({'have': bool(k), 'name': meta.get('name'),
                                   'expires': meta.get('expires_at'),
                                   'limits': meta.get('rate_limits'),
                                   'source': 'env' if os.environ.get('OPENSEA_API_KEY')
                                             else ('minted' if k else 'none')})
            if u.path == '/api/wallets':
                out, _ = cast(['wallet', 'list'])
                names = [l.split()[0] for l in (out or '').splitlines() if l.strip()]
                return self._send({'accounts': names})
            self._send({'error': 'not found'}, 404)
        except Exception as e:
            self._send({'error': f'{type(e).__name__}: {e}'}, 500)

    # ------------------------------------------------------- auth routes
    def _auth_get(self, u, q):
        if u.path == '/auth/me':
            who = self._who()
            return self._send({'email': who, 'google': bool(GOOGLE_ID),
                               'claimable': not ALLOWED and not _users()})
        if u.path == '/auth/logout':
            sid = self._cookie('wsid')
            with _authlock:
                _sessions.pop(sid, None)
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', 'wsid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')
            self.end_headers(); return
        if u.path == '/auth/google/start':
            if not GOOGLE_ID:
                return self._deny(400, 'google sign-in is not configured')
            state = secrets.token_urlsafe(24)
            with _authlock:
                _oauth_states[state] = time.time() + 600
            self.send_response(302)
            self.send_header('Location',
                             google_auth_url(state, self._base() + '/auth/google/callback'))
            self.end_headers(); return
        if u.path == '/auth/google/callback':
            state = (q.get('state') or [''])[0]
            with _authlock:
                exp = _oauth_states.pop(state, None)
            if not exp or exp < time.time():
                return self._deny(400, 'bad or expired oauth state')
            try:
                info = google_exchange((q.get('code') or [''])[0],
                                       self._base() + '/auth/google/callback')
            except Exception as e:
                return self._deny(400, f'google sign-in failed: {e}')
            email = (info.get('email') or '').lower()
            users = _users()
            if email not in users and not email_allowed(email):
                return self._deny(403, f'{email} is not on the allowlist')
            if email not in users:
                users[email] = {'via': 'google', 'created': int(time.time())}
                _save_users(users)
            sid = new_session(email)
            self.send_response(302)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie',
                             f'wsid={sid}; Path=/; HttpOnly; SameSite=Lax; Secure'
                             if self.headers.get('X-Forwarded-Proto') == 'https'
                             else f'wsid={sid}; Path=/; HttpOnly; SameSite=Lax')
            self.end_headers(); return
        return self._deny(404, 'not found')

    def _auth_post(self, path, d):
        email = (d.get('email') or '').strip().lower()
        pw = d.get('password') or ''
        if not email or '@' not in email:
            return self._deny(400, 'enter a valid email')
        if len(pw) < 10:
            return self._deny(400, 'password must be at least 10 characters')
        users = _users()
        if path == '/auth/signup':
            if email in users:
                return self._deny(409, 'that account already exists — sign in instead')
            if not email_allowed(email):
                return self._deny(403, 'this email is not on the allowlist')
            users[email] = {'via': 'password', 'pw': hash_pw(pw),
                            'created': int(time.time())}
            _save_users(users)
        elif path == '/auth/login':
            rec = users.get(email)
            # same response either way, so the endpoint does not reveal who exists
            if not rec or not rec.get('pw') or not check_pw(pw, rec['pw']):
                time.sleep(0.4)
                return self._deny(401, 'wrong email or password')
        else:
            return self._deny(404, 'not found')
        sid = new_session(email)
        b = json.dumps({'email': email}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Set-Cookie',
                         f'wsid={sid}; Path=/; HttpOnly; SameSite=Lax; Secure'
                         if self.headers.get('X-Forwarded-Proto') == 'https'
                         else f'wsid={sid}; Path=/; HttpOnly; SameSite=Lax')
        self._secure_headers(); self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        u0 = urllib.parse.urlparse(self.path)
        if u0.path.startswith('/auth/'):
            if not self._origin_ok():
                return self._deny(403, 'cross-site request refused')
            n0 = int(self.headers.get('Content-Length', 0))
            try:
                d0 = json.loads(self.rfile.read(n0) or b'{}')
            except Exception:
                return self._deny(400, 'bad json')
            try:
                return self._auth_post(u0.path, d0)
            except Exception as e:
                return self._deny(500, f'{type(e).__name__}: {e}')
        if not self._authed():
            return self._deny(401, 'unauthorised')
        if not self._origin_ok():
            return self._deny(403, 'cross-site request refused')
        n = int(self.headers.get('Content-Length', 0))
        d = json.loads(self.rfile.read(n) or b'{}')
        u = urllib.parse.urlparse(self.path)
        try:
            if u.path == '/api/prepare':
                return self._send(prepare(d['contract'], d['chain'], int(d['qty']), d['account']))
            if u.path == '/api/batch/prepare':
                return self._send(batch_prepare(d['path'], d['contract'], d['chain'],
                                                int(d.get('qty', 10))))
            if u.path == '/api/batch/fire':
                return self._send(batch_fire(d['rpc'], d['items'], d.get('at'), d.get('chain')))
            if u.path == '/api/burst':
                return self._send(burst(d['rpc'], d['raw'], float(d['at']), d.get('chain'),
                                        float(d.get('lead', 0.4)),
                                        float(d.get('interval', 0.025)),
                                        float(d.get('window', 4.0))))
            if u.path == '/api/fire':
                return self._send(fire(d['rpc'], d['raw'], int(d.get('lanes', 8)),
                                       d.get('at'), d.get('chain')))
            self._send({'error': 'not found'}, 404)
        except Exception as e:
            self._send({'error': f'{type(e).__name__}: {e}'}, 500)


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == '__main__':
    k = os.environ.get('OPENSEA_API_KEY')
    print(f'opensea key   :  {"from .env (" + str(len(k)) + " chars)" if k else "auto-minted"}')
    print(f'wallet roots  :  {", ".join(WALLET_ROOTS)}')
    if not os.environ.get('WASABI_TOKEN'):
        print('access token  :  generated for this run (set WASABI_TOKEN to pin it)')
    print()
    print(f'  http://{BIND}:{PORT}/?token={TOKEN}')
    print()
    S((BIND, PORT), H).serve_forever()
