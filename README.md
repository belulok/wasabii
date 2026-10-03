# wasabii

Sharp execution for OpenSea SeaDrop mints.

Reads a drop straight from the contract — supply, stages, per-wallet caps and
whether a given wallet actually passes — then signs offline and submits direct
to the chain's sequencer.

## Why direct submission

Arbitrum Orbit chains order transactions by **arrival at the sequencer**.
There is no priority fee and no mempool, so you cannot outbid anyone and
nobody can outbid you. The only thing that decides position is who gets there
first.

The public RPC is Cloudflare, then a gateway, then the same sequencer. Measured
from Singapore against Robinhood Chain:

| route | min | median | max | spread |
|---|---|---|---|---|
| public RPC | 756 | **934** | 1221 | 465 ms |
| sequencer direct | 264 | **266** | 288 | **24 ms** |

668 ms saved, and the variance nearly vanishes. Of the remaining 266 ms, ~264 ms
is the TCP round trip to `us-east-2` — distance, not software. Running from the
sequencer's own region takes it to roughly 10 ms.

## What it does

- Resolves an OpenSea URL **or** a bare contract address; detects the chain by
  looking for bytecode, and reports ambiguity rather than guessing
- Reads name, supply, price, window, per-wallet cap, allowlist root, signers,
  creator payout, royalty and metadata URI in **one batched `eth_call`**
- Rebuilds stage history from `SeaDropMint` events, so token counts per stage
  are exact rather than reported
- Checks eligibility against `getMintStats` and says *why* a wallet fails
- Benchmarks both the read and write paths and interprets the result
- Signs offline, then fires with nothing in the hot path but a socket write
- Batch mode: one transaction per wallet, each taking its own allowance

## Running it

```bash
python3 server.py          # http://127.0.0.1:8899
```

Python standard library only. Requires [Foundry](https://getfoundry.sh)'s `cast`
on PATH for signing.

Optional: `OPENSEA_API_KEY` in the environment or a `.env` file for collection
names, images and floor prices. Without one, Wasabi mints a free agent key
automatically; everything that decides a mint is read from the contract either
way.

## Scope and limits

- **SeaDrop 1.0 ERC-721 only.** Manifold, thirdweb and custom minters resolve
  but report no stage.
- **Local tool, not a hosted service.** It binds `127.0.0.1`, has no auth, no
  origin check on POST, and the batch path reads wallet files from disk. Do not
  expose it.
- Batch mode exists to save a group of people a manual mint each — one wallet
  per person, each taking the allowance the drop intends them to have. Per-wallet
  caps are how a drop spreads its supply; this does not work around them.

## Chains

Robinhood, Ethereum, Base, Arbitrum, Optimism, Polygon. Direct sequencer
submission is currently configured for Robinhood; others fall back to their RPC.
