# dig-pex

**Peer Exchange (PEX) for the DIG Node peer network.**

PEX lets a participant that already holds an **authenticated** link to another participant tell it,
incrementally, which peers it knows **first-hand** — so the network's address books stay warm
without polling and without a central directory. It adapts the proven mechanics of BitTorrent PEX
(`ut_pex`): peers exchange **deltas of their first-hand known-peer set** over already-established
connections, on a bounded periodic cadence, with hard per-message caps and **no third-party
re-flooding**.

`SPEC.md` in this repo is the authoritative, normative contract (wire version `1`); this crate is
its reference implementation.

## Where PEX runs

1. **Node ↔ Node** — over the mutual-TLS dig-nat multiplexed stream transport (a `u32` big-endian
   length prefix + JSON body, byte-identical to the dig-nat / dig-dht wires).
2. **Relay → Node** — by the `dig-relay` introducer, riding the existing `RelayMessage` WebSocket
   (designated **RLY-008**) as bare JSON text frames — purely additive to RLY-001..RLY-007.

## What it is not

- **Not a trust channel.** Every received entry is a *hint* — a candidate to dial and verify via the
  mTLS handshake, never an authenticated fact.
- **Not a gossip flood.** A participant advertises only what it knows **first-hand**; there is no
  `"pex"` provenance token, so a PEX-learned entry can never be re-advertised until independently
  verified. Bad or stale entries die one hop from their source.
- **Not content discovery.** Locating which peers hold content is the DHT's job (`dig-dht`); PEX
  populates the pool of dialable peers underneath it.

## The four messages

| `type` | Purpose |
|---|---|
| `pex_handshake` | first message each direction: version + network + declared interval + own flags |
| `pex_snapshot` | the first data message: a capped picture of the sender's first-hand set (one per direction) |
| `pex_delta` | the periodic message: `added` / `dropped` relative to what this link was told |
| `pex_error` | the advisory error envelope (codes 1–6) |

## The engine

The crate ships a transport-agnostic, **sans-IO** `PexEngine`: you feed it link events, inbound
messages, local peer-set changes, and clock ticks, and it returns the messages to send and the
events to act on. It does no I/O itself — the node and relay do the actual dig-nat mux / WebSocket
reads and writes, and both embed the *same* engine.

```rust
use dig_pex::{PexConfig, PexEngine, PexMessage, PeerEntry, Provenance, Address};

let mut engine = PexEngine::new(PexConfig::new(my_peer_id, "mainnet"));

// A first-hand peer enters our advertise set.
engine.upsert_known(
    PeerEntry::new(peer_c, "mainnet", now_secs, Provenance::Direct)
        .with_address(Address::direct("203.0.113.7", 9444)),
);

// A link comes up → emit our handshake + snapshot; write them on our sending stream.
let outgoing = engine.link_up(&peer_b, now_ms);

// Feed inbound messages → get verified-candidate events + any pex_error replies.
let outcome = engine.on_message(&peer_b, incoming, now_ms);

// Drive ~1/s → get per-link pex_delta messages for pending changes.
let deltas = engine.tick(now_ms);
```

- **DIG Node** (`dig-node`): route `PexEvent::Candidates` into the dig-gossip `AddressManager` as
  new-table candidates to dial + verify; feed first-hand knowledge back with `upsert_known` /
  `remove_known`.
- **dig-relay**: create the engine with flags `["introducer"]`; mirror the registration registry
  into it; **never** fold inbound node PEX data into the registry.

## Design & safety

- **Bounded everywhere.** Frame size (256 KiB), list caps (50 added / 50 dropped / 200 snapshot),
  per-entry address/flag caps, and a receiver-enforced minimum inter-arrival floor — a hostile
  sender costs a receiver at most one bounded frame per interval before it is muted.
- **`#![forbid(unsafe_code)]`**, `#![warn(missing_docs)]`, strict clippy, ≥80% line coverage gated
  in CI (currently ~98%).
- **Minimal dependencies** — `serde` / `serde_json` / `tokio` / `rand`. The peer entry is *mirrored*
  from (byte-compatible with) the L7 `dig.getPeers` / dig-nat / dig-gossip `Contact` shape rather
  than importing those crates, to keep the tree small.

## License

Licensed under either of Apache-2.0 or MIT at your option.
