# DIG PEX — Peer Exchange Protocol Specification

**Status:** Normative · **Wire version:** `1` · **Crate:** `dig-pex`

This document is the authoritative contract for the DIG Peer Exchange (PEX) protocol. An
independent implementation built from this document alone MUST interoperate with `dig-pex`. The
design adapts the proven mechanics of BitTorrent PEX (`ut_pex`): peers exchange **deltas of their
first-hand known-peer set** over **already-established, authenticated connections**, on a bounded
periodic cadence, with hard per-message caps and **no third-party re-flooding**.

---

## 1 · Purpose & scope

### 1.1 What PEX is

PEX is the peer-sharing protocol of the DIG Node peer network. It lets a participant that already
holds an authenticated link to another participant tell it, incrementally, which peers it knows
first-hand — so the network's address books stay warm without polling and without a central
directory. PEX is used in exactly two places:

1. **Node ↔ Node** — between two DIG Nodes over their mutual-TLS (mTLS) peer connection
   (the dig-nat multiplexed stream transport; L7 peer-network §1–§2).
2. **Relay → Node** — by the `dig-relay` **introducer** toward its registered peers, over the
   existing `RelayMessage` WebSocket wire (L7 peer-network §4a, §6).

### 1.2 What PEX replaces

Today discovery flows through ad-hoc polling: nodes poll the relay with `get_peers` (RLY-005) and
poll each other via `dig.getPeers` / `RequestPeers`. PEX subsumes the *polling* half of both:

- **RLY-005 (`get_peers`/`peers`)** remains valid as a one-shot query, but a PEX-capable node
  SHOULD prefer the PEX subscription (§10.2) — the relay pushes an initial snapshot and then only
  deltas, instead of the node re-fetching the full list. The RLY-005 messages and the
  `peer_connected` / `peer_disconnected` notifications are unchanged; PEX is additive (designated
  **RLY-008** on the relay wire).
- **Node↔node `RequestPeers`/`RespondPeers`** (Chia-streamable) remains for Chia-protocol
  compatibility; PEX is the richer, DIG-native exchange (typed addresses, provenance, flags,
  deltas) over the dig-nat mux.
- **`dig.getPeers`** (the JSON-RPC observability surface) is unchanged — PEX feeds the same
  address book that `dig.getPeers` reads.

### 1.3 What PEX is not

- PEX is **not a trust channel**. Every received entry is a *hint* — a candidate to dial and
  verify via the mTLS handshake. §11.
- PEX is **not a gossip flood**. A participant advertises only what it knows **first-hand** (§8);
  entries learned via PEX itself MUST NOT be re-advertised until independently verified.
- PEX is **not content discovery**. Locating which peers hold content is the DHT's job
  (`dig-dht`); PEX populates the pool of dialable peers underneath it.

## 2 · Conventions & terminology

- The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be
  interpreted as described in RFC 2119.
- **`<64hex>`** — exactly 64 lower-case hexadecimal characters encoding 32 bytes.
- **`peer_id`** — the mTLS peer identity, `SHA-256(TLS SubjectPublicKeyInfo DER)`, rendered
  `<64hex>` on every text surface (L7 peer-network §1).
- **Unix seconds** — an unsigned integer count of seconds since the Unix epoch (UTC).
- **Participant** — a PEX endpoint: a DIG Node, or the relay in its introducer role.
- **Link** — one authenticated connection between two participants over which PEX runs.
- **Data message** — a `pex_snapshot` or `pex_delta` (i.e. not `pex_handshake` / `pex_error`).
- **Direction** — PEX on a link is two independent half-conversations; each participant is the
  *sender* of its own direction and the *receiver* of the other's. All sender rules bind each
  participant's outgoing direction; all receiver rules bind its incoming direction.
- JSON shapes in this document are **frozen**: the field names, `type` tags, and enum token
  strings are the wire contract. Receivers MUST ignore unknown JSON fields (additive evolution);
  senders MUST NOT rely on unknown fields being processed.

## 3 · The peer entry

The unit of exchange is the **peer entry** — the L7 `PeerRecord` shape (`dig.getPeers`, L7
peer-network §7) extended with a `flags` list:

```json
{
  "peer_id":   "<64hex>",
  "addresses": [ { "host": "203.0.113.7", "port": 9444, "kind": "direct" } ],
  "network_id": "<network id string>",
  "last_seen": 1719763200,
  "via":       "direct",
  "flags":     ["storage", "holepunch"]
}
```

### 3.1 Fields

| Field | Type | Requirement |
|---|---|---|
| `peer_id` | string | REQUIRED. `<64hex>`. The advertised peer's mTLS identity. |
| `addresses` | array | REQUIRED (MAY be empty). Candidate addresses, most-direct-first. Each is `{ "host": str, "port": uint, "kind": str }` — **byte-compatible** with the L7 `dig.getPeers` / DHT `Contact` address shape. `kind` ∈ `"direct"` \| `"mapped"` \| `"reflexive"` \| `"relay"`. `port` ∈ 1–65535. An empty array means the advertiser knows no dialable address (the peer is reachable only via shared infrastructure, e.g. relay rendezvous by `peer_id`; see the `relay-only` flag). |
| `network_id` | string | REQUIRED. The network the peer belongs to. MUST equal the link's network (§5.2, §7.3). |
| `last_seen` | uint | REQUIRED. Unix seconds when the **advertiser** last had first-hand evidence of the peer (§8.2). |
| `via` | string | REQUIRED. The advertiser's **provenance** for this entry (§8.1): `"direct"` \| `"relay"` \| `"introducer"`. |
| `flags` | array of strings | OPTIONAL (default `[]`). Per-peer capability flags (§3.2). |

### 3.2 Flags

`flags` is an extensible set of lower-case ASCII tokens (each 1–32 chars, `[a-z0-9-]`). Version 1
registers:

| Flag | Meaning |
|---|---|
| `storage` | The peer serves DIG content (a full DIG Node answering the L7 content RPCs). |
| `holepunch` | The peer supports relay-coordinated hole-punching (RLY-007). |
| `relay-only` | The peer has no direct inbound path; reach it via relay rendezvous by `peer_id`. |
| `introducer` | The peer acts as an introducer. |

Rules:

- A receiver MUST ignore flag tokens it does not recognize (they are hints, never gates).
- A sender MUST NOT emit more than **8** flags per entry, nor tokens longer than 32 chars.
- Future flags are registered by amending this table — additive only; a registered token's
  meaning is never repurposed.

### 3.3 Entry validation (receiver side)

An entry inside an otherwise-valid data message is **skipped, not fatal**, when any of the
following holds (skipping is silent — no error, no violation strike):

- `peer_id` is not `<64hex>`;
- `peer_id` equals the receiver's own `peer_id` or the sender's `peer_id` (§5.4);
- any address has an empty `host`, a `port` of 0, or an unknown `kind` token;
- `addresses` has more than **8** elements, or `flags` more than **8**;
- `network_id` differs from the link's network;
- `via` is not one of the three registered tokens;
- `last_seen` is more than **1800 seconds** (`PEX_MAX_ENTRY_AGE`) in the past by the receiver's
  clock (SHOULD skip — clock-skew tolerance is the receiver's choice); a `last_seen` in the
  future SHOULD be clamped to the receiver's now.

## 4 · Messages

### 4.1 Encoding & framing

Every PEX message is a **`type`-tagged JSON object** — the uniform DIG peer-network convention
shared with the dig-nat control messages, the DHT RPC, and the relay wire.

- **On a byte stream** (the node↔node binding, §10.1) each message is framed as a **`u32`
  big-endian length prefix followed by the JSON body** — byte-identical framing to the dig-nat /
  DHT wires. A length prefix greater than **262144 bytes** (256 KiB, `PEX_MAX_FRAME`) MUST be
  rejected without allocating or reading the body (§7.2).
- **On the relay WebSocket** (§10.2) each message is one WebSocket text frame containing the bare
  JSON object (the WebSocket already delimits messages; no length prefix). The same
  `PEX_MAX_FRAME` bound applies to the frame's payload size.

### 4.2 `pex_handshake`

The first PEX message a participant sends on a link, in each direction, before anything else.

```json
{ "type": "pex_handshake", "version": 1, "network_id": "<network id string>",
  "interval": 60, "flags": ["storage", "holepunch"] }
```

| Field | Type | Meaning |
|---|---|---|
| `version` | uint | REQUIRED. The PEX wire version the sender speaks. This document defines version `1`. |
| `network_id` | string | REQUIRED. The sender's network. MUST match the receiver's, else §5.2. |
| `interval` | uint | REQUIRED. Seconds — the sender's declared minimum spacing between its own data messages on this link (§6). MUST be within `[30, 3600]`; a receiver clamps out-of-range values into that range for enforcement. |
| `flags` | array | OPTIONAL (default `[]`). The **sender's own** capability flags (§3.2 tokens). |

### 4.3 `pex_snapshot`

The first **data message** in a direction — a fuller, capped picture of the sender's first-hand
known-peer set, so a fresh link warms up in one message.

```json
{ "type": "pex_snapshot", "peers": [ PeerEntry, "..." ] }
```

- `peers` — REQUIRED array of peer entries (§3). MAY be empty. MUST NOT exceed **200** entries
  (`PEX_MAX_SNAPSHOT`). SHOULD be ordered most-recently-seen first, so a truncated view carries
  the freshest peers.
- Exactly **one** snapshot per direction per link (§5.3).

### 4.4 `pex_delta`

The periodic message: what changed in the sender's first-hand set **relative to what this link
has already been told** (§9.1).

```json
{ "type": "pex_delta",
  "added":   [ PeerEntry, "..." ],
  "dropped": [ "<64hex>", "..." ] }
```

- `added` — REQUIRED array (MAY be empty) of peer entries newly known, or already-told entries
  whose advertised content changed (an `added` entry for an already-told `peer_id` is an
  **update**: it replaces the previous entry). MUST NOT exceed **50** entries (`PEX_MAX_ADDED`).
- `dropped` — REQUIRED array (MAY be empty) of `<64hex>` peer ids the sender no longer considers
  good (§8.3). MUST NOT exceed **50** ids (`PEX_MAX_DROPPED`). A sender MUST NOT drop a peer it
  never told this link; a receiver silently ignores dropped ids it was never told.
- A `peer_id` MUST NOT appear in both `added` and `dropped` of the same message.
- A delta with both arrays empty MUST NOT be sent (empty deltas are suppressed; silence means
  "no change").

### 4.5 `pex_error`

The advisory error envelope, either direction.

```json
{ "type": "pex_error", "code": 3, "message": "rate violation" }
```

| `code` | Name | Meaning |
|---|---|---|
| `1` | `PEX_BAD_MESSAGE` | The message was not valid PEX JSON, or violated a structural MUST (e.g. a `peer_id` in both `added` and `dropped`). |
| `2` | `PEX_UNSUPPORTED_VERSION` | The handshake `version` is not supported by the receiver. |
| `3` | `PEX_RATE_VIOLATION` | Data messages arrived faster than the enforced minimum interval (§6.4). |
| `4` | `PEX_OVERSIZED` | A frame exceeded `PEX_MAX_FRAME`, or a list exceeded its cap (§7). |
| `5` | `PEX_NETWORK_MISMATCH` | The handshake `network_id` differs from the receiver's. |
| `6` | `PEX_PROTOCOL_VIOLATION` | A state-machine violation (§5.3): data before handshake, a second snapshot, or a delta before the snapshot. |

`pex_error` is **advisory**: it is sent best-effort and never requires a reply. The error
envelope is named `pex_error` (not `error`) on **both** transport bindings, because the relay
binding shares one message namespace with RLY-001..RLY-007, whose `error` message owns a
different code space — a uniform `pex_error` keeps one frozen shape everywhere.

The `type` tags `pex_handshake`, `pex_snapshot`, `pex_delta`, and `pex_error` are reserved to
this protocol on every surface that carries it.

## 5 · Link lifecycle

### 5.1 Directions are independent

PEX on a link is two independent half-conversations. Each participant that wishes to advertise
sends, in order: its `pex_handshake`, then its `pex_snapshot`, then zero or more `pex_delta`s. A
participant MAY be receive-only (it never sends a handshake and therefore never sends data
messages); the other direction is unaffected. On the relay binding the node's direction is a
capability signal only (§10.2).

### 5.2 Handshake

- A participant MUST send its `pex_handshake` before any other PEX message it sends on the link.
- A receiver that gets a handshake with an unsupported `version` MUST reply `pex_error` code `2`
  and MUST ignore all further PEX messages in that direction (**mute** it). It MUST NOT tear
  down the underlying connection for this reason alone — PEX is an optional overlay.
- A receiver that gets a handshake whose `network_id` differs from its own MUST reply
  `pex_error` code `5` and mute the direction.
- The handshake's `interval` and `flags` are recorded for the life of the link (§6).

### 5.3 State machine (per direction, receiver's view)

```text
  AWAITING_HANDSHAKE --pex_handshake(ok)--> AWAITING_SNAPSHOT --pex_snapshot--> STREAMING
        |                                        |                                  |
        | data message                           | pex_delta                        | pex_snapshot
        v                                        v                                  v
    violation(6)                             violation(6)                       violation(6)
```

- A data message before the handshake, a `pex_delta` before the snapshot, or a **second**
  snapshot is a **protocol violation** (code `6`): the message is discarded and a violation
  strike is counted (§11.2).
- `pex_error` is acceptable in any state and does not change state.

### 5.4 Self and partner exclusion

A sender MUST NOT advertise **itself** (the link is its own advertisement) and MUST NOT
advertise **the link partner to itself**. A receiver skips such entries (§3.3).

### 5.5 Link teardown

When the underlying connection closes, all PEX state for the link (§9.1) is discarded. A new
connection starts from `AWAITING_HANDSHAKE` in both directions — including a fresh snapshot.

## 6 · Timing

All constants in §7.1.

### 6.1 Cadence

- The snapshot MAY be sent immediately after that direction's handshake (back-to-back is
  expected on a fresh link).
- After the snapshot, a sender MUST space its data messages by at least its **effective
  interval** and SHOULD send a delta at each interval tick **only when it has pending changes**
  (§4.4 — empty deltas are never sent).

### 6.2 Interval negotiation

- Each participant declares `interval` in its handshake — the minimum spacing it commits to for
  its own data messages. The default declaration is **60 seconds** (`PEX_DEFAULT_INTERVAL`);
  declarations MUST lie in `[30, 3600]` (`PEX_MIN_INTERVAL`, `PEX_MAX_INTERVAL`).
- A sender's **effective interval** is `max(own declared interval, PEX_MIN_INTERVAL)` — and,
  once it has received the remote's handshake, `max(own declared, remote declared)`: a sender
  MUST honor the receiver's declared interval as a floor once known. (The remote's declaration
  says "don't tell me more often than this.")

### 6.3 Jitter

A sender SHOULD add random jitter of **0 to +10%** of the effective interval to each scheduled
send, to decorrelate network-wide ticks. Jitter is **additive only** — a sender MUST NOT send
*earlier* than its effective interval. (This is what makes receiver enforcement, §6.4, exact.)

### 6.4 Receiver-side enforcement (the anti-flood floor)

A receiver MUST enforce a minimum inter-arrival time on data messages, per direction:

- Let `declared` = the sender's handshake `interval`, clamped into `[30, 3600]`.
- Let `floor` = `max(declared, PEX_MIN_INTERVAL) − PEX_ARRIVAL_GRACE` where
  `PEX_ARRIVAL_GRACE = 5` seconds (absorbs scheduling and clock skew).
- The first data message (the snapshot) starts the clock and is never a violation. Every
  subsequent data message arriving **less than `floor` seconds** after the previous data message
  in that direction is a **rate violation** (code `3`): the message MUST be discarded unprocessed
  and a strike counted (§11.2).
- A receiver MAY additionally penalize a sender that, after a round-trip allowance of one data
  message, keeps sending faster than the **receiver's** own declared interval (§6.2's MUST on the
  sender's side).

A sender receiving `pex_error` code `3` SHOULD double its effective interval on that link
(capped at `PEX_MAX_INTERVAL`).

## 7 · Caps & validation

### 7.1 Constants (frozen for version 1)

| Constant | Value | Meaning |
|---|---|---|
| `PEX_VERSION` | `1` | The wire version this document defines. |
| `PEX_MAX_ADDED` | `50` | Max entries in `pex_delta.added`. |
| `PEX_MAX_DROPPED` | `50` | Max ids in `pex_delta.dropped`. |
| `PEX_MAX_SNAPSHOT` | `200` | Max entries in `pex_snapshot.peers`. |
| `PEX_MAX_ADDRESSES` | `8` | Max `addresses` per peer entry. |
| `PEX_MAX_FLAGS` | `8` | Max `flags` per peer entry (and per handshake). |
| `PEX_MAX_FLAG_LEN` | `32` | Max characters per flag token. |
| `PEX_MAX_FRAME` | `262144` | Max message body bytes (256 KiB) — matches the DHT wire bound. |
| `PEX_DEFAULT_INTERVAL` | `60` s | Default declared send interval. |
| `PEX_MIN_INTERVAL` | `30` s | Hard interval floor (sender MUST, receiver enforces). |
| `PEX_MAX_INTERVAL` | `3600` s | Interval ceiling for declarations. |
| `PEX_ARRIVAL_GRACE` | `5` s | Receiver's enforcement tolerance (§6.4). |
| `PEX_MAX_ENTRY_AGE` | `1800` s | Max `last_seen` age an entry may be advertised with (§8.2). |
| `PEX_VIOLATION_LIMIT` | `3` | Strikes before a link's PEX is muted / the peer disconnected (§11.2). |

### 7.2 Oversize handling

- **Frame level:** a length prefix (or WebSocket payload) exceeding `PEX_MAX_FRAME` MUST be
  rejected without allocating the body. Because stream framing sync may be lost, the receiver
  SHOULD close the PEX stream (node↔node binding); on the relay binding it counts a violation
  (code `4`) and the frame is dropped.
- **List level:** a structurally valid message whose list exceeds its cap (`added` > 50,
  `dropped` > 50, `peers` > 200) MUST be **rejected whole** — discarded unprocessed, `pex_error`
  code `4` MAY be sent, and a violation strike is counted. Receivers MUST NOT truncate-and-accept
  (truncation would desynchronize the sender's told-state, §9.1, and mask sender bugs).
- **Sender level:** a sender MUST cap its own messages: excess pending changes queue for
  subsequent deltas (§9.1); a first-hand set larger than the snapshot cap sends the freshest 200
  and lets the remainder flow as later `added` entries.

### 7.3 Malformed content

- A frame that is not valid JSON, lacks a known `type`, or is missing a REQUIRED field of its
  type is a `PEX_BAD_MESSAGE` (code `1`): discarded, strike counted.
- A malformed **entry** inside a valid message is skipped silently (§3.3) — not fatal, no strike.
  This asymmetry is deliberate: entry-level junk is expected from honest-but-stale peers;
  message-level junk indicates a broken or hostile implementation.

## 8 · First-hand knowledge & provenance (the anti-flood core)

### 8.1 The first-hand rule

A participant MUST only advertise peers it knows **first-hand**, meaning at least one of:

1. it holds, or recently held, an mTLS-verified connection to the peer (`via: "direct"` for a
   direct link, `via: "relay"` for a relayed link — L7 §2/§6);
2. the peer is registered with **this participant's own introducer role** (the relay advertising
   its registrants), or this participant learned it from **its own** introducer/relay
   registration surface (`via: "introducer"`).

Entries learned **from PEX itself MUST NOT be re-advertised**. There is deliberately no `"pex"`
provenance token: an entry known only via PEX has no legitimate `via` to claim. A node that wants
to share a PEX-learned peer first dials and verifies it (mTLS handshake) — at which point it
knows the peer first-hand (`via: "direct"`) and may advertise it. This is what prevents
amplification: bad or stale entries die one hop from their source instead of echoing around the
network.

### 8.2 Freshness

`last_seen` is the Unix time of the advertiser's most recent first-hand evidence (last message on
a live connection; last registration heartbeat for an introducer). A sender MUST NOT advertise an
entry whose `last_seen` is more than `PEX_MAX_ENTRY_AGE` (1800 s) in the past.

### 8.3 `dropped` semantics

`dropped` means "**I** no longer consider this peer good" (it disconnected, went stale, or
misbehaved). It is **advisory, not authoritative**:

- A receiver MUST NOT delete a peer from its address book solely because one sender dropped it.
  It SHOULD remove the sender as a *source* for that candidate and MAY deprioritize it.
- A receiver MUST NOT drop a peer it has itself verified first-hand on another sender's say-so.

## 9 · State

### 9.1 Per-link sender state ("what I've told you")

Deltas are **relative to per-link history**. For each link, a sender keeps the set of `peer_id`s
it has told this link, with a fingerprint of each entry's advertised content (addresses + flags —
**not** `last_seen`, so heartbeat churn alone never re-advertises a peer):

- an entry enters `added` when it is first-hand-known but not yet told, or told with a different
  fingerprint (an update);
- an entry enters `dropped` when it was told but has left the sender's first-hand set;
- an unchanged told entry MUST NOT be re-advertised to that link;
- changes beyond the per-message caps queue for subsequent deltas in deterministic order
  (freshest first for `added`);
- told-state is per-link and dies with the link (§5.5).

### 9.2 Receiver state & dedup

Received entries are deduplicated by `peer_id`; for duplicates from different senders the entry
with the newest `last_seen` wins as the current hint. Hints are stored with their source link so
a `dropped` (§8.3) and a violation-triggered cleanup (§11.2) can be attributed.

### 9.3 Interaction with the address manager / peer pool

PEX is the feed, not the store. In a DIG Node:

- **Inbound:** validated PEX entries flow into the dig-gossip `AddressManager` as *candidates*
  (untried/new-table peers) to dial and verify — exactly like introducer-learned addresses. The
  address manager's own eviction, bucketing, and eclipse-resistance policies apply unchanged.
- **Outbound:** the node's first-hand set — its live connections and its own introducer learnings
  — feeds PEX. When a peer connects, disconnects, changes its candidate addresses, or ages past
  `PEX_MAX_ENTRY_AGE`, that change surfaces as `added`/`dropped` in the next delta on each link.
- Stale first-hand entries (older than `PEX_MAX_ENTRY_AGE`) are evicted from the advertise set
  (producing `dropped` on links that were told them).

## 10 · Transport bindings

### 10.1 Node ↔ Node — a dig-nat mux logical stream

- **Carrier:** one logical, bidirectional stream on the established dig-nat mTLS session
  (`PeerSession::open_stream`) — the **PEX stream**. Framing per §4.1 (u32-BE + JSON).
- **Identification:** the first frame on the stream is the opener's `pex_handshake`; its `type`
  tag identifies the stream's protocol (the same convention by which the DHT and range streams
  self-identify on the shared mux).
- **Topology:** each participant that wishes to advertise opens **its own** PEX stream and sends
  its direction (handshake → snapshot → deltas) on it; the acceptor of a PEX stream only reads
  from it (and MAY write `pex_error` frames back on the same stream). Two independent
  half-conversations — no stream-open race, no shared write ordering.
- **Identity:** the peer's identity is the connection's mTLS `peer_id` — never a wire field. A
  participant MUST NOT open more than one live PEX stream per connection; a second inbound PEX
  stream from the same peer is a protocol violation (code `6`).
- **Lifetime:** the PEX stream lives as long as the connection; closing it ends PEX (either side
  MAY close it without affecting sibling streams).

### 10.2 Relay → Node — riding the RelayMessage WebSocket (RLY-008)

PEX messages travel as additional top-level messages on the existing relay wire — the relay wire
is already `type`-tagged JSON over WebSocket, and the `pex_*` type tags do not collide with any
RLY-001..RLY-007 tag, so the binding is **purely additive** (designated **RLY-008**). No existing
RLY message changes shape or meaning.

- **Capability gate:** after `register` / `register_ack` (RLY-001), a PEX-capable node sends its
  `pex_handshake` as a WebSocket text frame. The relay MUST NOT send any PEX message to a
  connection that has not sent `pex_handshake` (legacy nodes see the wire exactly as before). A
  `pex_handshake` from an unregistered connection is answered with the **relay's** error envelope
  code `1` (`NOT_REGISTERED`), consistent with every other pre-registration message.
- **Relay direction:** the relay replies with its own `pex_handshake`, then a `pex_snapshot` of
  its registered same-network peers, then periodic `pex_delta`s as registrations come and go —
  entries carry `via: "introducer"`, the registrant's observed public address (`kind:
  "reflexive"`) when known, and the `relay-only` flag when the relay knows no direct path.
  Registration **is** the relay's first-hand evidence (§8.1); `last_seen` is the registrant's
  relay-connection liveness. All PEX traffic is scoped to the node's registered `network_id`,
  like every relay route.
- **Node direction:** the node's `pex_handshake` is a capability signal. A node SHOULD NOT send
  data messages to the relay; the relay MUST NOT fold node-sent PEX entries into its introducer
  registry (the registry is registration-backed only — a PEX hint must never impersonate a
  registration). A relay MAY simply discard node-sent data messages.
- **Errors:** PEX-level errors on this binding use `pex_error` (§4.5); the relay's own `error`
  envelope keeps its RLY code space. Timing (§6) and caps (§7) apply unchanged; the relay
  enforces §6.4 against chatty nodes and nodes enforce it against a chatty relay.

## 11 · Security considerations

### 11.1 Trust model

- PEX runs **only over authenticated links**: mTLS peer connections (node↔node) or the node's
  established relay registration (relay binding). There is no unauthenticated PEX surface.
- Received entries are **hints**, never authenticated facts. The only proof of a peer's identity
  is a completed mTLS handshake with it; the only proof of its network is that handshake's
  network check. A receiver MUST NOT mark a peer verified, trusted, or reachable on the basis of
  a PEX entry.
- The sender's identity for attribution is always the transport identity (mTLS `peer_id` /
  registered relay identity) — never a message field.

### 11.2 Misbehavior & penalties

A receiver counts a **strike** per direction for each violation: rate (code `3`), oversize (code
`4`), bad message (code `1`), or state violation (code `6`). On reaching `PEX_VIOLATION_LIMIT`
(3) strikes, the receiver SHOULD send one `pex_error` (best-effort), MUST mute the direction
(ignore all further PEX from it), and MAY disconnect the peer and penalize it in its reputation
system. Candidates learned from a muted peer SHOULD be deprioritized.

### 11.3 Resource bounds

Every inbound surface is bounded before allocation: frame size (§7.2), list caps (§7.1),
per-entry address/flag caps, and the arrival-rate floor (§6.4). A hostile sender can therefore
cost a receiver at most one bounded frame per `PEX_MIN_INTERVAL` per link before it is muted.

### 11.4 Eclipse & poisoning resistance

The first-hand rule (§8.1) stops re-gossip amplification; the address-manager integration (§9.3)
applies the existing bucketing/eclipse defenses to PEX-learned candidates; provenance (`via`) and
per-source attribution (§9.2) let a node discount sources that feed it junk. A node SHOULD keep
using multiple discovery sources (introducer, DHT, PEX from several peers) so no single link
shapes its view of the network.

## 12 · Conformance

The frozen, testable statements of version 1. An implementation conforms iff all hold.

| ID | Statement |
|---|---|
| PEX-01 | The four message shapes (§4.2–§4.5) serialize with exactly the given `type` tags and field names; unknown JSON fields are ignored on receive. |
| PEX-02 | The peer entry has the §3 shape; `addresses[]` is byte-compatible with the L7 `dig.getPeers` / DHT `Contact` addresses (`host`/`port`/`kind`, kinds `direct`\|`mapped`\|`reflexive`\|`relay`). |
| PEX-03 | Stream framing is u32-BE length prefix + JSON body, bounded by `PEX_MAX_FRAME` = 262144, rejected before allocation when over. |
| PEX-04 | Caps: 50 `added` / 50 `dropped` / 200 snapshot / 8 addresses / 8 flags — senders never exceed them; receivers reject (not truncate) over-cap messages with a violation. |
| PEX-05 | Handshake precedes everything; snapshot is the first data message, exactly once per direction; delta-before-snapshot / second-snapshot / data-before-handshake are code-6 violations. |
| PEX-06 | A sender's data messages are spaced ≥ its effective interval (`max(own, remote-known, 30 s)`), jitter additive-only; a receiver discards + strikes any data message arriving < `max(declared, 30) − 5` s after the previous one. |
| PEX-07 | Empty deltas are never sent; unchanged told entries are never re-advertised on the same link; per-link told-state resets with the link. |
| PEX-08 | Only first-hand peers are advertised (`via` ∈ `direct`\|`relay`\|`introducer`); PEX-learned entries are not re-advertised unverified; entries older than 1800 s are not advertised. |
| PEX-09 | `dropped` is advisory: a receiver never deletes a first-hand-verified peer on it, and only unlists the sender as a source otherwise. |
| PEX-10 | Malformed entries are skipped silently; malformed messages are discarded with a strike; 3 strikes mute the direction. |
| PEX-11 | Self and the link partner are never advertised to that link. |
| PEX-12 | Node↔node: PEX rides one self-identifying logical stream per advertising direction on the dig-nat mux; identity is the mTLS `peer_id`, never a wire field. |
| PEX-13 | Relay binding (RLY-008): purely additive to RLY-001..RLY-007; gated on the node's `pex_handshake` after registration; relay entries are registration-backed with `via:"introducer"`; node-sent data messages never enter the introducer registry. |
| PEX-14 | The error envelope is `pex_error` with the §4.5 code table, on both bindings; errors are advisory. |

Cross-references: the L7 peer-network page (`docs.dig.net` → protocol → peer-network) defines the
`peer_id`, the address/`Contact` shapes, RLY-001..RLY-007, and the framed-JSON convention this
spec builds on; the superproject `SYSTEM.md` records the change-impact edges (a change to the
shared shapes must be mirrored across the affected modules in the same unit of work).

## 13 · References

- BitTorrent PEX (`ut_pex`) — BEP 11 lineage: delta exchange (`added`/`dropped`), ~1-minute
  cadence with receiver-enforced minimum, ~50-entry caps, no third-party re-flooding.
- L7 · DIG Node peer network — `modules/services/docs.dig.net/docs/protocol/peer-network.md`.
- `dig-gossip` — the peer pool + `AddressManager` PEX feeds (§9.3).
- `dig-relay` — the `RelayMessage` wire PEX's relay binding rides (§10.2).
- `dig-nat` — the mTLS mux transport PEX's node binding rides (§10.1).
- `dig-dht` — the sibling framed-JSON wire sharing the §4.1 conventions.
- RFC 2119 — requirement-level key words.

---

## Appendix A · Implementers' note — embedding the `PexEngine`

The crate ships a transport-agnostic, sans-IO `PexEngine`: you feed it link events, inbound
messages, local peer-set changes, and clock ticks; it returns the messages to send and the events
to act on. Both integrations are thin adapters:

**dig-node** (node↔node binding, §10.1):

1. Create one `PexEngine` (`PexConfig::new(local_peer_id, network_id)` + local flags).
2. On each established peer connection: call `engine.link_up(peer_id, now_ms)` and write the
   returned frames (`msg.encode()`) on a newly opened mux logical stream — that stream is your
   sending direction. Read inbound PEX streams (first frame `pex_handshake`) and feed each
   decoded message to `engine.on_message(peer_id, msg, now_ms)`; send any returned replies,
   honor `disconnect`.
3. Drive `engine.tick(now_ms)` about once per second; write the returned `(peer_id, message)`
   pairs to the matching PEX streams.
4. Wire events: `PexEvent::Candidates` → `AddressManager` new-table candidates (dial + verify);
   `PexEvent::Dropped` → unlist that source; `PexEvent::Violation { mute: true }` → reputation
   penalty / disconnect.
5. Feed first-hand knowledge back: on every verified peer connect / address change, call
   `engine.upsert_known(entry)` (with the honest `via` + fresh `last_seen`); on disconnect/stale,
   `engine.remove_known(peer_id)`. On connection close, `engine.link_down(peer_id)`.

**dig-relay** (relay binding, §10.2):

1. Create one `PexEngine` for the introducer role (flags `["introducer"]`).
2. On a registered connection's first `pex_handshake` text frame: `engine.link_up` +
   `engine.on_message`, and send returned messages as WebSocket text frames
   (`serde_json::to_string`, no length prefix). Never send PEX to connections that have not
   sent `pex_handshake`.
3. Mirror the registry into the engine: on register → `engine.upsert_known` (`via:
   Introducer`, observed reflexive address, `relay-only` when applicable); on
   unregister/disconnect/liveness-timeout → `engine.remove_known`. Never fold inbound node PEX
   data into the registry — discard it.
4. Drive `engine.tick` on the relay's housekeeping timer; route per-link output to the matching
   WebSocket, scoped by `network_id` exactly like every other relay route.
