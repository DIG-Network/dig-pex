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
| `payment` | object | OPTIONAL (omitted when absent). The peer's self-signed payment address (§3.4). |

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

### 3.4 Payment address

A peer MAY carry a `payment` object designating where the incentive layer should send its earnings:

```json
"payment": {
  "address": "xch1...",
  "spki":    "<base64 of the peer's TLS SubjectPublicKeyInfo DER>",
  "sig":     "<base64 signature over the canonical bytes of 3.4.1>"
}
```

A payee field cannot be an unauthenticated claim. PEX records are **relayed**, so an unsigned payee
means the incentive layer pays whoever last forwarded the record rather than whoever earned it, and
the victim never observes the difference because a payment that succeeds looks identical either way.

**Privacy: the claim is public by design.** A PEX record is gossiped to every peer that learns of the
advertised peer and is relayed second- and third-hand, so `address` and `spki` MUST be treated as
published to the whole network. `spki` reveals nothing new — it is the same public key the peer
presents in its TLS certificate on every connection — but the claim does publicly and durably link a
`peer_id` to an on-chain address whose activity is observable by anyone. A peer that does not wish to
publish a payout address MUST omit the `payment` object; an embedder SHOULD populate it only from an
explicitly configured payout address and MUST give the operator a way to leave it unset. Receivers
MUST NOT treat the absence of a claim as a fault (§3.4.3).

#### 3.4.1 Canonical signing bytes

The signature covers exactly, with no separators other than those shown:

```text
"dig-pex/payment-address/v1\0"
  || u32be(len(peer_id))    || peer_id
  || u32be(len(network_id)) || network_id
  || u32be(len(address))    || address
```

All strings are UTF-8; lengths are byte counts. The context string domain-separates the signature
from every other DIG protocol, and the length prefixes make the encoding injective, so no two
different field triples produce the same bytes.

A valid signature proves that **the holder of the private key whose SPKI hashes to `peer_id`
designated this address as its payee on this network**. It does NOT prove the peer is reachable or
honest, that the address is well-formed or spendable, that the claim is recent, or that it has not
been superseded by a newer claim the verifier has not seen.

`last_seen` is deliberately NOT covered. Including it would expire the signature on the advertiser's
next heartbeat, requiring the advertised peer to re-sign continuously and the advertiser to obtain a
signature it cannot produce itself — an availability dependency on the very peer the record exists to
route around. The cost of excluding it is that a revoked address stays verifiable until a newer claim
propagates; a consumer SHOULD therefore prefer the claim on the freshest first-hand record.

#### 3.4.2 Caps

| Field | Cap |
|---|---|
| `address` | 128 characters (`PEX_MAX_PAYMENT_ADDRESS_LEN`) |
| `spki` | 512 base64 characters (`PEX_MAX_PAYMENT_SPKI_LEN`) |
| `sig` | 256 base64 characters (`PEX_MAX_PAYMENT_SIG_LEN`) |

An entry whose `payment` exceeds any cap is skipped (§3.3). This is a size verdict only.

#### 3.4.3 Verification, and the two verdicts on one record

A verifier that wishes to pay a peer MUST, in order:

1. check every field is within its cap and `spki` / `sig` are valid base64;
2. recompute **`SHA-256(spki) == peer_id`** — this is what makes the record self-proving, since
   `peer_id` is defined as `SHA-256(TLS SPKI DER)` (§2). No directory, resolution step or additional
   trust root is consulted, which matters because the parties most needing to check a claim (relays,
   and any node holding the record second- or third-hand) are the least likely to have one;
3. verify `sig` over §3.4.1's bytes using the key in `spki`.

**Reachability and payability are different verdicts on one record.** An entry whose claim is absent,
malformed or unverifiable remains a perfectly good dial hint and MUST still be usable as one — making
a bad claim cost a peer its reachability would hand a relaying attacker a way to partition it. An
implementation MUST NOT expose an unverified payee to a caller.

Signature verification is the embedder's primitive (DIG node certificates are ECDSA P-256 today), but
the `peer_id` binding of step 2 MUST be performed by the PEX implementation itself, so that a
permissive verifier cannot be induced to name the wrong payee.

#### 3.4.4 Relation to provenance

A signed claim is self-proving and is therefore NOT subject to the re-flooding concern of §8.1 —
relaying it cannot corrupt it. This does **not** relax the §8.1 rule: an entry learned via PEX still
has no legitimate `via` to claim and is still never re-advertised until independently verified. The
re-flooding rule is about the *record*, not about the claim inside it, and is unchanged.

The one channel on which a claim is *not* merely relayed is the sender's own `pex_handshake`
(§4.2.1): there the claim arrives first-hand from the peer it names, over a link whose mTLS identity
is exactly the `peer_id` the claim must bind to. That is what lets a receiver attach it to that
peer's entry and re-advertise it without violating §8.1 — the entry is advertisable because the
receiver connected to the peer, and the claim is attachable because the same link proved whose it is.

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
| `payment` | object | OPTIONAL (default absent). The **sender's own** signed payment claim, in the §3.4 shape and no other. Its `spki` MUST hash to the sender's mTLS `peer_id` on this link. Carriage, provenance, verification, storage and re-advertisement are governed entirely by §4.2.1. |

A handshake carrying a claim:

```json
{ "type": "pex_handshake", "version": 1, "network_id": "mainnet", "interval": 60,
  "flags": ["storage"],
  "payment": { "address": "xch1...", "spki": "<base64 of the sender's TLS SPKI DER>",
               "sig": "<base64 signature over the canonical bytes of §3.4.1>" } }
```

`payment` was added in crate version **0.3.0**. The wire `version` stays **`1`**: the field is
purely additive, and a version-1 receiver that does not know it MUST ignore it (§2). A sender MUST
NOT bump `version` on account of this field — a handshake declaring `version: 2` is muted with
`pex_error` code `2` by every conformant receiver (§5.2), so bumping it would break exactly the
interoperability the additive shape preserves.

#### 4.2.1 The sender's own payment claim (`payment`)

§3.4 defines a signed payment claim that may ride on a `PeerEntry`, but leaves open how a peer's own
claim reaches the peers that advertise it. Entries are advertised by *other* participants, and §8.1
forbids re-advertising anything learned via PEX, so a peer cannot inject its claim into the gossip by
sending an entry about itself (§5.4 forbids that too). The handshake is the one message a peer sends
*as itself* on an authenticated link, so it is the channel: a participant states its own payee once
per link, to the peer that will advertise it.

Every rule in this section is **specified, not yet implemented** as of the 0.3.0 development head
except where the status table at the end of this section cites an implementation.

**(1) The claim is the §3.4 type, and it is the sender's own.** A `payment` on a `pex_handshake`
MUST be the object of §3.4 — the same three fields, the same §3.4.1 signing bytes, the same §3.4.2
caps — and MUST NOT be a bare address or any other shape. It asserts *the sender's* payee. A sender
MUST NOT place another peer's claim on its handshake, and a receiver MUST NOT attach a handshake
claim to any entry other than the sending peer's own.

**(2) `peer_id` binding is to the link, not to a wire field.** The `peer_id` a claim is verified
against is the link's mTLS peer identity supplied by the host — never a field of any PEX message
(PEX-12, §11.1). A receiver MUST verify `SHA-256(claim.spki) == link_peer_id` and MUST reject the
claim when it differs. The `network_id` used for verification is the link's, which the §5.2 check
has already proven equal to the receiver's own; a receiver MUST NOT verify against any other
network.

**(3) Verification happens before storage and before re-advertisement.** A receiver MUST run the
full §3.4.3 order — caps, then base64 decodability, then the `SHA-256(spki) == peer_id` binding
(performed by the PEX implementation itself, never delegated), then the signature over §3.4.1's
bytes using the embedder-supplied primitive — and MUST complete it successfully **before** the
claim is stored, attached to an entry, or included in any outgoing message. A receiver MUST NOT
store an unverified claim for later verification, and MUST NOT synthesize, repair, re-encode or
re-sign a claim under any circumstances.

**(4) A failed claim costs the claim and nothing else.** A claim that fails for any reason — over
caps, undecodable, `peer_id` mismatch, bad signature, or no verifier configured — MUST be dropped,
and the handshake MUST otherwise be processed exactly as if no `payment` field had been present:
no `pex_error`, no strike, no mute, no effect on the link's phase, interval or flags. Two reasons
this direction is normative rather than discretionary: §3.4.3 already rules that payability never
costs reachability, and the failure mode of striking is that an embedder with a missing or wrong
verifier would mute the PEX of every honest neighbour it has — a self-inflicted partition triggered
by a purely local misconfiguration.

**(5) No verifier configured means no payee.** A receiver with no signature verifier configured
MUST treat every claim as unverified: it MUST NOT store one, MUST NOT expose one, and MUST NOT
attach one to an entry it advertises. It MUST continue to run PEX normally in both directions. This
is fail-closed on payability and fail-open on reachability — the same asymmetry as §3.4.3.

**(6) The PEX implementation owns the store; the embedder writes no carriage code.** Verified
neighbour claims are held by the PEX implementation itself, keyed by `peer_id`, at most one per
peer, and are attached to that peer's entry when the implementation advertises it. An embedder MUST
NOT be required to move a claim from a handshake onto a `PeerEntry`, and a conforming implementation
MUST NOT require it to. Three consequences:

- **Replacement.** A newly verified claim for a peer replaces any claim stored for that peer. A
  claim that fails verification MUST NOT replace or remove a stored verified one — the store is only
  ever advanced by a claim that verifies. A stored claim therefore proves what the peer designated
  when it last successfully handshook, not what it designates now (§3.4.1).
- **Precedence.** When a verified claim is stored for a peer, it MUST take precedence over any claim
  the embedder attached to that peer's entry, because it is the only one the PEX implementation has
  itself verified against the link identity. When no verified claim is stored, an
  embedder-attached claim MUST be left on the entry unchanged and advertised as-is; verifying it is
  the receiving end's job (§3.4.3).
- **Storing a claim is not knowing a peer.** Storing a claim MUST NOT create, refresh or extend an
  entry in the first-hand set. Only an mTLS-verified connection or the participant's own introducer
  role makes a peer first-hand-known (§8.1); a peer with a stored claim and no first-hand entry is
  not advertisable, and its claim goes nowhere.

**(7) Lifetime.** A stored claim is retained exactly as long as **either** the link that delivered it
is up **or** the peer has an entry in the first-hand set. It MUST be discarded when both cease:
removing the peer from the first-hand set discards it, and link teardown discards it *unless* the
peer is still in the first-hand set — in which case the entry stays advertisable for up to
`PEX_MAX_ENTRY_AGE` after disconnect (§8.2) and MUST keep its claim for that whole window, since
dropping it would silently stop paying a peer that is still being advertised. Per-link told-state
still dies with the link (§5.5, §9.1); the claim store does not.

**(8) Re-advertisement.** A claim newly stored, replaced or removed for a peer that has already been
told to a link changes that entry's advertised content, so the entry MUST be re-advertised on that
link as an `added` **update** at the next delta (§9.1, §4.4). The claim is part of the §9.1
fingerprint. A claim is never carried in `dropped`, which is an array of `peer_id` strings (§4.4) —
vacuously satisfied by the wire shape, and it MUST remain so.

**(9) Sender-side configuration MUST refuse an unusable claim.** The API by which an embedder
configures its own claim MUST refuse — at configuration time, not at send time — a claim whose
`spki` does not hash to the participant's own `local_peer_id`, or which exceeds any §3.4.2 cap, so
that a misconfigured claim never leaves the node. A participant that has configured no claim sends
handshakes with no `payment` field, which is an ordinary and complete conformance state: a peer that
does not wish to publish a payout address MUST be able to leave it unset (§3.4).

**(10) Resource bounds.** This section introduces no new constant and no new unauthenticated
surface. The claim is bounded by §3.4.2's existing caps, so a maximal handshake claim is at most 896
characters of field content — under 1.1 KB of framed JSON against `PEX_MAX_FRAME` (262144), over
two orders of magnitude below the frame cap. A claim can enter the store only through a handshake
accepted on an already-authenticated link (§11.1), at most one per peer, and rule 7 discards it when
the peer is neither connected nor known, so the store is bounded by the number of live links plus
the size of the first-hand set (§11.3).

**(11) Compatibility.** A `pex_handshake` carrying an unknown field decodes on a version-1 decoder —
`src/wire.rs:263` (`unknown_fields_ignored_on_receive`) is exactly that case — so a dig-pex 0.2.x
receiver ignores `payment` and completes the handshake normally, and a 0.3.0 sender interoperates
with every 0.2.x peer with no negotiation and no capability flag. `PEX_VERSION` remains `1`
(`src/caps.rs:9`). The claim's *presence* is not a capability signal and MUST NOT be read as one;
capability flags are the §3.2 tokens in `flags` and nothing else.

**(12) Relay binding.** These rules are per-**link**, not per-binding: a node's `pex_handshake` to a
relay (§10.2) MAY carry its claim, and a relay MAY attach it under exactly the rules above, since the
relay's registered connection is the authenticated link and registration is its first-hand evidence.
`dig-relay` does not do so in this pass — its own SPEC §4 pins introducer entries to `payment`
absent — so relay-advertised entries carry no claim and no relay-side behaviour is specified here.

**What a reader MUST NOT conclude.** A verified claim proves only that the holder of the key whose
SPKI hashes to this `peer_id` designated this address as its payee on this network (§3.4.1). It does
NOT prove the peer is reachable, honest, or still connected; NOT that the address is well-formed,
spendable, or on any particular chain; NOT that the claim is current or unsuperseded; and NOT that
the peer earned anything. The absence of a claim is NOT a fault, NOT a downgrade, and MUST NOT
affect reachability, strikes, muting, or an entry's usefulness as a dial hint (§3.4.3). A stored
claim is NOT evidence that the link is still up. Receiving a claim does NOT make its sender
first-hand-known (rule 6).

**Implementation status of this section** — every row is a clause of this section against the code
in the same unit of work:

| Rule | Status |
|---|---|
| 1 — the §3.4 claim type | Implemented: `src/payment.rs:173` `PaymentClaim`, `:134` `payment_signing_bytes`, `:65`–`:73` the three caps. |
| 1 — carriage on the handshake | **Specified, not yet implemented**: `PexMessage::PexHandshake` has no `payment` field (`src/wire.rs:40`). |
| 2, 3 — binding + verification order | Primitive implemented: `src/payment.rs:236` `PaymentClaim::verify` runs caps → base64 → `SHA-256(spki) == peer_id` → verifier, in that order, and performs the binding itself. Its application to the handshake is **specified, not yet implemented**: `src/engine.rs:446` `on_handshake` neither receives nor verifies a claim. |
| 4, 5 — no strike, fail closed | **Specified, not yet implemented.** |
| 6, 7 — store, precedence, lifetime | **Specified, not yet implemented**: `PexEngine` holds no claim store and no verifier (`src/engine.rs:133`), so `link_down` (`:239`) and `remove_known` (`:190`) have nothing to discard. |
| 8 — fingerprint includes the claim | Implemented: `src/entry.rs:312`–`317` and `:361`–`364` already fold all three claim fields into both fingerprints; §9.1's prose is corrected in this same unit. The delta-visibility half — a claim mutation reaching links already told the entry — is **specified, not yet implemented**: the advertisable-set cache is keyed on first-hand-set mutations only (`src/engine.rs:145`–`151`). |
| 8 — never in `dropped` | Vacuously satisfied by the wire shape: `dropped` is an array of `peer_id` strings (§4.4). |
| 9 — sender-side refusal | **Specified, not yet implemented**: `PexConfig` carries no claim and no verifier (`src/engine.rs:34`). |
| 10 — bounds | No new constant. §3.4.2's caps are implemented (`src/payment.rs:223` `within_caps`); the store bound is **specified, not yet implemented**. |
| 11 — compatibility | Implemented and unchanged: `PEX_VERSION = 1` (`src/caps.rs:9`); `src/wire.rs:263` proves a version-1 decoder ignores an unknown handshake field. |
| 12 — relay binding | Out of scope for this crate version; `dig-relay` unchanged. |
| Negative clauses | Constraints on readers and consumers; nothing to implement. |

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
- The handshake's `payment` claim (§4.2.1), when present, is processed **only after the handshake
  itself is accepted** — after the state check (§5.3), the `version` check and the `network_id`
  check have all passed. A handshake muted for `version` (code `2`) or `network_id` (code `5`), or
  struck as a state violation (code `6`), MUST NOT have its claim verified, stored, or attached to
  anything.
- A `payment` claim that fails verification MUST NOT produce a `pex_error`, a strike, or a mute.
  It is dropped and the handshake is otherwise processed normally (§4.2.1 rule 4). Payability never
  costs reachability (§3.4.3).

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

`pex_error` is advisory and **unauthenticated** — any non-muted peer can send one at will (§4.5,
§11.1) — so a sender MUST bound how far/fast an unearned code-3 can push its own cadence:

- **Plausibility gate:** a sender MUST only apply the back-off if it has itself sent a data
  message to that peer within the receiver's arrival-floor window — i.e. `now` is within `floor`
  seconds (per this section's `floor` definition, evaluated against the sender's OWN
  `self_interval_secs`) of `last_data_send_ms` on that link. A code-3 arriving outside that window
  cannot correspond to a real violation of the sender's own sends and MUST be ignored (the
  interval is left unchanged).
- **Rate limit:** even a plausible code-3 MUST be honored at most once per (pre-doubling)
  effective interval on that link. A burst of further code-3 frames arriving before that interval
  elapses again MUST NOT re-apply the doubling — so a peer flooding code-3 cannot ratchet the
  interval toward `PEX_MAX_INTERVAL` faster than one genuine violation could.

Together these bound a spoofed code-3 to, at most, one doubling per interval the sender could
plausibly have violated — never an unbounded or immediate escalation to `PEX_MAX_INTERVAL`.

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
| `PEX_MAX_PAYMENT_ADDRESS_LEN` | `128` | Max characters in `payment.address` (§3.4.2). |
| `PEX_MAX_PAYMENT_SPKI_LEN` | `512` | Max base64 characters in `payment.spki` (§3.4.2). |
| `PEX_MAX_PAYMENT_SIG_LEN` | `256` | Max base64 characters in `payment.sig` (§3.4.2). |
| `PEX_MAX_FRAME` | `262144` | Max message body bytes (256 KiB) — matches the DHT wire bound. |
| `PEX_DEFAULT_INTERVAL` | `60` s | Default declared send interval. |
| `PEX_MIN_INTERVAL` | `30` s | Hard interval floor (sender MUST, receiver enforces). |
| `PEX_MAX_INTERVAL` | `3600` s | Interval ceiling for declarations. |
| `PEX_ARRIVAL_GRACE` | `5` s | Receiver's enforcement tolerance (§6.4). |
| `PEX_MAX_ENTRY_AGE` | `1800` s | Max `last_seen` age an entry may be advertised with (§8.2). |
| `PEX_VIOLATION_LIMIT` | `3` | Strikes before a link's PEX is muted / the peer disconnected (§11.2). |
| `PEX_MAX_RECEIVED_PER_LINK` | `4096` | Cap on one link's `received` accumulator, oldest-`last_seen` evicted (§9.2, §11.3). |
| `PEX_MAX_HINTS` | `16384` | Cap on the engine-global `hints` map, oldest-`last_seen` evicted (§9.2, §11.3). |

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
  A sender MUST ALSO bound its messages by **encoded bytes**, not by entry count alone: the entry
  count caps are a proxy, and they stopped implying the frame bound once entries could carry a signed
  payment address (§3.4). Two hundred maximal entries encode to ~214 KB without a claim and ~281 KB
  with one, against a 256 KiB frame — so a count-only sender would emit a frame every conformant
  receiver is required to reject, and be struck for it. A sender therefore drops trailing (least
  fresh) entries until the encoded message fits `PEX_MAX_FRAME`; the remainder flows as later
  `added` entries (§9.1).

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
it has told this link, with a fingerprint of each entry's advertised content — its addresses, its
flags, and its attached `payment` claim (all three wire fields), but **not** `last_seen`, so
heartbeat churn alone never re-advertises a peer while a replaced or re-signed claim does
(`src/entry.rs:312`, `src/entry.rs:361`):

- an entry enters `added` when it is first-hand-known but not yet told, or told with a different
  fingerprint (an update);
- an entry enters `dropped` when it was told but has left the sender's first-hand set;
- an unchanged told entry MUST NOT be re-advertised to that link;
- changes beyond the per-message caps queue for subsequent deltas in deterministic order
  (freshest first for `added`);
- told-state is per-link and dies with the link (§5.5).
- a `payment` claim newly stored, replaced, or removed for an already-told peer changes that peer's
  fingerprint and therefore enters `added` as an **update** on every link that was told it (§4.2.1
  rule 8); a claim is never carried in `dropped`, which is an array of `peer_id` strings (§4.4).

### 9.2 Receiver state & dedup

Received entries are deduplicated by `peer_id`; for duplicates from different senders the entry
with the newest `last_seen` wins as the current hint. Hints are stored with their source link so
a `dropped` (§8.3) and a violation-triggered cleanup (§11.2) can be attributed.

Both receiver-side accumulators are **bounded** — a single per-message cap (§7.1's
`PEX_MAX_ADDED`/`PEX_MAX_SNAPSHOT`) bounds one message but not the cumulative total an
authenticated sender can push across many messages over a link's lifetime:

- **Per-link `received`** (the set of `peer_id`s that link has told us, kept for §8.3 `dropped`
  attribution) is capped at `PEX_MAX_RECEIVED_PER_LINK` (4096) entries.
- **The global `hints` map** (the deduplicated current-best hint per `peer_id`, across all links)
  is capped at `PEX_MAX_HINTS` (16384) entries.
- On an insert that would exceed either cap, the implementation MUST evict the single
  oldest-`last_seen` entry from that map first (ties broken deterministically, e.g. by `peer_id`)
  before inserting the new one — an LRU-by-freshness policy mirroring the address manager's own
  eviction (§9.3). A cap MUST NOT be enforced by rejecting the new (fresher) entry instead.
- When a direction is muted (§11.2), the implementation MUST treat it like a soft `link_down` for
  these accumulators: clear that link's `received` set and remove any `hints` entries currently
  sourced from it, immediately — not deferred until the underlying connection actually closes. A
  muted direction accepts no further inbound PEX, so its accumulated state can only ever be freed,
  never usefully grown.

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

Per-message caps are not sufficient on their own: an authenticated peer that stays within every
per-message cap can still, over many messages across a link's lifetime, push an unbounded number
of *distinct* `peer_id`s. The receiver-side accumulators this would otherwise grow without limit
(the per-link `received` set and the global `hints` map, §9.2) are therefore themselves bounded
(`PEX_MAX_RECEIVED_PER_LINK`, `PEX_MAX_HINTS`) with oldest-`last_seen` eviction, and are freed
promptly on mute rather than left to accumulate until the connection closes (§9.2).

The verified payment-claim store (§4.2.1 rules 6–7) is bounded on the same principle: a claim can
enter it only through a handshake accepted on an already-authenticated link, at most one per peer,
and it is discarded once the peer has neither a live link nor a first-hand entry — so it is bounded
by the number of live links plus the size of the first-hand set, and adds no new unauthenticated
growth surface (§4.2.1 rule 10). Its per-field size is bounded before decoding by §3.4.2's caps.

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
| PEX-15 | The per-link `received` set is capped at `PEX_MAX_RECEIVED_PER_LINK` and the global `hints` map at `PEX_MAX_HINTS`, both with oldest-`last_seen` eviction on overflow; muting a direction immediately clears its `received` set and any `hints` it sources. |
| PEX-16 | A `pex_error` code-3 back-off is applied only when the sender's own last data send on that link falls within the receiver's arrival-floor window of `now`, and at most once per (pre-doubling) effective interval — an unauthenticated code-3 flood cannot force an unbounded or immediate escalation to `PEX_MAX_INTERVAL`. |
| PEX-17 | `pex_handshake` carries an OPTIONAL `payment` in exactly the §3.4 claim shape — never a bare address; the addition is additive and the wire `version` stays `1`, so a version-1 decoder that does not know the field ignores it and completes the handshake (§2, §4.2.1 rules 1, 11). |
| PEX-18 | A handshake claim is the **sender's own**: it is verified against the link's mTLS `peer_id` (never a wire field) and the link's `network_id`, `SHA-256(spki) == peer_id` is recomputed by the PEX implementation itself, and a receiver never attaches a handshake claim to any entry but the sending peer's (§4.2.1 rules 1–3). |
| PEX-19 | A claim that fails for any reason — caps, base64, `peer_id` mismatch, bad signature — is dropped while the handshake is processed exactly as if the field were absent: no `pex_error`, no strike, no mute, no change to phase / interval / flags (§4.2.1 rule 4). |
| PEX-20 | A receiver with no verifier configured stores, exposes and advertises no claim, and runs PEX normally in both directions — fail-closed on payability, fail-open on reachability (§4.2.1 rule 5). |
| PEX-21 | The PEX implementation itself verifies, stores (keyed by `peer_id`, at most one per peer) and attaches neighbour claims, so an embedder writes no carriage code; a verified claim takes precedence over an embedder-attached one, a failed claim never replaces a stored verified one, and storing a claim never creates or refreshes a first-hand entry (§4.2.1 rules 6, 9). |
| PEX-22 | The §9.1 advertised-content fingerprint includes all three claim fields, so a claim that arrives, changes or is removed re-advertises its entry as an `added` update on every link already told it; a claim never appears in `dropped` (§4.2.1 rule 8, §9.1). |
| PEX-23 | A stored claim outlives link teardown for as long as the peer stays in the first-hand set (up to `PEX_MAX_ENTRY_AGE`) and is discarded when it leaves — bounding the store by live links plus first-hand set, with no new constant and no new unauthenticated surface (§4.2.1 rules 7, 10, §11.3). |

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
6. Payment claims (§4.2.1) need **no carriage code**. Configure two things on the config once — the
   node's own signed claim (only if the operator set a payout address) and an ECDSA P-256 signature
   verifier for the key type `dig-tls` issues — and the engine puts the claim on every outgoing
   handshake, verifies and stores each neighbour's, and attaches it whenever it advertises that
   neighbour. Do NOT build a claim onto a `PeerEntry`, verify one, or copy one out of a handshake
   yourself; a claim you attach by hand is superseded by the verified one the engine holds (§4.2.1
   rule 6). A node with no verifier configured runs PEX normally and simply never learns a payee, and
   a node with no claim configured sends handshakes without the field — both are complete conformance
   states (§4.2.1 rules 5, 9). Read a payee only through `PeerEntry::verified_payment_address`.

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
5. Payment claims: the §4.2.1 rules are per-link, so the relay MAY configure its own claim and a
   verifier and they would apply to its registered links unchanged. It does not in this pass —
   `dig-relay`'s own SPEC §4 pins introducer entries to `payment` absent — so leave both unset. A
   node's handshake to the relay may still carry that node's claim; with no verifier configured the
   relay stores nothing and advertises nothing (§4.2.1 rule 5), which is the intended behaviour here.
