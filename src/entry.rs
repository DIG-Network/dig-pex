//! The **peer entry** — the unit of exchange (SPEC §3). It is the L7 `PeerRecord` shape extended
//! with a `flags` list, carrying a `peer_id`, candidate `addresses`, the `network_id`, a `last_seen`
//! Unix-seconds timestamp, a `via` provenance, and per-peer capability `flags`.
//!
//! ## Byte-compatibility
//!
//! [`Address`] (`{ host, port, kind }`) is byte-compatible with the L7 `dig.getPeers` addresses and
//! the dig-nat / dig-gossip / dig-dht `Contact` address shape — same JSON field names and the same
//! `kind` tokens (`direct` | `mapped` | `reflexive` | `relay`). It is mirrored here (rather than
//! importing those crates) to keep the PEX dependency surface minimal; the wire form MUST stay
//! identical so a returned entry drops straight into a dial target.
//!
//! ## Tolerant decode, strict validation
//!
//! Inbound entries decode **tolerantly**: an unrecognized `kind` or `via` token deserializes to the
//! [`AddressKind::Unknown`] / [`Provenance::Unknown`] catch-all rather than failing the whole
//! message, and every field has a default. This is what makes a malformed entry *skipped, not fatal*
//! (SPEC §3.3, §7.3): [`PeerEntry::validate`] decides keep-or-skip; a broken token never aborts the
//! sibling entries around it.

use serde::{Deserialize, Serialize};

use crate::caps::{PEX_MAX_ADDRESSES, PEX_MAX_ENTRY_AGE, PEX_MAX_FLAGS, PEX_MAX_FLAG_LEN};
use crate::error::EntrySkip;

/// How a candidate address was learned — the L7 `dig.getPeers` `addresses[].kind` tokens (SPEC §3.1).
/// The lowercase serde spelling is the frozen wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressKind {
    /// A directly reachable address (publicly routable or port-forwarded).
    Direct,
    /// A UPnP / NAT-PMP / PCP-mapped external address.
    Mapped,
    /// A STUN-discovered public reflexive address.
    Reflexive,
    /// Reachable through the relay (no direct candidate).
    Relay,
    /// An unrecognized token — the catch-all so an unknown `kind` skips the entry (SPEC §3.3)
    /// instead of aborting the message. Never emitted by a conformant sender.
    #[serde(other)]
    #[default]
    Unknown,
}

impl AddressKind {
    /// The frozen lowercase wire token (or `"unknown"` for the catch-all).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AddressKind::Direct => "direct",
            AddressKind::Mapped => "mapped",
            AddressKind::Reflexive => "reflexive",
            AddressKind::Relay => "relay",
            AddressKind::Unknown => "unknown",
        }
    }

    /// Whether this is one of the four registered tokens (i.e. not the `Unknown` catch-all).
    #[must_use]
    pub fn is_registered(self) -> bool {
        !matches!(self, AddressKind::Unknown)
    }
}

/// The advertiser's **provenance** for an entry (SPEC §3.1, §8.1) — how it knows the peer first-hand.
/// There is deliberately no `"pex"` token: an entry known only via PEX has no legitimate `via` to
/// claim, which is what stops re-gossip amplification (SPEC §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    /// Learned from a direct mTLS-verified connection to the peer.
    Direct,
    /// Learned from a relayed mTLS-verified connection to the peer.
    Relay,
    /// Learned from this participant's own introducer / relay registration surface.
    Introducer,
    /// An unrecognized token — the catch-all so an unknown `via` skips the entry (SPEC §3.3).
    /// Never emitted by a conformant sender.
    #[serde(other)]
    #[default]
    Unknown,
}

impl Provenance {
    /// The frozen lowercase wire token (or `"unknown"` for the catch-all).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::Direct => "direct",
            Provenance::Relay => "relay",
            Provenance::Introducer => "introducer",
            Provenance::Unknown => "unknown",
        }
    }

    /// Whether this is one of the three registered provenance tokens.
    #[must_use]
    pub fn is_registered(self) -> bool {
        !matches!(self, Provenance::Unknown)
    }
}

/// One candidate address for a peer: `{ host, port, kind }` (SPEC §3.1). Byte-compatible with the L7
/// `dig.getPeers` / DHT `Contact` address shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    /// IPv4/IPv6 literal or hostname. MUST be non-empty (SPEC §3.3).
    #[serde(default)]
    pub host: String,
    /// P2P port, 1–65535. A `port` of 0 skips the entry (SPEC §3.3).
    #[serde(default)]
    pub port: u16,
    /// How this address was learned.
    #[serde(default)]
    pub kind: AddressKind,
}

impl Address {
    /// A directly-dialable candidate (public / port-forwarded / discovered).
    #[must_use]
    pub fn direct(host: impl Into<String>, port: u16) -> Self {
        Address {
            host: host.into(),
            port,
            kind: AddressKind::Direct,
        }
    }

    /// A candidate of a specific [`AddressKind`].
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, kind: AddressKind) -> Self {
        Address {
            host: host.into(),
            port,
            kind,
        }
    }

    /// Whether this address is well-formed for a receiver (non-empty host, non-zero port, a
    /// registered `kind`) — SPEC §3.3.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.host.is_empty() && self.port != 0 && self.kind.is_registered()
    }
}

/// The unit of exchange — a peer entry (SPEC §3). Constructed via [`PeerEntry::new`] + the builder
/// methods for outgoing advertisements; decoded tolerantly for inbound validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    /// The advertised peer's mTLS identity, `<64hex>`.
    #[serde(default)]
    pub peer_id: String,
    /// Candidate addresses, most-direct-first. MAY be empty (reachable only via shared
    /// infrastructure, e.g. relay rendezvous by `peer_id`; see the `relay-only` flag).
    #[serde(default)]
    pub addresses: Vec<Address>,
    /// The network the peer belongs to. MUST equal the link's network.
    #[serde(default)]
    pub network_id: String,
    /// Unix seconds when the advertiser last had first-hand evidence of the peer (SPEC §8.2).
    #[serde(default)]
    pub last_seen: u64,
    /// The advertiser's provenance for this entry (SPEC §8.1).
    #[serde(default)]
    pub via: Provenance,
    /// Per-peer capability flags (SPEC §3.2). Optional; defaults to empty.
    #[serde(default)]
    pub flags: Vec<String>,
}

impl PeerEntry {
    /// A new entry for `peer_id` on `network_id`, last seen at `last_seen` (Unix seconds), with
    /// provenance `via`. Add addresses/flags with the builder methods.
    #[must_use]
    pub fn new(
        peer_id: impl Into<String>,
        network_id: impl Into<String>,
        last_seen: u64,
        via: Provenance,
    ) -> Self {
        PeerEntry {
            peer_id: peer_id.into(),
            addresses: Vec::new(),
            network_id: network_id.into(),
            last_seen,
            via,
            flags: Vec::new(),
        }
    }

    /// Builder: append a candidate address.
    #[must_use]
    pub fn with_address(mut self, addr: Address) -> Self {
        self.addresses.push(addr);
        self
    }

    /// Builder: append a capability flag token.
    #[must_use]
    pub fn with_flag(mut self, flag: impl Into<String>) -> Self {
        self.flags.push(flag.into());
        self
    }

    /// Validate this entry against the receiver's link context (SPEC §3.3). Returns the reason a
    /// conformant receiver skips it, or `Ok(())` to keep it. Skipping is silent — no strike.
    pub fn validate(&self, ctx: &ValidateCtx<'_>) -> Result<(), EntrySkip> {
        if !is_hex64(&self.peer_id) {
            return Err(EntrySkip::BadPeerId);
        }
        if self.peer_id == ctx.receiver_peer_id || self.peer_id == ctx.sender_peer_id {
            return Err(EntrySkip::SelfOrPartner);
        }
        if self.addresses.len() > PEX_MAX_ADDRESSES {
            return Err(EntrySkip::TooManyAddresses);
        }
        if self.addresses.iter().any(|a| !a.is_valid()) {
            return Err(EntrySkip::BadAddress);
        }
        if self.flags.len() > PEX_MAX_FLAGS || self.flags.iter().any(|f| f.len() > PEX_MAX_FLAG_LEN)
        {
            return Err(EntrySkip::TooManyFlags);
        }
        if self.network_id != ctx.network_id {
            return Err(EntrySkip::NetworkMismatch);
        }
        if !self.via.is_registered() {
            return Err(EntrySkip::BadVia);
        }
        // A `last_seen` in the future is clamped by the caller (see `clamped`); only an entry too far
        // in the PAST is skipped.
        if self.last_seen < ctx.now_secs && ctx.now_secs - self.last_seen > PEX_MAX_ENTRY_AGE {
            return Err(EntrySkip::TooOld);
        }
        Ok(())
    }

    /// A copy with a future `last_seen` clamped to `now_secs` (SPEC §3.3 — a receiver SHOULD clamp a
    /// `last_seen` in the future to its own clock).
    #[must_use]
    pub fn clamped(&self, now_secs: u64) -> PeerEntry {
        let mut e = self.clone();
        if e.last_seen > now_secs {
            e.last_seen = now_secs;
        }
        e
    }

    /// The per-link **advertised-content fingerprint** — a stable string over the addresses and flags
    /// **excluding `last_seen`** (SPEC §9.1), so heartbeat churn (a fresher `last_seen` alone) never
    /// re-advertises an unchanged peer. Two entries with the same fingerprint are "the same
    /// advertisement" for delta purposes.
    ///
    /// This allocates (a `Vec<String>` per call plus the final formatted `String`) and is intended
    /// for display/debugging/tests. The delta hot path uses the allocation-free
    /// [`fingerprint_hash`](Self::fingerprint_hash) instead (#179 MED optimization).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut addrs: Vec<String> = self
            .addresses
            .iter()
            .map(|a| format!("{}|{}|{}", a.host, a.port, a.kind.as_str()))
            .collect();
        addrs.sort();
        let mut flags = self.flags.clone();
        flags.sort();
        format!("{}#{}", addrs.join(","), flags.join(","))
    }

    /// The allocation-free equivalent of [`fingerprint`](Self::fingerprint): a 64-bit hash over the
    /// same canonical content (addresses + flags, sorted, **excluding `last_seen`**) with the same
    /// equality semantics — two entries with equal `fingerprint()` strings MUST have equal
    /// `fingerprint_hash()` values (and vice versa for practical purposes; a hash collision is
    /// possible but not a correctness concern for this delta-suppression use). Used as the `told`-map
    /// value (SPEC §9.1) so the per-tick, per-link delta comparison is a `Copy`, allocation-free `u64`
    /// equality check instead of building + sorting + formatting a `String` per advertisable entry
    /// per link per tick (#179 MED optimization).
    ///
    /// Sorts addresses/flags by **reference** (`Vec<&Address>` / `Vec<&str>`, no cloning) before
    /// feeding a stable field-separated byte stream to the hasher, so the result is independent of
    /// input order while never allocating an intermediate `String`.
    #[must_use]
    pub fn fingerprint_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut addrs: Vec<&Address> = self.addresses.iter().collect();
        addrs.sort_by(|a, b| {
            (a.host.as_str(), a.port, a.kind.as_str()).cmp(&(
                b.host.as_str(),
                b.port,
                b.kind.as_str(),
            ))
        });
        let mut flags: Vec<&str> = self.flags.iter().map(String::as_str).collect();
        flags.sort_unstable();

        // A fixed-seed hasher (not HashMap's randomized default) so the result is reproducible within
        // and across engine instances in the same process run — only ever compared in-memory, never
        // persisted or sent over the wire, so cross-process/version stability is not required.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        addrs.len().hash(&mut hasher);
        for a in &addrs {
            a.host.hash(&mut hasher);
            a.port.hash(&mut hasher);
            a.kind.as_str().hash(&mut hasher);
        }
        flags.len().hash(&mut hasher);
        for f in &flags {
            f.hash(&mut hasher);
        }
        hasher.finish()
    }
}

/// The receiver-side context an inbound entry is validated against (SPEC §3.3).
#[derive(Debug, Clone, Copy)]
pub struct ValidateCtx<'a> {
    /// The receiver's own `peer_id` — an entry advertising it is skipped (SPEC §5.4).
    pub receiver_peer_id: &'a str,
    /// The link partner's (sender's) `peer_id` — an entry advertising it is skipped (SPEC §5.4).
    pub sender_peer_id: &'a str,
    /// The link's network — an entry on a different `network_id` is skipped.
    pub network_id: &'a str,
    /// The receiver's current time in Unix seconds — for the freshness check.
    pub now_secs: u64,
}

/// Whether `s` is exactly 64 lowercase hexadecimal characters (`<64hex>`, SPEC §2).
#[must_use]
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: u8) -> String {
        format!("{b:02x}").repeat(32)
    }

    fn ctx<'a>(recv: &'a str, send: &'a str, net: &'a str, now: u64) -> ValidateCtx<'a> {
        ValidateCtx {
            receiver_peer_id: recv,
            sender_peer_id: send,
            network_id: net,
            now_secs: now,
        }
    }

    #[test]
    fn hex64_recognizer() {
        assert!(is_hex64(&"a".repeat(64)));
        assert!(is_hex64(&hex(0xab)));
        assert!(!is_hex64(&"a".repeat(63)));
        assert!(!is_hex64(&"A".repeat(64))); // uppercase not allowed
        assert!(!is_hex64(&"g".repeat(64))); // non-hex
    }

    #[test]
    fn kind_and_via_tokens_are_frozen_lowercase() {
        assert_eq!(
            serde_json::to_string(&AddressKind::Direct).unwrap(),
            "\"direct\""
        );
        assert_eq!(
            serde_json::to_string(&AddressKind::Relay).unwrap(),
            "\"relay\""
        );
        assert_eq!(
            serde_json::to_string(&Provenance::Introducer).unwrap(),
            "\"introducer\""
        );
    }

    #[test]
    fn unknown_kind_and_via_decode_to_catch_all() {
        let a: Address = serde_json::from_str(r#"{"host":"h","port":1,"kind":"quantum"}"#).unwrap();
        assert_eq!(a.kind, AddressKind::Unknown);
        let e: PeerEntry = serde_json::from_str(
            r#"{"peer_id":"x","addresses":[],"network_id":"n","last_seen":1,"via":"teleport"}"#,
        )
        .unwrap();
        assert_eq!(e.via, Provenance::Unknown);
    }

    #[test]
    fn valid_entry_passes() {
        let e = PeerEntry::new(hex(0x07), "mainnet", 1000, Provenance::Direct)
            .with_address(Address::direct("203.0.113.7", 9444))
            .with_flag("storage");
        assert!(e
            .validate(&ctx(&hex(0x01), &hex(0x02), "mainnet", 1000))
            .is_ok());
    }

    #[test]
    fn skip_reasons_match_spec() {
        let recv = hex(0x01);
        let send = hex(0x02);
        // bad peer_id
        let e = PeerEntry::new("nothex", "mainnet", 10, Provenance::Direct);
        assert_eq!(
            e.validate(&ctx(&recv, &send, "mainnet", 10)),
            Err(EntrySkip::BadPeerId)
        );
        // self / partner
        let e = PeerEntry::new(recv.clone(), "mainnet", 10, Provenance::Direct);
        assert_eq!(
            e.validate(&ctx(&recv, &send, "mainnet", 10)),
            Err(EntrySkip::SelfOrPartner)
        );
        let e = PeerEntry::new(send.clone(), "mainnet", 10, Provenance::Direct);
        assert_eq!(
            e.validate(&ctx(&recv, &send, "mainnet", 10)),
            Err(EntrySkip::SelfOrPartner)
        );
        // bad address (port 0)
        let e = PeerEntry::new(hex(0x07), "mainnet", 10, Provenance::Direct)
            .with_address(Address::new("h", 0, AddressKind::Direct));
        assert_eq!(
            e.validate(&ctx(&recv, &send, "mainnet", 10)),
            Err(EntrySkip::BadAddress)
        );
        // unknown kind
        let e = PeerEntry::new(hex(0x07), "mainnet", 10, Provenance::Direct)
            .with_address(Address::new("h", 1, AddressKind::Unknown));
        assert_eq!(
            e.validate(&ctx(&recv, &send, "mainnet", 10)),
            Err(EntrySkip::BadAddress)
        );
        // network mismatch
        let e = PeerEntry::new(hex(0x07), "testnet", 10, Provenance::Direct);
        assert_eq!(
            e.validate(&ctx(&recv, &send, "mainnet", 10)),
            Err(EntrySkip::NetworkMismatch)
        );
        // bad via
        let e = PeerEntry::new(hex(0x07), "mainnet", 10, Provenance::Unknown);
        assert_eq!(
            e.validate(&ctx(&recv, &send, "mainnet", 10)),
            Err(EntrySkip::BadVia)
        );
        // too old
        let e = PeerEntry::new(hex(0x07), "mainnet", 10, Provenance::Direct);
        assert_eq!(
            e.validate(&ctx(&recv, &send, "mainnet", 2000)),
            Err(EntrySkip::TooOld)
        );
    }

    #[test]
    fn too_many_addresses_and_flags() {
        let recv = hex(0x01);
        let send = hex(0x02);
        let mut e = PeerEntry::new(hex(0x07), "mainnet", 10, Provenance::Direct);
        for i in 0..9 {
            e = e.with_address(Address::direct("h", 1000 + i));
        }
        assert_eq!(
            e.validate(&ctx(&recv, &send, "mainnet", 10)),
            Err(EntrySkip::TooManyAddresses)
        );

        let mut e = PeerEntry::new(hex(0x07), "mainnet", 10, Provenance::Direct);
        for i in 0..9 {
            e = e.with_flag(format!("f{i}"));
        }
        assert_eq!(
            e.validate(&ctx(&recv, &send, "mainnet", 10)),
            Err(EntrySkip::TooManyFlags)
        );
    }

    #[test]
    fn future_last_seen_is_clamped_not_skipped() {
        let recv = hex(0x01);
        let send = hex(0x02);
        let e = PeerEntry::new(hex(0x07), "mainnet", 5000, Provenance::Direct);
        // now=1000, last_seen=5000 (future) — valid, and clamped to now.
        assert!(e.validate(&ctx(&recv, &send, "mainnet", 1000)).is_ok());
        assert_eq!(e.clamped(1000).last_seen, 1000);
        assert_eq!(e.clamped(6000).last_seen, 5000);
    }

    #[test]
    fn fingerprint_ignores_last_seen_but_tracks_addresses_and_flags() {
        let a = PeerEntry::new(hex(0x07), "mainnet", 100, Provenance::Direct)
            .with_address(Address::direct("h", 1))
            .with_flag("storage");
        let a2 = PeerEntry::new(hex(0x07), "mainnet", 999, Provenance::Direct)
            .with_address(Address::direct("h", 1))
            .with_flag("storage");
        assert_eq!(
            a.fingerprint(),
            a2.fingerprint(),
            "last_seen must not affect fingerprint"
        );
        let b = a2.clone().with_flag("holepunch");
        assert_ne!(
            a.fingerprint(),
            b.fingerprint(),
            "a flag change must change fingerprint"
        );
    }

    /// MEDIUM finding (#179): `fingerprint_hash()` is the allocation-free hot-path equality check
    /// used in the delta loop (`told` stores this hash, not the `String` fingerprint). It MUST agree
    /// with `fingerprint()`'s equality semantics: same addresses+flags (order-independent) and
    /// `last_seen`-independence hash equal; a real content change hashes different.
    #[test]
    fn fingerprint_hash_matches_fingerprint_equality_semantics() {
        let a = PeerEntry::new(hex(0x07), "mainnet", 100, Provenance::Direct)
            .with_address(Address::direct("h", 1))
            .with_flag("storage");
        let a2 = PeerEntry::new(hex(0x07), "mainnet", 999, Provenance::Direct)
            .with_address(Address::direct("h", 1))
            .with_flag("storage");
        assert_eq!(
            a.fingerprint_hash(),
            a2.fingerprint_hash(),
            "last_seen must not affect fingerprint_hash"
        );
        assert_eq!(
            a.fingerprint() == a2.fingerprint(),
            a.fingerprint_hash() == a2.fingerprint_hash(),
            "fingerprint_hash must agree with fingerprint on equality"
        );

        let b = a2.clone().with_flag("holepunch");
        assert_ne!(
            a.fingerprint_hash(),
            b.fingerprint_hash(),
            "a flag change must change fingerprint_hash"
        );
        assert_eq!(
            a.fingerprint() == b.fingerprint(),
            a.fingerprint_hash() == b.fingerprint_hash(),
            "fingerprint_hash must agree with fingerprint on inequality"
        );

        // Multiple addresses/flags supplied in a different insertion order must still hash equal
        // (the canonical form sorts both before hashing, same as `fingerprint()`).
        let c = PeerEntry::new(hex(0x08), "mainnet", 1, Provenance::Direct)
            .with_address(Address::direct("h1", 1))
            .with_address(Address::direct("h2", 2))
            .with_flag("storage")
            .with_flag("holepunch");
        let d = PeerEntry::new(hex(0x08), "mainnet", 2, Provenance::Direct)
            .with_address(Address::direct("h2", 2))
            .with_address(Address::direct("h1", 1))
            .with_flag("holepunch")
            .with_flag("storage");
        assert_eq!(
            c.fingerprint_hash(),
            d.fingerprint_hash(),
            "address/flag insertion order must not affect fingerprint_hash"
        );
        assert_eq!(c.fingerprint(), d.fingerprint());
    }

    #[test]
    fn entry_round_trips_through_json() {
        let e = PeerEntry::new(hex(0x07), "mainnet", 1_719_763_200, Provenance::Direct)
            .with_address(Address::direct("203.0.113.7", 9444))
            .with_flag("storage")
            .with_flag("holepunch");
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"peer_id\":"));
        assert!(json.contains("\"via\":\"direct\""));
        assert!(json.contains("\"kind\":\"direct\""));
        let back: PeerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}
