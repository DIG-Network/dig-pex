//! The frozen version-1 protocol constants and the message-level cap checks (SPEC §7.1, §7.2).
//!
//! These are the **wire contract** — an implementation is conformant only if it enforces exactly
//! these values. Senders MUST never exceed the list caps; receivers MUST reject (never truncate) an
//! over-cap message with a violation strike. The [`PexEngine`](crate::PexEngine) enforces both
//! directions: it caps its own outgoing messages, and it rejects over-cap inbound ones.

/// The PEX wire version this crate implements (SPEC §7.1).
pub const PEX_VERSION: u32 = 1;

/// Maximum entries in a `pex_delta.added` list.
pub const PEX_MAX_ADDED: usize = 50;

/// Maximum ids in a `pex_delta.dropped` list.
pub const PEX_MAX_DROPPED: usize = 50;

/// Maximum entries in a `pex_snapshot.peers` list.
pub const PEX_MAX_SNAPSHOT: usize = 200;

/// Maximum `addresses` per peer entry.
pub const PEX_MAX_ADDRESSES: usize = 8;

/// Maximum `flags` per peer entry (and per handshake).
pub const PEX_MAX_FLAGS: usize = 8;

/// Maximum characters per flag token.
pub const PEX_MAX_FLAG_LEN: usize = 32;

/// Maximum message body bytes (256 KiB) — matches the DHT / dig-nat wire bound. A frame claiming a
/// larger body MUST be rejected before allocating or reading the body (SPEC §4.1, §7.2).
pub const PEX_MAX_FRAME: usize = 262_144;

/// Default declared send interval, in seconds (SPEC §6.2).
pub const PEX_DEFAULT_INTERVAL: u32 = 60;

/// Hard interval floor, in seconds — a sender MUST NOT declare (nor be enforced) below this.
pub const PEX_MIN_INTERVAL: u32 = 30;

/// Interval ceiling for declarations, in seconds.
pub const PEX_MAX_INTERVAL: u32 = 3600;

/// The receiver's enforcement tolerance, in seconds — absorbs scheduling + clock skew (SPEC §6.4).
pub const PEX_ARRIVAL_GRACE: u32 = 5;

/// Maximum `last_seen` age (seconds) an entry may be advertised with; older entries are not
/// advertised (sender) and skipped on receive (SPEC §3.3, §8.2).
pub const PEX_MAX_ENTRY_AGE: u64 = 1800;

/// Strikes on a direction before it is muted / the peer may be disconnected (SPEC §7.1, §11.2).
pub const PEX_VIOLATION_LIMIT: u32 = 3;

/// Whether a frame body of `len` bytes is within [`PEX_MAX_FRAME`]. A caller MUST check this
/// **before** allocating or reading the body (the stream binding checks the length prefix; the relay
/// binding checks the WebSocket payload length).
#[must_use]
pub fn frame_within_bound(len: usize) -> bool {
    len <= PEX_MAX_FRAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_v1_constants() {
        // These values are the wire contract (SPEC §7.1) — pinned so a change is a deliberate,
        // reviewed protocol event, never an accident.
        assert_eq!(PEX_VERSION, 1);
        assert_eq!(PEX_MAX_ADDED, 50);
        assert_eq!(PEX_MAX_DROPPED, 50);
        assert_eq!(PEX_MAX_SNAPSHOT, 200);
        assert_eq!(PEX_MAX_ADDRESSES, 8);
        assert_eq!(PEX_MAX_FLAGS, 8);
        assert_eq!(PEX_MAX_FLAG_LEN, 32);
        assert_eq!(PEX_MAX_FRAME, 262_144);
        assert_eq!(PEX_DEFAULT_INTERVAL, 60);
        assert_eq!(PEX_MIN_INTERVAL, 30);
        assert_eq!(PEX_MAX_INTERVAL, 3600);
        assert_eq!(PEX_ARRIVAL_GRACE, 5);
        assert_eq!(PEX_MAX_ENTRY_AGE, 1800);
        assert_eq!(PEX_VIOLATION_LIMIT, 3);
    }

    #[test]
    fn frame_bound_edges() {
        assert!(frame_within_bound(0));
        assert!(frame_within_bound(PEX_MAX_FRAME));
        assert!(!frame_within_bound(PEX_MAX_FRAME + 1));
    }
}
