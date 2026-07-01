//! Per-link, per-direction PEX state (SPEC §5, §9).
//!
//! PEX on a link is two independent half-conversations (SPEC §5.1). [`LinkState`] holds both for one
//! link, keyed in the engine by the transport `peer_id` (never a wire field — SPEC §5.4, §10):
//!
//! - the **sender** (outgoing) direction — whether we've sent our handshake + snapshot, the per-link
//!   *told-state* ("what I've told you", SPEC §9.1: `peer_id → advertised-content fingerprint`), the
//!   send-cadence bookkeeping, and our own (possibly backed-off) declared interval;
//! - the **receiver** (incoming) direction — the [`RecvPhase`] state machine, the remote's declared
//!   interval, the last data-message arrival time (for the SPEC §6.4 floor), the strike count + mute
//!   flag, and the set of `peer_id`s this link has told us (for `dropped` attribution, SPEC §8.3).
//!
//! All of this dies with the link (SPEC §5.5): a fresh connection restarts from
//! [`RecvPhase::AwaitingHandshake`] with an empty told-state.

use std::collections::HashMap;

use crate::caps::PEX_DEFAULT_INTERVAL;

/// The receiver-side state machine for one direction (SPEC §5.3).
///
/// ```text
///   AwaitingHandshake --handshake(ok)--> AwaitingSnapshot --snapshot--> Streaming
/// ```
///
/// A data message before the handshake, a delta before the snapshot, or a second snapshot is a
/// protocol violation (code `6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvPhase {
    /// No valid handshake seen yet — the only acceptable inbound message is `pex_handshake`.
    AwaitingHandshake,
    /// Handshake accepted; awaiting the single `pex_snapshot` that opens the data stream.
    AwaitingSnapshot,
    /// Snapshot seen; `pex_delta`s flow (subject to the SPEC §6.4 arrival floor).
    Streaming,
}

/// All PEX state for one link (both directions). Created on `link_up` / first inbound message and
/// discarded on `link_down` (SPEC §5.5).
#[derive(Debug, Clone)]
pub struct LinkState {
    // ---- sender (outgoing) direction ----
    /// Whether we have sent our `pex_handshake` on this link.
    pub handshake_sent: bool,
    /// Whether we have sent our one `pex_snapshot` on this link.
    pub snapshot_sent: bool,
    /// Per-link told-state (SPEC §9.1): `peer_id → advertised-content fingerprint`. Deltas are
    /// computed relative to this; an unchanged told entry is never re-advertised.
    pub told: HashMap<String, String>,
    /// When we last sent a **data message** (snapshot or delta) on this link, in `now_ms`. `None`
    /// until the snapshot goes out; the cadence spaces subsequent sends from here (SPEC §6.1).
    pub last_data_send_ms: Option<u64>,
    /// The additive jitter (ms) drawn for the *current* schedule interval (SPEC §6.3).
    pub send_jitter_ms: u64,
    /// Our own declared interval (seconds) for this link — starts at the configured value and MAY
    /// double on receiving `pex_error` code `3` (SPEC §6.4), capped at `PEX_MAX_INTERVAL`.
    pub self_interval_secs: u32,

    // ---- receiver (incoming) direction ----
    /// The inbound state machine (SPEC §5.3).
    pub phase: RecvPhase,
    /// The remote's handshake-declared interval (seconds), once its handshake arrived. Used as the
    /// arrival-floor basis (SPEC §6.4) and as a spacing floor for our own sends (SPEC §6.2).
    pub remote_declared_secs: Option<u32>,
    /// When the last inbound **data message** arrived, in `now_ms` — the SPEC §6.4 clock.
    pub last_arrival_ms: Option<u64>,
    /// Violation strikes counted on the incoming direction (SPEC §11.2).
    pub strikes: u32,
    /// Whether the incoming direction is muted (all further inbound PEX ignored) — SPEC §5.2, §11.2.
    pub muted: bool,
    /// `peer_id`s this link has told us (via snapshot / delta `added`) — so a later `dropped` can be
    /// attributed to it and ignored for ids it never told us (SPEC §4.4, §8.3).
    pub received: HashMap<String, u64>,
}

impl LinkState {
    /// A fresh link: both directions at their start state, no told/received history.
    #[must_use]
    pub fn new(self_interval_secs: u32) -> Self {
        LinkState {
            handshake_sent: false,
            snapshot_sent: false,
            told: HashMap::new(),
            last_data_send_ms: None,
            send_jitter_ms: 0,
            self_interval_secs,
            phase: RecvPhase::AwaitingHandshake,
            remote_declared_secs: None,
            last_arrival_ms: None,
            strikes: 0,
            muted: false,
            received: HashMap::new(),
        }
    }
}

impl Default for LinkState {
    fn default() -> Self {
        LinkState::new(PEX_DEFAULT_INTERVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_link_starts_awaiting_handshake() {
        let l = LinkState::new(60);
        assert_eq!(l.phase, RecvPhase::AwaitingHandshake);
        assert!(!l.handshake_sent);
        assert!(!l.snapshot_sent);
        assert!(!l.muted);
        assert_eq!(l.strikes, 0);
        assert!(l.told.is_empty());
        assert!(l.received.is_empty());
        assert_eq!(l.self_interval_secs, 60);
    }

    #[test]
    fn default_uses_default_interval() {
        assert_eq!(
            LinkState::default().self_interval_secs,
            PEX_DEFAULT_INTERVAL
        );
    }
}
