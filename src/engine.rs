//! The [`PexEngine`] — the transport-agnostic, sans-IO core both a DIG Node and the relay embed
//! (SPEC Appendix A).
//!
//! You feed the engine four kinds of input and it returns the messages to send + the events to act
//! on; it does no I/O itself (the node/relay do the actual dig-nat mux / WebSocket reads and writes):
//!
//! - **link events** — [`link_up`](PexEngine::link_up) (produces our outgoing handshake + snapshot)
//!   and [`link_down`](PexEngine::link_down) (discards all per-link state, SPEC §5.5);
//! - **inbound messages** — [`on_message`](PexEngine::on_message) validates + advances the receiver
//!   state machine, returning verified-candidate / dropped events and any `pex_error` replies, and
//!   penalizing misbehavior (SPEC §5, §6.4, §7, §11);
//! - **local peer-set changes** — [`upsert_known`](PexEngine::upsert_known) /
//!   [`remove_known`](PexEngine::remove_known) maintain the first-hand set PEX advertises (SPEC §9.3);
//! - **clock ticks** — [`tick`](PexEngine::tick) (~1/s) emits per-link `pex_delta`s for pending
//!   changes, spaced by the effective interval (SPEC §6).
//!
//! Timestamps are **Unix epoch milliseconds**. See [`crate`] docs for the node vs relay embedding.

use std::collections::HashMap;

use crate::caps::{
    PEX_MAX_ADDED, PEX_MAX_DROPPED, PEX_MAX_INTERVAL, PEX_MAX_SNAPSHOT, PEX_VERSION,
    PEX_VIOLATION_LIMIT,
};
use crate::entry::{PeerEntry, ValidateCtx};
use crate::error::PexErrorCode;
use crate::state::{LinkState, RecvPhase};
use crate::timer::{arrival_floor_ms, clamp_interval, effective_interval_secs, jitter_ms};
use crate::wire::PexMessage;

/// Configuration for a [`PexEngine`] (SPEC Appendix A).
#[derive(Debug, Clone)]
pub struct PexConfig {
    /// This participant's own transport identity (`peer_id`, `<64hex>`) — excluded from every
    /// advertisement and used to skip self-entries on receive (SPEC §5.4).
    pub local_peer_id: String,
    /// The network this participant serves — every handshake declares it and every entry MUST match
    /// it (SPEC §5.2, §7.3).
    pub network_id: String,
    /// This participant's own capability flags, sent in its handshake (SPEC §4.2). For the relay
    /// introducer this is `["introducer"]`.
    pub flags: Vec<String>,
    /// The declared send interval (seconds) — clamped into `[30, 3600]` (SPEC §6.2). Default `60`.
    pub interval: u32,
    /// Whether to add SPEC §6.3 send jitter. Default `true`; tests may disable it for deterministic
    /// scheduling (0% jitter is within the allowed `0..+10%`).
    pub jitter: bool,
}

impl PexConfig {
    /// A new config for `local_peer_id` on `network_id`, with the default 60 s interval, no flags,
    /// and jitter enabled.
    #[must_use]
    pub fn new(local_peer_id: impl Into<String>, network_id: impl Into<String>) -> Self {
        PexConfig {
            local_peer_id: local_peer_id.into(),
            network_id: network_id.into(),
            flags: Vec::new(),
            interval: crate::caps::PEX_DEFAULT_INTERVAL,
            jitter: true,
        }
    }

    /// Builder: set this participant's own capability flags.
    #[must_use]
    pub fn with_flags(mut self, flags: Vec<String>) -> Self {
        self.flags = flags;
        self
    }

    /// Builder: set the declared send interval (seconds), clamped into `[30, 3600]`.
    #[must_use]
    pub fn with_interval(mut self, secs: u32) -> Self {
        self.interval = clamp_interval(secs);
        self
    }

    /// Builder: enable/disable send jitter (SPEC §6.3).
    #[must_use]
    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }
}

/// An event the engine surfaces from an inbound message for the host to act on (SPEC Appendix A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PexEvent {
    /// Validated, verified-candidate peer hints — feed to the address manager as new-table
    /// candidates to dial + verify (SPEC §9.3). These are hints, never authenticated facts (§11.1).
    Candidates(Vec<PeerEntry>),
    /// The link's sender dropped these `peer_id`s (SPEC §8.3) — advisory. Unlist the sender as a
    /// source for them; never delete a first-hand-verified peer on this alone.
    Dropped {
        /// The dropped ids this link had previously told us (ids it never told us are ignored).
        peer_ids: Vec<String>,
    },
    /// The link's sender committed a violation (SPEC §11.2). `mute` is `true` once the direction is
    /// muted — either at the strike limit (misbehavior: `code` 1/3/4/6 → the host MAY penalize /
    /// disconnect) or immediately for a version/network mismatch (`code` 2/5 → benign; the host MUST
    /// NOT tear down the underlying connection for that alone, SPEC §5.2).
    Violation {
        /// The SPEC §4.5 error code.
        code: u16,
        /// Whether the incoming direction is now muted.
        mute: bool,
    },
}

/// The result of feeding the engine an inbound message or transport error: the messages to send back
/// on the link, plus the events for the host to act on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PexOutcome {
    /// Messages to write back on the link (e.g. a `pex_error`). Best-effort / advisory (SPEC §4.5).
    pub replies: Vec<PexMessage>,
    /// Events for the host (candidates / dropped / violation).
    pub events: Vec<PexEvent>,
}

/// A deduplicated inbound hint (SPEC §9.2) — the current best entry for a `peer_id` across all links.
#[derive(Debug, Clone)]
struct ReceivedHint {
    /// The link (`peer_id`) that is currently the source for this hint.
    source: String,
    /// The `last_seen` of the current hint — newer wins across senders.
    last_seen: u64,
}

/// The transport-agnostic PEX engine (SPEC Appendix A). One instance per participant; it multiplexes
/// all of that participant's links.
#[derive(Debug)]
pub struct PexEngine {
    cfg: PexConfig,
    /// The first-hand known-peer set PEX advertises, keyed by `peer_id` (SPEC §9.3 outbound).
    known: HashMap<String, PeerEntry>,
    /// Per-link state, keyed by the transport `peer_id`.
    links: HashMap<String, LinkState>,
    /// Global inbound dedup (SPEC §9.2): `peer_id → current best hint`.
    hints: HashMap<String, ReceivedHint>,
}

impl PexEngine {
    /// Create an engine from `cfg`.
    #[must_use]
    pub fn new(cfg: PexConfig) -> Self {
        PexEngine {
            cfg,
            known: HashMap::new(),
            links: HashMap::new(),
            hints: HashMap::new(),
        }
    }

    // ----- local first-hand set (SPEC §9.3 outbound) -----

    /// Add or update a **first-hand-known** peer in the advertise set (SPEC §8.1, §9.3). The caller
    /// supplies the honest `via` + a fresh `last_seen`; the [`Provenance`](crate::Provenance) type
    /// structurally forbids a `"pex"` provenance, so a PEX-learned entry can never be re-advertised
    /// unverified. The change surfaces as `added` in the next [`tick`](Self::tick) delta on each link.
    pub fn upsert_known(&mut self, entry: PeerEntry) {
        // Never advertise ourselves (the link is our own advertisement — SPEC §5.4).
        if entry.peer_id == self.cfg.local_peer_id {
            return;
        }
        self.known.insert(entry.peer_id.clone(), entry);
    }

    /// Remove a peer from the advertise set — it disconnected or went stale (SPEC §9.3). It surfaces
    /// as `dropped` in the next delta on links that were told it.
    pub fn remove_known(&mut self, peer_id: &str) {
        self.known.remove(peer_id);
    }

    // ----- link lifecycle (SPEC §5) -----

    /// A link came up: register it and produce our outgoing direction — the `pex_handshake` followed
    /// (back-to-back) by the `pex_snapshot` of our current first-hand set (SPEC §5.1, §6.1). Write
    /// the returned messages on our sending stream. Preserves any receiver-side state if the link
    /// already exists (e.g. an inbound message arrived first).
    pub fn link_up(&mut self, peer_id: &str, now_ms: u64) -> Vec<PexMessage> {
        let interval = self.cfg.interval;
        let handshake = PexMessage::PexHandshake {
            version: PEX_VERSION,
            network_id: self.cfg.network_id.clone(),
            interval,
            flags: self.cfg.flags.clone(),
        };

        // Build the snapshot from the current advertisable set (freshest-first, capped, self+partner
        // excluded) before mutating the link, so `known` isn't borrowed across the link mutation.
        let now_secs = now_ms / 1000;
        let mut peers = advertisable(&self.known, &self.cfg.local_peer_id, peer_id, now_secs);
        peers.truncate(PEX_MAX_SNAPSHOT);

        let remote_declared = self.links.get(peer_id).and_then(|l| l.remote_declared_secs);
        let jitter = self.draw_jitter(effective_interval_secs(interval, remote_declared));

        let link = self
            .links
            .entry(peer_id.to_string())
            .or_insert_with(|| LinkState::new(interval));
        link.self_interval_secs = interval;
        link.handshake_sent = true;
        for e in &peers {
            link.told.insert(e.peer_id.clone(), e.fingerprint());
        }
        link.snapshot_sent = true;
        link.last_data_send_ms = Some(now_ms);
        link.send_jitter_ms = jitter;

        vec![handshake, PexMessage::PexSnapshot { peers }]
    }

    /// A link went down: discard all per-link state, and unlist it as the source of any current hints
    /// (SPEC §5.5, §9.2). A new connection starts fresh.
    pub fn link_down(&mut self, peer_id: &str) {
        self.links.remove(peer_id);
        self.hints.retain(|_, h| h.source != peer_id);
    }

    // ----- inbound (SPEC §5.3, §6.4, §7, §11) -----

    /// Feed one decoded inbound message from `peer_id`. Returns replies to send + events to act on.
    /// A malformed *entry* inside a valid message is skipped silently; a malformed *message* /
    /// rate / oversize / state violation is discarded with a strike (SPEC §7.3, §11.2).
    pub fn on_message(&mut self, peer_id: &str, msg: PexMessage, now_ms: u64) -> PexOutcome {
        // Ensure a link exists (an inbound message may precede our own `link_up`).
        let interval = self.cfg.interval;
        let muted = {
            let link = self
                .links
                .entry(peer_id.to_string())
                .or_insert_with(|| LinkState::new(interval));
            link.muted
        };
        if muted {
            // Direction muted — ignore all further inbound PEX (SPEC §5.2, §11.2).
            return PexOutcome::default();
        }

        match msg {
            PexMessage::PexError { code, .. } => self.on_pex_error(peer_id, code),
            PexMessage::PexHandshake {
                version,
                network_id,
                interval: declared,
                ..
            } => self.on_handshake(peer_id, version, &network_id, declared),
            PexMessage::PexSnapshot { peers } => self.on_snapshot(peer_id, peers, now_ms),
            PexMessage::PexDelta { added, dropped } => {
                self.on_delta(peer_id, added, dropped, now_ms)
            }
        }
    }

    /// Record a transport-detected violation the engine could not see itself: a frame-size overrun
    /// (`Oversized`) or an undecodable/malformed frame (`BadMessage`) — SPEC §7.2, §7.3. Counts a
    /// strike and mutes at the limit, exactly like an engine-detected violation.
    pub fn record_violation(
        &mut self,
        peer_id: &str,
        code: PexErrorCode,
        _now_ms: u64,
    ) -> PexOutcome {
        let interval = self.cfg.interval;
        self.links
            .entry(peer_id.to_string())
            .or_insert_with(|| LinkState::new(interval));
        self.strike(peer_id, code)
    }

    // ----- clock (SPEC §6.1) -----

    /// Drive the send cadence (call ~1/s). For each link whose effective interval has elapsed since
    /// its last data message and that has pending changes, emits a `pex_delta` (SPEC §4.4, §6). A
    /// delta with no changes is suppressed (empty deltas are never sent). Returns `(peer_id,
    /// message)` pairs to write to the matching links.
    pub fn tick(&mut self, now_ms: u64) -> Vec<(String, PexMessage)> {
        let now_secs = now_ms / 1000;
        let mut out = Vec::new();
        // Snapshot the link keys to avoid borrowing `self.links` while mutating per-link below.
        let peer_ids: Vec<String> = self.links.keys().cloned().collect();
        for peer_id in peer_ids {
            let (eligible, effective) = {
                let link = &self.links[&peer_id];
                if !link.snapshot_sent {
                    continue; // we are receive-only on this link
                }
                let effective =
                    effective_interval_secs(link.self_interval_secs, link.remote_declared_secs);
                let base = link.last_data_send_ms.unwrap_or(0);
                let eligible = now_ms >= base + u64::from(effective) * 1000 + link.send_jitter_ms;
                (eligible, effective)
            };
            if !eligible {
                continue;
            }

            let (added, dropped) = self.build_delta(&peer_id, now_secs);
            if added.is_empty() && dropped.is_empty() {
                continue; // suppress empty deltas (SPEC §4.4)
            }

            // Commit the told-state for exactly what we send (SPEC §9.1); the capped remainder recurs.
            let link = self.links.get_mut(&peer_id).expect("link exists");
            for e in &added {
                link.told.insert(e.peer_id.clone(), e.fingerprint());
            }
            for id in &dropped {
                link.told.remove(id);
            }
            link.last_data_send_ms = Some(now_ms);
            let jitter = self.draw_jitter(effective);
            self.links
                .get_mut(&peer_id)
                .expect("link exists")
                .send_jitter_ms = jitter;

            out.push((peer_id, PexMessage::PexDelta { added, dropped }));
        }
        out
    }

    // ----- read-only accessors (observability / tests) -----

    /// Number of peers in the first-hand advertise set.
    #[must_use]
    pub fn known_count(&self) -> usize {
        self.known.len()
    }

    /// Number of live links.
    #[must_use]
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Whether the incoming direction of `peer_id`'s link is muted (SPEC §5.2, §11.2).
    #[must_use]
    pub fn is_muted(&self, peer_id: &str) -> bool {
        self.links.get(peer_id).is_some_and(|l| l.muted)
    }

    /// The violation strike count on `peer_id`'s incoming direction (SPEC §11.2).
    #[must_use]
    pub fn strikes(&self, peer_id: &str) -> u32 {
        self.links.get(peer_id).map_or(0, |l| l.strikes)
    }

    /// How many peer ids we have currently told `peer_id`'s link (told-state size, SPEC §9.1).
    #[must_use]
    pub fn told_count(&self, peer_id: &str) -> usize {
        self.links.get(peer_id).map_or(0, |l| l.told.len())
    }

    /// The current deduplicated hint for `peer_id` (SPEC §9.2): `(source link, last_seen)`, if any.
    #[must_use]
    pub fn current_hint(&self, peer_id: &str) -> Option<(&str, u64)> {
        self.hints
            .get(peer_id)
            .map(|h| (h.source.as_str(), h.last_seen))
    }

    // ----- internals -----

    fn draw_jitter(&self, effective_secs: u32) -> u64 {
        if self.cfg.jitter {
            jitter_ms(effective_secs)
        } else {
            0
        }
    }

    /// `pex_error` is acceptable in any state and never changes the receiver state (SPEC §5.3). A
    /// sender receiving code `3` SHOULD back off — double its effective interval, capped (SPEC §6.4).
    fn on_pex_error(&mut self, peer_id: &str, code: u16) -> PexOutcome {
        if code == PexErrorCode::RateViolation.as_u16() {
            if let Some(link) = self.links.get_mut(peer_id) {
                link.self_interval_secs = clamp_interval(
                    (link.self_interval_secs.saturating_mul(2)).min(PEX_MAX_INTERVAL),
                );
            }
        }
        PexOutcome::default()
    }

    fn on_handshake(
        &mut self,
        peer_id: &str,
        version: u32,
        network_id: &str,
        declared: u32,
    ) -> PexOutcome {
        let phase = self.links[peer_id].phase;
        if phase != RecvPhase::AwaitingHandshake {
            // A repeat handshake once past the handshake state is a protocol violation (SPEC §5.3).
            return self.strike(peer_id, PexErrorCode::ProtocolViolation);
        }
        if version != PEX_VERSION {
            return self.mute_mismatch(peer_id, PexErrorCode::UnsupportedVersion);
        }
        if network_id != self.cfg.network_id {
            return self.mute_mismatch(peer_id, PexErrorCode::NetworkMismatch);
        }
        let link = self.links.get_mut(peer_id).expect("link exists");
        link.remote_declared_secs = Some(clamp_interval(declared));
        link.phase = RecvPhase::AwaitingSnapshot;
        PexOutcome::default()
    }

    fn on_snapshot(&mut self, peer_id: &str, peers: Vec<PeerEntry>, now_ms: u64) -> PexOutcome {
        match self.links[peer_id].phase {
            RecvPhase::AwaitingHandshake => self.strike(peer_id, PexErrorCode::ProtocolViolation),
            RecvPhase::Streaming => self.strike(peer_id, PexErrorCode::ProtocolViolation),
            RecvPhase::AwaitingSnapshot => {
                if peers.len() > PEX_MAX_SNAPSHOT {
                    return self.strike(peer_id, PexErrorCode::Oversized);
                }
                let link = self.links.get_mut(peer_id).expect("link exists");
                link.phase = RecvPhase::Streaming;
                link.last_arrival_ms = Some(now_ms); // the snapshot starts the arrival clock
                self.ingest_added(peer_id, peers, now_ms)
            }
        }
    }

    fn on_delta(
        &mut self,
        peer_id: &str,
        added: Vec<PeerEntry>,
        dropped: Vec<String>,
        now_ms: u64,
    ) -> PexOutcome {
        match self.links[peer_id].phase {
            RecvPhase::AwaitingHandshake | RecvPhase::AwaitingSnapshot => {
                // Data before handshake, or a delta before the snapshot (SPEC §5.3).
                return self.strike(peer_id, PexErrorCode::ProtocolViolation);
            }
            RecvPhase::Streaming => {}
        }

        // Rate enforcement (SPEC §6.4): a delta arriving under the floor is discarded + struck.
        let (floor, last) = {
            let link = &self.links[peer_id];
            (
                arrival_floor_ms(link.remote_declared_secs.unwrap_or(0)),
                link.last_arrival_ms,
            )
        };
        if let Some(last) = last {
            if now_ms.saturating_sub(last) < floor {
                return self.strike(peer_id, PexErrorCode::RateViolation);
            }
        }

        // List caps: reject the whole message, never truncate (SPEC §7.2).
        if added.len() > PEX_MAX_ADDED || dropped.len() > PEX_MAX_DROPPED {
            return self.strike(peer_id, PexErrorCode::Oversized);
        }
        // Structural MUST: a peer_id may not appear in both `added` and `dropped` (SPEC §4.4).
        let added_ids: std::collections::HashSet<&str> =
            added.iter().map(|e| e.peer_id.as_str()).collect();
        if dropped.iter().any(|d| added_ids.contains(d.as_str())) {
            return self.strike(peer_id, PexErrorCode::BadMessage);
        }

        self.links
            .get_mut(peer_id)
            .expect("link exists")
            .last_arrival_ms = Some(now_ms);

        let mut outcome = self.ingest_added(peer_id, added, now_ms);
        outcome
            .events
            .extend(self.ingest_dropped(peer_id, dropped).events);
        outcome
    }

    /// Validate + dedup a batch of inbound entries into `Candidates` (SPEC §3.3, §9.2). Malformed
    /// entries are skipped silently.
    fn ingest_added(&mut self, peer_id: &str, entries: Vec<PeerEntry>, now_ms: u64) -> PexOutcome {
        let now_secs = now_ms / 1000;
        let mut candidates = Vec::new();
        for e in entries {
            let ctx = ValidateCtx {
                receiver_peer_id: &self.cfg.local_peer_id,
                sender_peer_id: peer_id,
                network_id: &self.cfg.network_id,
                now_secs,
            };
            if e.validate(&ctx).is_err() {
                continue; // malformed entry — skip silently (SPEC §3.3, §7.3)
            }
            let ce = e.clamped(now_secs);
            // Attribute the hint to this link so a later `dropped` can be matched (SPEC §8.3).
            self.links
                .get_mut(peer_id)
                .expect("link exists")
                .received
                .insert(ce.peer_id.clone(), ce.last_seen);
            // Dedup: newest `last_seen` wins as the current hint (SPEC §9.2); only surface an entry
            // that is new or fresher than what we already hold, to avoid re-dialing stale duplicates.
            let fresher = match self.hints.get(&ce.peer_id) {
                Some(h) => ce.last_seen > h.last_seen,
                None => true,
            };
            if fresher {
                self.hints.insert(
                    ce.peer_id.clone(),
                    ReceivedHint {
                        source: peer_id.to_string(),
                        last_seen: ce.last_seen,
                    },
                );
                candidates.push(ce);
            }
        }
        let mut outcome = PexOutcome::default();
        if !candidates.is_empty() {
            outcome.events.push(PexEvent::Candidates(candidates));
        }
        outcome
    }

    /// Attribute `dropped` ids: only those this link previously told us are acted on (SPEC §4.4,
    /// §8.3). If a dropped id's current hint was sourced from this link, clear it (unlist the source).
    fn ingest_dropped(&mut self, peer_id: &str, dropped: Vec<String>) -> PexOutcome {
        let mut attributed = Vec::new();
        for id in dropped {
            let told_us = self
                .links
                .get_mut(peer_id)
                .expect("link exists")
                .received
                .remove(&id)
                .is_some();
            if told_us {
                if let Some(h) = self.hints.get(&id) {
                    if h.source == peer_id {
                        self.hints.remove(&id);
                    }
                }
                attributed.push(id);
            }
        }
        let mut outcome = PexOutcome::default();
        if !attributed.is_empty() {
            outcome.events.push(PexEvent::Dropped {
                peer_ids: attributed,
            });
        }
        outcome
    }

    /// Count a misbehavior strike (SPEC §11.2): discard the message, reply `pex_error` (advisory),
    /// mute at the limit, and surface a `Violation` event. Version/network mismatch use
    /// [`mute_mismatch`](Self::mute_mismatch) instead (immediate, non-strike mute).
    fn strike(&mut self, peer_id: &str, code: PexErrorCode) -> PexOutcome {
        let link = self.links.get_mut(peer_id).expect("link exists");
        link.strikes += 1;
        let mute = link.strikes >= PEX_VIOLATION_LIMIT;
        if mute {
            link.muted = true;
        }
        PexOutcome {
            replies: vec![PexMessage::PexError {
                code: code.as_u16(),
                message: code.message().to_string(),
            }],
            events: vec![PexEvent::Violation {
                code: code.as_u16(),
                mute,
            }],
        }
    }

    /// Immediately mute the direction for a version/network mismatch (SPEC §5.2). This is NOT a
    /// strike (the peer is simply on a different version/network) and MUST NOT tear down the
    /// underlying connection — PEX is an optional overlay.
    fn mute_mismatch(&mut self, peer_id: &str, code: PexErrorCode) -> PexOutcome {
        self.links.get_mut(peer_id).expect("link exists").muted = true;
        PexOutcome {
            replies: vec![PexMessage::PexError {
                code: code.as_u16(),
                message: code.message().to_string(),
            }],
            events: vec![PexEvent::Violation {
                code: code.as_u16(),
                mute: true,
            }],
        }
    }
}

/// The advertisable subset of `known` for a link to `partner` at `now_secs`: self + partner excluded
/// (SPEC §5.4), stale entries dropped (SPEC §8.2), sorted **freshest-first** then by `peer_id` for a
/// deterministic order (SPEC §4.3, §9.1).
fn advertisable(
    known: &HashMap<String, PeerEntry>,
    local_peer_id: &str,
    partner: &str,
    now_secs: u64,
) -> Vec<PeerEntry> {
    let mut out: Vec<PeerEntry> = known
        .values()
        .filter(|e| e.peer_id != local_peer_id && e.peer_id != partner)
        .filter(|e| {
            // Not stale: within PEX_MAX_ENTRY_AGE (a future last_seen is treated as fresh).
            e.last_seen >= now_secs || now_secs - e.last_seen <= crate::caps::PEX_MAX_ENTRY_AGE
        })
        .cloned()
        .collect();
    out.sort_by(|a, b| {
        b.last_seen
            .cmp(&a.last_seen)
            .then_with(|| a.peer_id.cmp(&b.peer_id))
    });
    out
}

impl PexEngine {
    /// Compute the delta for a link relative to its told-state (SPEC §9.1): `added` = advertisable
    /// entries not yet told (or told with a changed fingerprint), freshest-first, capped at
    /// [`PEX_MAX_ADDED`]; `dropped` = told ids no longer advertisable, capped at [`PEX_MAX_DROPPED`].
    fn build_delta(&self, peer_id: &str, now_secs: u64) -> (Vec<PeerEntry>, Vec<String>) {
        let link = &self.links[peer_id];
        let advert = advertisable(&self.known, &self.cfg.local_peer_id, peer_id, now_secs);

        let mut added = Vec::new();
        for e in &advert {
            if added.len() >= PEX_MAX_ADDED {
                break;
            }
            match link.told.get(&e.peer_id) {
                Some(fp) if *fp == e.fingerprint() => {} // unchanged — never re-advertise (SPEC §9.1)
                _ => added.push(e.clone()),
            }
        }

        let advert_ids: std::collections::HashSet<&str> =
            advert.iter().map(|e| e.peer_id.as_str()).collect();
        let mut dropped = Vec::new();
        for id in link.told.keys() {
            if dropped.len() >= PEX_MAX_DROPPED {
                break;
            }
            if !advert_ids.contains(id.as_str()) {
                dropped.push(id.clone());
            }
        }
        dropped.sort(); // deterministic order

        (added, dropped)
    }
}
