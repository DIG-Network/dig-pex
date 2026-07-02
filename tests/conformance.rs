//! End-to-end conformance tests pinning the SPEC §12 conformance table (PEX-01..PEX-14).
//!
//! Everything runs over IN-MEMORY links — two [`PexEngine`]s pumped against each other, or an engine
//! driven directly — with NO real network. Each test names the conformance id(s) it guards.

use dig_pex::{
    Address, AddressKind, PeerEntry, PexConfig, PexEngine, PexErrorCode, PexEvent, PexMessage,
    Provenance, PEX_MAX_ADDED, PEX_MAX_SNAPSHOT, PEX_VERSION,
};

fn hex(b: u8) -> String {
    format!("{b:02x}").repeat(32)
}

/// A valid entry for peer `id` on `net`, seen at `last_seen`, reachable at one direct address.
fn entry(id: &str, net: &str, last_seen: u64) -> PeerEntry {
    PeerEntry::new(
        id.to_string(),
        net.to_string(),
        last_seen,
        Provenance::Direct,
    )
    .with_address(Address::direct("203.0.113.7", 9444))
    .with_flag("storage")
}

fn engine(local: &str, net: &str) -> PexEngine {
    PexEngine::new(PexConfig::new(local.to_string(), net.to_string()).with_jitter(false))
}

/// Deliver an inbound handshake for `sender` into `eng`, transitioning its receiver to
/// `AwaitingSnapshot`.
fn deliver_handshake(eng: &mut PexEngine, sender: &str, net: &str, interval: u32) {
    let out = eng.on_message(
        sender,
        PexMessage::PexHandshake {
            version: PEX_VERSION,
            network_id: net.to_string(),
            interval,
            flags: vec![],
        },
        1_000_000,
    );
    assert!(out.events.is_empty(), "a good handshake yields no events");
}

// ---------------------------------------------------------------------------------------------
// PEX-05 — handshake precedes everything; snapshot is the first data message, exactly once.
// ---------------------------------------------------------------------------------------------

#[test]
fn link_up_emits_handshake_then_snapshot() {
    let mut a = engine(&hex(0x0a), "mainnet");
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000));
    let out = a.link_up(&hex(0x0b), 1_000_000);
    assert_eq!(out.len(), 2);
    assert!(matches!(out[0], PexMessage::PexHandshake { version, .. } if version == PEX_VERSION));
    match &out[1] {
        PexMessage::PexSnapshot { peers } => {
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].peer_id, hex(0x0c));
        }
        other => panic!("expected snapshot, got {other:?}"),
    }
}

#[test]
fn data_before_handshake_is_protocol_violation() {
    let mut b = engine(&hex(0x0b), "mainnet");
    // A snapshot arriving before any handshake — code 6.
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexSnapshot { peers: vec![] },
        1_000_000,
    );
    assert_eq!(
        out.events,
        vec![PexEvent::Violation {
            code: PexErrorCode::ProtocolViolation.as_u16(),
            mute: false
        }]
    );
    assert!(matches!(
        out.replies[0],
        PexMessage::PexError { code: 6, .. }
    ));
}

#[test]
fn delta_before_snapshot_is_protocol_violation() {
    let mut b = engine(&hex(0x0b), "mainnet");
    deliver_handshake(&mut b, &hex(0x0a), "mainnet", 60);
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexDelta {
            added: vec![],
            dropped: vec![],
        },
        1_000_000,
    );
    assert!(matches!(
        out.replies[0],
        PexMessage::PexError { code: 6, .. }
    ));
}

#[test]
fn second_snapshot_is_protocol_violation() {
    let mut b = engine(&hex(0x0b), "mainnet");
    deliver_handshake(&mut b, &hex(0x0a), "mainnet", 60);
    let ok = b.on_message(
        &hex(0x0a),
        PexMessage::PexSnapshot { peers: vec![] },
        1_000_000,
    );
    assert!(ok.replies.is_empty());
    let bad = b.on_message(
        &hex(0x0a),
        PexMessage::PexSnapshot { peers: vec![] },
        1_000_000,
    );
    assert!(matches!(
        bad.replies[0],
        PexMessage::PexError { code: 6, .. }
    ));
}

// ---------------------------------------------------------------------------------------------
// PEX-11 — self and the link partner are never advertised to that link.
// ---------------------------------------------------------------------------------------------

#[test]
fn snapshot_excludes_self_and_partner() {
    let me = hex(0x0a);
    let partner = hex(0x0b);
    let mut a = engine(&me, "mainnet");
    a.upsert_known(entry(&me, "mainnet", 1000)); // self — ignored by upsert
    a.upsert_known(entry(&partner, "mainnet", 1000)); // partner — excluded from this link
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000)); // a third peer — advertised
    let out = a.link_up(&partner, 1_000_000);
    match &out[1] {
        PexMessage::PexSnapshot { peers } => {
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].peer_id, hex(0x0c));
        }
        other => panic!("expected snapshot, got {other:?}"),
    }
    assert_eq!(
        a.known_count(),
        2,
        "self is never stored in the advertise set"
    );
}

// ---------------------------------------------------------------------------------------------
// PEX-07 — empty deltas never sent; unchanged told entries never re-advertised; told-state resets.
// ---------------------------------------------------------------------------------------------

#[test]
fn delta_carries_only_changes_added_then_dropped() {
    let mut a = engine(&hex(0x0a), "mainnet");
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000));
    a.link_up(&hex(0x0b), 1_000_000); // snapshot tells 0x0c

    // Nothing changed → tick after the interval produces no delta.
    assert!(a.tick(1_070_000).is_empty(), "no change → no delta");

    // A new first-hand peer appears → next tick advertises exactly it.
    a.upsert_known(entry(&hex(0x0d), "mainnet", 1070));
    let out = a.tick(1_070_000);
    assert_eq!(out.len(), 1);
    match &out[0].1 {
        PexMessage::PexDelta { added, dropped } => {
            assert_eq!(added.len(), 1);
            assert_eq!(added[0].peer_id, hex(0x0d));
            assert!(dropped.is_empty());
        }
        other => panic!("expected delta, got {other:?}"),
    }

    // Remove the original → next tick drops it (advisory dropped id).
    a.remove_known(&hex(0x0c));
    let out = a.tick(1_140_000);
    assert_eq!(out.len(), 1);
    match &out[0].1 {
        PexMessage::PexDelta { added, dropped } => {
            assert!(added.is_empty());
            assert_eq!(dropped, &vec![hex(0x0c)]);
        }
        other => panic!("expected delta, got {other:?}"),
    }
}

#[test]
fn unchanged_entry_is_not_readvertised_on_heartbeat_churn() {
    let mut a = engine(&hex(0x0a), "mainnet");
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000));
    a.link_up(&hex(0x0b), 1_000_000);
    // Same addresses+flags, only a fresher last_seen (a heartbeat) → fingerprint unchanged.
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1069));
    assert!(
        a.tick(1_070_000).is_empty(),
        "a last_seen-only change must not re-advertise (SPEC §9.1)"
    );
}

#[test]
fn told_state_resets_with_the_link() {
    let mut a = engine(&hex(0x0a), "mainnet");
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000));
    a.link_up(&hex(0x0b), 1_000_000);
    assert_eq!(a.told_count(&hex(0x0b)), 1);
    a.link_down(&hex(0x0b));
    assert_eq!(a.link_count(), 0);
    // A fresh link re-sends a full snapshot (told-state started empty again).
    let out = a.link_up(&hex(0x0b), 2_000_000);
    match &out[1] {
        PexMessage::PexSnapshot { peers } => assert_eq!(peers.len(), 1),
        other => panic!("expected snapshot, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// PEX-08 — only first-hand peers advertised; stale entries not advertised; no "pex" provenance.
// ---------------------------------------------------------------------------------------------

#[test]
fn stale_entries_are_not_advertised() {
    let mut a = engine(&hex(0x0a), "mainnet");
    // now_secs at link_up = 5000; entry last_seen 1000 → age 4000 s > PEX_MAX_ENTRY_AGE (1800).
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000));
    let out = a.link_up(&hex(0x0b), 5_000_000);
    match &out[1] {
        PexMessage::PexSnapshot { peers } => assert!(peers.is_empty(), "stale peer not advertised"),
        other => panic!("expected snapshot, got {other:?}"),
    }
}

#[test]
fn provenance_has_no_pex_token() {
    // The type system forbids re-advertising a PEX-learned entry: there is no `Provenance::Pex`.
    for p in [
        Provenance::Direct,
        Provenance::Relay,
        Provenance::Introducer,
    ] {
        assert!(p.is_registered());
    }
    assert!(!Provenance::Unknown.is_registered());
    // The three registered wire tokens are exactly these.
    assert_eq!(Provenance::Direct.as_str(), "direct");
    assert_eq!(Provenance::Relay.as_str(), "relay");
    assert_eq!(Provenance::Introducer.as_str(), "introducer");
}

// ---------------------------------------------------------------------------------------------
// PEX-06 — sender spacing >= effective interval; receiver discards + strikes under the floor.
// ---------------------------------------------------------------------------------------------

#[test]
fn sender_spaces_data_messages_by_the_effective_interval() {
    let mut a = engine(&hex(0x0a), "mainnet");
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000));
    a.link_up(&hex(0x0b), 1_000_000); // snapshot at t0; effective = 60 s
    a.upsert_known(entry(&hex(0x0d), "mainnet", 1000));
    // Before the interval elapses → nothing.
    assert!(
        a.tick(1_059_000).is_empty(),
        "must not send before the effective interval"
    );
    // At/after the interval → the pending change flushes.
    assert_eq!(
        a.tick(1_060_000).len(),
        1,
        "sends once the effective interval elapses"
    );
}

#[test]
fn receiver_strikes_a_delta_arriving_under_the_floor() {
    let mut b = engine(&hex(0x0b), "mainnet");
    deliver_handshake(&mut b, &hex(0x0a), "mainnet", 60); // floor = (60-5)*1000 = 55_000 ms
    b.on_message(
        &hex(0x0a),
        PexMessage::PexSnapshot { peers: vec![] },
        1_000_000,
    ); // starts clock
       // 10 s later — under the 55 s floor → rate violation, discarded.
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexDelta {
            added: vec![entry(&hex(0x0c), "mainnet", 1010)],
            dropped: vec![],
        },
        1_010_000,
    );
    assert!(matches!(
        out.replies[0],
        PexMessage::PexError { code: 3, .. }
    ));
    assert_eq!(b.strikes(&hex(0x0a)), 1);
    // The discarded delta produced no candidate.
    assert!(!out
        .events
        .iter()
        .any(|e| matches!(e, PexEvent::Candidates(_))));

    // A delta at/after the floor is accepted and yields a candidate.
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexDelta {
            added: vec![entry(&hex(0x0c), "mainnet", 1060)],
            dropped: vec![],
        },
        1_060_000,
    );
    assert!(out
        .events
        .iter()
        .any(|e| matches!(e, PexEvent::Candidates(c) if c.len() == 1)));
}

#[test]
fn code3_error_backs_off_the_senders_interval() {
    let mut a = engine(&hex(0x0a), "mainnet");
    a.link_up(&hex(0x0b), 1_000_000);
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000));
    // Receiving a rate-violation error doubles our effective interval: 60 → 120 s. Our own send
    // (link_up, above) was at the same now_ms, so it is plausible we actually violated the floor.
    a.on_message(
        &hex(0x0b),
        PexMessage::PexError {
            code: 3,
            message: "rate violation".into(),
        },
        1_000_000,
    );
    assert!(
        a.tick(1_060_000).is_empty(),
        "after backoff, 60 s is too soon"
    );
    assert_eq!(
        a.tick(1_120_000).len(),
        1,
        "the doubled 120 s interval now elapsed"
    );
}

// ---------------------------------------------------------------------------------------------
// LOW (#179) — a spoofed pex_error code 3 must not force an unbounded/indefinite back-off: it is
// only honored when we could plausibly have violated the floor, and at most once per effective
// interval even from a genuinely-violating peer.
// ---------------------------------------------------------------------------------------------

#[test]
fn code3_error_is_ignored_when_we_never_plausibly_violated_the_floor() {
    let mut a = engine(&hex(0x0a), "mainnet");
    // link_up at t=0 sends our snapshot (our only send so far). The arrival floor for a 60s
    // interval is (60-5)=55s, so a real rate violation on OUR sends could only be claimed while
    // within 55s of that send. A code-3 arriving long after (well past the floor window, and long
    // before our next legitimate send at t=60s) cannot correspond to a real violation.
    a.link_up(&hex(0x0b), 0);

    // Spoofed code-3 arrives at t=56s: past the 55s arrival-floor window since our last (and only)
    // send, so it is not plausible we actually violated anything.
    a.on_message(
        &hex(0x0b),
        PexMessage::PexError {
            code: 3,
            message: "rate violation".into(),
        },
        56_000,
    );

    // The interval must be unaffected: tick at exactly 60s must still fire (not pushed to 120s).
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000));
    assert_eq!(
        a.tick(60_000).len(),
        1,
        "an un-doubled 60s interval must have already elapsed by t=60s"
    );
}

#[test]
fn repeated_code3_spam_backs_off_at_most_once_per_effective_interval() {
    let mut a = engine(&hex(0x0a), "mainnet");
    a.link_up(&hex(0x0b), 1_000_000);
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000));

    // First code-3 (plausible: arrives right after our send) legitimately doubles 60 -> 120.
    a.on_message(
        &hex(0x0b),
        PexMessage::PexError {
            code: 3,
            message: "rate violation".into(),
        },
        1_000_000,
    );
    // A flood of further code-3 frames arriving immediately after must NOT keep doubling
    // (120 -> 240 -> 480 -> ... -> 3600) — at most one back-off per effective interval.
    for _ in 0..10 {
        a.on_message(
            &hex(0x0b),
            PexMessage::PexError {
                code: 3,
                message: "rate violation".into(),
            },
            1_000_001,
        );
    }

    // If the spam had kept doubling, the interval would have hit PEX_MAX_INTERVAL (3600s) and a
    // tick at 1_000_000 + 130_000 (just past the legitimate single-doubling 120s) would stay
    // silent far longer than 120s. Assert the single doubling (120s), not runaway growth: a tick
    // just past 120s must fire.
    assert!(
        a.tick(1_000_000 + 119_000).is_empty(),
        "119s < the single doubled 120s interval"
    );
    assert_eq!(
        a.tick(1_000_000 + 121_000).len(),
        1,
        "121s > the single doubled 120s interval — spam must not have pushed it further"
    );
}

// ---------------------------------------------------------------------------------------------
// PEX-04 — caps enforced on send and receive.
// ---------------------------------------------------------------------------------------------

#[test]
fn sender_caps_snapshot_at_200() {
    let mut a = engine(&hex(0x0a), "mainnet");
    for i in 0..250u32 {
        let id = format!("{:064x}", 0x1000 + i);
        a.upsert_known(entry(&id, "mainnet", 1000));
    }
    let out = a.link_up(&hex(0x0b), 1_000_000);
    match &out[1] {
        PexMessage::PexSnapshot { peers } => assert_eq!(peers.len(), PEX_MAX_SNAPSHOT),
        other => panic!("expected snapshot, got {other:?}"),
    }
}

#[test]
fn sender_caps_added_at_50_and_queues_the_rest() {
    let mut a = engine(&hex(0x0a), "mainnet");
    a.link_up(&hex(0x0b), 1_000_000);
    for i in 0..120u32 {
        let id = format!("{:064x}", 0x2000 + i);
        a.upsert_known(entry(&id, "mainnet", 1000));
    }
    let out = a.tick(1_060_000);
    match &out[0].1 {
        PexMessage::PexDelta { added, .. } => assert_eq!(added.len(), PEX_MAX_ADDED),
        other => panic!("expected delta, got {other:?}"),
    }
    // The remaining pending entries flow in subsequent deltas.
    let out = a.tick(1_120_000);
    match &out[0].1 {
        PexMessage::PexDelta { added, .. } => assert_eq!(added.len(), PEX_MAX_ADDED),
        other => panic!("expected delta, got {other:?}"),
    }
}

#[test]
fn receiver_rejects_oversize_snapshot_whole() {
    let mut b = engine(&hex(0x0b), "mainnet");
    deliver_handshake(&mut b, &hex(0x0a), "mainnet", 60);
    let peers: Vec<PeerEntry> = (0..PEX_MAX_SNAPSHOT + 1)
        .map(|i| entry(&format!("{:064x}", 0x3000 + i), "mainnet", 1000))
        .collect();
    let out = b.on_message(&hex(0x0a), PexMessage::PexSnapshot { peers }, 1_000_000);
    assert!(matches!(
        out.replies[0],
        PexMessage::PexError { code: 4, .. }
    ));
    // Rejected whole — no candidates surfaced from a truncated view.
    assert!(!out
        .events
        .iter()
        .any(|e| matches!(e, PexEvent::Candidates(_))));
}

#[test]
fn receiver_rejects_oversize_added_whole() {
    let mut b = engine(&hex(0x0b), "mainnet");
    deliver_handshake(&mut b, &hex(0x0a), "mainnet", 60);
    b.on_message(
        &hex(0x0a),
        PexMessage::PexSnapshot { peers: vec![] },
        1_000_000,
    );
    let added: Vec<PeerEntry> = (0..PEX_MAX_ADDED + 1)
        .map(|i| entry(&format!("{:064x}", 0x4000 + i), "mainnet", 1_060))
        .collect();
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexDelta {
            added,
            dropped: vec![],
        },
        1_060_000,
    );
    assert!(matches!(
        out.replies[0],
        PexMessage::PexError { code: 4, .. }
    ));
}

// ---------------------------------------------------------------------------------------------
// PEX-01 structural MUST — a peer_id in both added and dropped is a bad message.
// ---------------------------------------------------------------------------------------------

#[test]
fn peer_id_in_both_added_and_dropped_is_bad_message() {
    let mut b = engine(&hex(0x0b), "mainnet");
    deliver_handshake(&mut b, &hex(0x0a), "mainnet", 60);
    b.on_message(
        &hex(0x0a),
        PexMessage::PexSnapshot { peers: vec![] },
        1_000_000,
    );
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexDelta {
            added: vec![entry(&hex(0x0c), "mainnet", 1_060)],
            dropped: vec![hex(0x0c)],
        },
        1_060_000,
    );
    assert!(matches!(
        out.replies[0],
        PexMessage::PexError { code: 1, .. }
    ));
}

// ---------------------------------------------------------------------------------------------
// PEX-10 — malformed entries skipped silently; malformed messages struck; 3 strikes mute.
// ---------------------------------------------------------------------------------------------

#[test]
fn malformed_entries_are_skipped_valid_ones_kept() {
    let mut b = engine(&hex(0x0b), "mainnet");
    deliver_handshake(&mut b, &hex(0x0a), "mainnet", 60);
    let peers = vec![
        entry(&hex(0x0c), "mainnet", 1000),   // valid
        entry("not-64-hex", "mainnet", 1000), // bad peer_id → skip
        entry(&hex(0x0d), "testnet", 1000),   // wrong network → skip
        entry(&hex(0x0b), "mainnet", 1000),   // the sender itself → skip
        PeerEntry::new(hex(0x0e), "mainnet", 1000, Provenance::Direct) // port 0 → skip
            .with_address(Address::new("h", 0, AddressKind::Direct)),
        entry(&hex(0x0f), "mainnet", 1000), // valid
    ];
    let out = b.on_message(&hex(0x0a), PexMessage::PexSnapshot { peers }, 1_000_000);
    // No strike (entry-level junk is silent), and only the two valid peers surface.
    assert_eq!(b.strikes(&hex(0x0a)), 0);
    let cands = out
        .events
        .iter()
        .find_map(|e| match e {
            PexEvent::Candidates(c) => Some(c.clone()),
            _ => None,
        })
        .expect("candidates event");
    let ids: Vec<&str> = cands.iter().map(|c| c.peer_id.as_str()).collect();
    assert_eq!(ids, vec![hex(0x0c).as_str(), hex(0x0f).as_str()]);
}

#[test]
fn three_strikes_mute_the_direction() {
    let mut b = engine(&hex(0x0b), "mainnet");
    deliver_handshake(&mut b, &hex(0x0a), "mainnet", 60);
    // Three protocol violations (deltas before the snapshot are code 6).
    for i in 1..=3 {
        let out = b.on_message(
            &hex(0x0a),
            PexMessage::PexDelta {
                added: vec![],
                dropped: vec![],
            },
            1_000_000,
        );
        let muted = i == 3;
        assert_eq!(
            out.events,
            vec![PexEvent::Violation {
                code: 6,
                mute: muted
            }]
        );
    }
    assert!(b.is_muted(&hex(0x0a)));
    // Once muted, further inbound PEX is ignored (no reply, no event).
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexSnapshot { peers: vec![] },
        1_000_000,
    );
    assert_eq!(out, dig_pex::PexOutcome::default());
}

// ---------------------------------------------------------------------------------------------
// PEX-14 / PEX-05 — version + network mismatch mute the direction (advisory, non-strike).
// ---------------------------------------------------------------------------------------------

#[test]
fn unsupported_version_mutes_without_a_strike() {
    let mut b = engine(&hex(0x0b), "mainnet");
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexHandshake {
            version: 999,
            network_id: "mainnet".into(),
            interval: 60,
            flags: vec![],
        },
        1_000_000,
    );
    assert!(matches!(
        out.replies[0],
        PexMessage::PexError { code: 2, .. }
    ));
    assert_eq!(
        out.events,
        vec![PexEvent::Violation {
            code: 2,
            mute: true
        }]
    );
    assert!(b.is_muted(&hex(0x0a)));
    assert_eq!(
        b.strikes(&hex(0x0a)),
        0,
        "a version mismatch is not a misbehavior strike"
    );
}

#[test]
fn network_mismatch_mutes_without_a_strike() {
    let mut b = engine(&hex(0x0b), "mainnet");
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexHandshake {
            version: PEX_VERSION,
            network_id: "testnet".into(),
            interval: 60,
            flags: vec![],
        },
        1_000_000,
    );
    assert!(matches!(
        out.replies[0],
        PexMessage::PexError { code: 5, .. }
    ));
    assert!(b.is_muted(&hex(0x0a)));
    assert_eq!(b.strikes(&hex(0x0a)), 0);
}

// ---------------------------------------------------------------------------------------------
// PEX-09 — dropped is advisory and attributed only to what a link actually told us.
// ---------------------------------------------------------------------------------------------

#[test]
fn dropped_id_never_told_is_ignored() {
    let mut b = engine(&hex(0x0b), "mainnet");
    deliver_handshake(&mut b, &hex(0x0a), "mainnet", 60);
    b.on_message(
        &hex(0x0a),
        PexMessage::PexSnapshot { peers: vec![] },
        1_000_000,
    );
    // Dropping a peer this link never told us → no Dropped event.
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexDelta {
            added: vec![],
            dropped: vec![hex(0x0c)],
        },
        1_060_000,
    );
    assert!(!out
        .events
        .iter()
        .any(|e| matches!(e, PexEvent::Dropped { .. })));
}

#[test]
fn dropped_id_previously_told_is_attributed() {
    let mut b = engine(&hex(0x0b), "mainnet");
    deliver_handshake(&mut b, &hex(0x0a), "mainnet", 60);
    b.on_message(
        &hex(0x0a),
        PexMessage::PexSnapshot {
            peers: vec![entry(&hex(0x0c), "mainnet", 1000)],
        },
        1_000_000,
    );
    assert_eq!(b.current_hint(&hex(0x0c)), Some((hex(0x0a).as_str(), 1000)));
    let out = b.on_message(
        &hex(0x0a),
        PexMessage::PexDelta {
            added: vec![],
            dropped: vec![hex(0x0c)],
        },
        1_060_000,
    );
    assert_eq!(
        out.events,
        vec![PexEvent::Dropped {
            peer_ids: vec![hex(0x0c)]
        }]
    );
    // The hint sourced from this link is cleared.
    assert_eq!(b.current_hint(&hex(0x0c)), None);
}

// ---------------------------------------------------------------------------------------------
// SPEC §9.2 — inbound dedup: newest last_seen wins across senders.
// ---------------------------------------------------------------------------------------------

#[test]
fn inbound_dedup_newest_last_seen_wins() {
    let mut b = engine(&hex(0x0b), "mainnet");
    let a1 = hex(0x0a);
    let a2 = hex(0x02);
    deliver_handshake(&mut b, &a1, "mainnet", 60);
    deliver_handshake(&mut b, &a2, "mainnet", 60);

    // now_secs = 2000 at delivery, so last_seen 1000/1500/1200 are all in the past (and unclamped)
    // and within PEX_MAX_ENTRY_AGE.
    let target = hex(0x0c);
    b.on_message(
        &a1,
        PexMessage::PexSnapshot {
            peers: vec![entry(&target, "mainnet", 1000)],
        },
        2_000_000,
    );
    assert_eq!(b.current_hint(&target), Some((a1.as_str(), 1000)));

    // A2 reports the same peer with a NEWER last_seen → A2 becomes the current hint.
    b.on_message(
        &a2,
        PexMessage::PexSnapshot {
            peers: vec![entry(&target, "mainnet", 1500)],
        },
        2_000_000,
    );
    assert_eq!(b.current_hint(&target), Some((a2.as_str(), 1500)));

    // A1 reports an OLDER last_seen → the current (newer) hint is unchanged.
    b.on_message(
        &a1,
        PexMessage::PexDelta {
            added: vec![entry(&target, "mainnet", 1200)],
            dropped: vec![],
        },
        2_060_000,
    );
    assert_eq!(b.current_hint(&target), Some((a2.as_str(), 1500)));
}

// ---------------------------------------------------------------------------------------------
// PEX-12 — identity is the transport peer_id, never a wire field; one engine multiplexes links.
// ---------------------------------------------------------------------------------------------

#[test]
fn engine_keys_links_by_transport_identity() {
    let mut a = engine(&hex(0x0a), "mainnet");
    a.link_up(&hex(0x0b), 1_000_000);
    a.link_up(&hex(0x0c), 1_000_000);
    assert_eq!(a.link_count(), 2);
    a.link_down(&hex(0x0b));
    assert_eq!(a.link_count(), 1);
}

// ---------------------------------------------------------------------------------------------
// PEX-13 — the relay/introducer role advertises registration-backed entries with via:introducer.
// ---------------------------------------------------------------------------------------------

#[test]
fn introducer_role_advertises_via_introducer_entries() {
    let mut relay = PexEngine::new(
        PexConfig::new(hex(0x99), "mainnet")
            .with_flags(vec!["introducer".into()])
            .with_jitter(false),
    );
    // The relay mirrors a registrant into the engine as its first-hand (introducer) knowledge.
    let registrant = PeerEntry::new(hex(0x0c), "mainnet", 1000, Provenance::Introducer)
        .with_address(Address::new("198.51.100.9", 9444, AddressKind::Reflexive))
        .with_flag("relay-only");
    relay.upsert_known(registrant);
    let out = relay.link_up(&hex(0x0b), 1_000_000);
    match &out[0] {
        PexMessage::PexHandshake { flags, .. } => {
            assert_eq!(flags, &vec!["introducer".to_string()])
        }
        other => panic!("expected handshake, got {other:?}"),
    }
    match &out[1] {
        PexMessage::PexSnapshot { peers } => {
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].via, Provenance::Introducer);
            assert!(peers[0].flags.contains(&"relay-only".to_string()));
        }
        other => panic!("expected snapshot, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Transport-detected violations (frame oversize / undecodable) strike via record_violation.
// ---------------------------------------------------------------------------------------------

#[test]
fn record_violation_strikes_transport_detected_faults() {
    let mut b = engine(&hex(0x0b), "mainnet");
    b.link_up(&hex(0x0a), 1_000_000);
    let out = b.record_violation(&hex(0x0a), PexErrorCode::Oversized, 1_000_000);
    assert_eq!(b.strikes(&hex(0x0a)), 1);
    assert!(matches!(
        out.replies[0],
        PexMessage::PexError { code: 4, .. }
    ));
}

// ---------------------------------------------------------------------------------------------
// Full two-engine end-to-end flow: handshake → snapshot → delta, over in-memory links.
// ---------------------------------------------------------------------------------------------

#[test]
fn two_engines_complete_a_full_exchange() {
    let a_id = hex(0x0a);
    let b_id = hex(0x0b);
    let mut a = engine(&a_id, "mainnet");
    let mut b = engine(&b_id, "mainnet");

    // A knows peer C first-hand; B knows peer D.
    a.upsert_known(entry(&hex(0x0c), "mainnet", 1000));
    b.upsert_known(entry(&hex(0x0d), "mainnet", 1000));

    // Each opens its sending direction.
    let a_out = a.link_up(&b_id, 1_000_000);
    let b_out = b.link_up(&a_id, 1_000_000);

    // Deliver A's stream into B and vice-versa.
    for m in a_out {
        let outcome = b.on_message(&a_id, m, 1_000_000);
        assert!(outcome
            .replies
            .iter()
            .all(|r| !matches!(r, PexMessage::PexError { .. })));
    }
    for m in b_out {
        let outcome = a.on_message(&b_id, m, 1_000_000);
        assert!(outcome
            .replies
            .iter()
            .all(|r| !matches!(r, PexMessage::PexError { .. })));
    }

    // Each side learned the other's peer as a candidate hint.
    assert_eq!(b.current_hint(&hex(0x0c)), Some((a_id.as_str(), 1000)));
    assert_eq!(a.current_hint(&hex(0x0d)), Some((b_id.as_str(), 1000)));

    // A learns a new peer E; after the interval it deltas exactly E to B.
    a.upsert_known(entry(&hex(0x0e), "mainnet", 1000));
    let ticks = a.tick(1_060_000);
    assert_eq!(ticks.len(), 1);
    let (peer, msg) = &ticks[0];
    assert_eq!(peer, &b_id);
    let outcome = b.on_message(&a_id, msg.clone(), 1_060_000);
    assert!(outcome
        .events
        .iter()
        .any(|e| matches!(e, PexEvent::Candidates(c) if c.iter().any(|x| x.peer_id == hex(0x0e)))));
}
