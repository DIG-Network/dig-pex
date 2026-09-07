//! Conformance tests for SPEC §4.2.1 — the sender's own signed payment claim on `pex_handshake`
//! (PEX-17..23). Every test drives the REAL inbound path (`PexEngine::on_message`) rather than
//! calling any internal claim store directly, and every claim is a genuine ECDSA P-256 signature —
//! not a stub verifier that cannot distinguish a bound signature from an unbound one (the same
//! discipline as `tests/payment_conformance.rs`).

use dig_pex::{
    Address, PaymentClaim, PaymentClaimError, PeerEntry, PexConfig, PexEngine, PexMessage,
    Provenance, SignatureVerifier,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use std::sync::Arc;

/// A real ECDSA P-256 verifier — the curve `dig-tls` issues node leaf certs on.
struct P256Verifier;

impl SignatureVerifier for P256Verifier {
    fn verify(&self, spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(vk) = VerifyingKey::from_public_key_der(spki_der) else {
            return false;
        };
        let Ok(sig) = Signature::from_der(signature) else {
            return false;
        };
        vk.verify(message, &sig).is_ok()
    }
}

/// One node's identity: a P-256 key pair plus the `peer_id` it induces. Deterministic per `seed`.
struct Node {
    signing_key: SigningKey,
    spki_der: Vec<u8>,
}

impl Node {
    fn new(seed: u8) -> Self {
        let signing_key = SigningKey::from_bytes(&[seed.max(1); 32].into())
            .expect("a non-zero 32-byte scalar is a valid P-256 signing key");
        let spki_der = VerifyingKey::from(&signing_key)
            .to_public_key_der()
            .expect("P-256 public keys encode to SPKI DER")
            .as_bytes()
            .to_vec();
        Node {
            signing_key,
            spki_der,
        }
    }

    fn peer_id(&self) -> String {
        dig_pex::peer_id_for_spki(&self.spki_der)
    }

    /// A claim signed by THIS node over `(peer_id, network_id, address)` — the context is passed in
    /// explicitly so a test can sign for one peer_id/network and present the result under another.
    fn claim_signed_for(&self, peer_id: &str, network_id: &str, address: &str) -> PaymentClaim {
        let msg = dig_pex::payment_signing_bytes(peer_id, network_id, address);
        let sig: Signature = self.signing_key.sign(&msg);
        PaymentClaim::new(address, &self.spki_der, sig.to_der().as_bytes())
    }

    /// The honest case: signed for this node's own `peer_id` on `network_id`.
    fn claim(&self, network_id: &str, address: &str) -> PaymentClaim {
        self.claim_signed_for(&self.peer_id(), network_id, address)
    }
}

const NET: &str = "mainnet";
const PAYEE: &str = "xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs7lyw6y";
const OTHER_PAYEE: &str = "xch1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzsp0m8xx";

/// A first-hand entry for `node`, dialable, with no payment claim attached (the engine attaches one
/// from its own store, never one carried on this base entry, unless the test asks for both).
fn first_hand_entry(node: &Node) -> PeerEntry {
    PeerEntry::new(node.peer_id(), NET, 1_000, Provenance::Direct)
        .with_address(Address::direct("203.0.113.7", 9444))
}

fn engine(local_peer_id: &str) -> PexEngine {
    PexEngine::new(PexConfig::new(local_peer_id.to_string(), NET).with_jitter(false))
}

fn engine_with_verifier(local_peer_id: &str) -> PexEngine {
    PexEngine::new(
        PexConfig::new(local_peer_id.to_string(), NET)
            .with_jitter(false)
            .with_payment_verifier(Arc::new(P256Verifier)),
    )
}

/// Deliver `sender`'s handshake carrying `payment` into `eng`, over the real inbound path.
fn deliver_handshake(eng: &mut PexEngine, sender: &str, payment: Option<PaymentClaim>) {
    let out = eng.on_message(
        sender,
        PexMessage::PexHandshake {
            version: dig_pex::PEX_VERSION,
            network_id: NET.to_string(),
            interval: 60,
            flags: vec![],
            payment,
        },
        1_000_000,
    );
    assert!(
        out.events.is_empty() && out.replies.is_empty(),
        "SPEC §4.2.1 rule 4: a payment claim — good or bad — never yields an error or event"
    );
}

/// The claim `receiver` currently advertises for `subject`, found by opening a fresh observer link
/// and reading the outgoing snapshot — the only public surface for "what would be told next" (no
/// internal store accessor is exposed, by design: SPEC §4.2.1 rule 6 says the embedder never
/// touches the store).
fn advertised_claim(
    receiver: &mut PexEngine,
    subject_peer_id: &str,
    observer: &str,
) -> Option<PaymentClaim> {
    let out = receiver.link_up(observer, 2_000_000);
    let PexMessage::PexSnapshot { peers } = &out[1] else {
        panic!("link_up's second message is always the snapshot");
    };
    peers
        .iter()
        .find(|e| e.peer_id == subject_peer_id)
        .and_then(|e| e.payment.clone())
}

// ---------------------------------------------------------------------------------------------
// (a) a valid own claim is stored and exposed on the sender's advertised entry.
// ---------------------------------------------------------------------------------------------

#[test]
fn valid_own_claim_is_stored_and_advertised() {
    let sender = Node::new(1);
    let mut receiver = engine_with_verifier(&Node::new(2).peer_id());
    receiver.upsert_known(first_hand_entry(&sender));

    let claim = sender.claim(NET, PAYEE);
    deliver_handshake(&mut receiver, &sender.peer_id(), Some(claim.clone()));

    assert_eq!(
        advertised_claim(&mut receiver, &sender.peer_id(), "observer-1"),
        Some(claim),
        "a claim verified against the link's own peer_id must ride on the sender's advertised entry"
    );
}

// ---------------------------------------------------------------------------------------------
// (b) spki hashes to a DIFFERENT peer_id than the link -> dropped, no error/strike, store unchanged.
// ---------------------------------------------------------------------------------------------

#[test]
fn peer_id_mismatched_claim_is_dropped_without_a_strike() {
    let real_sender = Node::new(3);
    let impostor_key = Node::new(4); // a different key entirely (PEX-17..23 trap: must be distinct)
    let mut receiver = engine_with_verifier(&Node::new(5).peer_id());
    receiver.upsert_known(first_hand_entry(&real_sender));

    // Signed correctly for the IMPOSTOR's own peer_id, but carried on a handshake whose link
    // peer_id is `real_sender`'s — exactly the substitution SPEC §4.2.1 rule 2 exists to catch.
    let mismatched = impostor_key.claim(NET, OTHER_PAYEE);
    deliver_handshake(&mut receiver, &real_sender.peer_id(), Some(mismatched));

    assert_eq!(
        receiver.strikes(&real_sender.peer_id()),
        0,
        "SPEC §4.2.1 rule 4: a failed claim costs the claim and nothing else, never a strike"
    );
    assert!(!receiver.is_muted(&real_sender.peer_id()));
    assert_eq!(
        advertised_claim(&mut receiver, &real_sender.peer_id(), "observer-2"),
        None,
        "a peer_id-mismatched claim must never enter the store"
    );
}

// ---------------------------------------------------------------------------------------------
// (c) same shape, but the bad field is the SIGNATURE rather than the key.
// ---------------------------------------------------------------------------------------------

#[test]
fn bad_signature_claim_is_dropped_without_a_strike() {
    let sender = Node::new(6);
    let mut receiver = engine_with_verifier(&Node::new(7).peer_id());
    receiver.upsert_known(first_hand_entry(&sender));

    // A genuine claim, but signed by the sender for a DIFFERENT address than the one it carries
    // (a tampered/rewritten address) — the correct key + peer_id, but the signature no longer
    // covers these exact canonical bytes (SPEC §3.4.1), so the signature check must fail.
    let signed_for_other_payee = sender.claim_signed_for(&sender.peer_id(), NET, OTHER_PAYEE);
    let rewritten = PaymentClaim::new(PAYEE, &sender.spki_der, &signed_for_other_payee.signature());
    deliver_handshake(&mut receiver, &sender.peer_id(), Some(rewritten));

    assert_eq!(receiver.strikes(&sender.peer_id()), 0);
    assert!(!receiver.is_muted(&sender.peer_id()));
    assert_eq!(
        advertised_claim(&mut receiver, &sender.peer_id(), "observer-3"),
        None,
        "a claim whose signature does not cover the carried address must never enter the store"
    );
}

// ---------------------------------------------------------------------------------------------
// (d) no verifier configured -> nothing stored, PEX runs normally.
// ---------------------------------------------------------------------------------------------

#[test]
fn no_verifier_configured_means_no_payee_but_pex_runs_normally() {
    let sender = Node::new(8);
    let mut receiver = engine(&Node::new(9).peer_id()); // no `with_payment_verifier`
    receiver.upsert_known(first_hand_entry(&sender));

    let claim = sender.claim(NET, PAYEE);
    deliver_handshake(&mut receiver, &sender.peer_id(), Some(claim));

    assert_eq!(receiver.strikes(&sender.peer_id()), 0);
    assert!(!receiver.is_muted(&sender.peer_id()));
    assert_eq!(
        advertised_claim(&mut receiver, &sender.peer_id(), "observer-4"),
        None,
        "SPEC §4.2.1 rule 5: no verifier configured means no claim is ever stored or exposed"
    );
}

// ---------------------------------------------------------------------------------------------
// (e) config-time refusal of an unusable own claim (rule 9).
// ---------------------------------------------------------------------------------------------

#[test]
fn config_refuses_an_own_claim_whose_key_is_not_its_own() {
    let me = Node::new(10);
    let someone_else = Node::new(11);
    let foreign_claim = someone_else.claim(NET, PAYEE);

    let err = PexConfig::new(me.peer_id(), NET)
        .try_with_payment(foreign_claim)
        .expect_err(
            "a claim whose spki hashes to a DIFFERENT peer_id must be refused at config time",
        );
    assert_eq!(err, PaymentClaimError::PeerIdMismatch);
}

#[test]
fn config_refuses_an_over_cap_own_claim() {
    let me = Node::new(12);
    let over_cap_address = "x".repeat(dig_pex::PEX_MAX_PAYMENT_ADDRESS_LEN + 1);
    let claim = me.claim(NET, &over_cap_address);

    let err = PexConfig::new(me.peer_id(), NET)
        .try_with_payment(claim)
        .expect_err("an over-cap claim must be refused at config time, never sent");
    assert_eq!(err, PaymentClaimError::Malformed);
}

#[test]
fn config_accepts_a_genuinely_own_claim() {
    let me = Node::new(13);
    let claim = me.claim(NET, PAYEE);
    assert!(PexConfig::new(me.peer_id(), NET)
        .try_with_payment(claim)
        .is_ok());
}

// ---------------------------------------------------------------------------------------------
// (g) a failed claim never replaces a stored verified one.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_failed_claim_never_replaces_a_stored_verified_one() {
    let sender = Node::new(14);
    let impostor_key = Node::new(15);
    let mut receiver = engine_with_verifier(&Node::new(16).peer_id());
    receiver.upsert_known(first_hand_entry(&sender));

    let good = sender.claim(NET, PAYEE);
    deliver_handshake(&mut receiver, &sender.peer_id(), Some(good.clone()));
    assert_eq!(
        advertised_claim(&mut receiver, &sender.peer_id(), "observer-5a"),
        Some(good.clone())
    );

    // The link tears down, but the peer is STILL first-hand known, so the claim survives (rule 7)
    // and a fresh connection from the same peer_id starts a new handshake cycle.
    receiver.link_down(&sender.peer_id());
    let bad = impostor_key.claim(NET, OTHER_PAYEE); // wrong key entirely
    deliver_handshake(&mut receiver, &sender.peer_id(), Some(bad));

    assert_eq!(
        advertised_claim(&mut receiver, &sender.peer_id(), "observer-5b"),
        Some(good),
        "SPEC §4.2.1 rule 6: only a claim that itself verifies may replace the stored one"
    );
}

// ---------------------------------------------------------------------------------------------
// (h) lifetime: claim discarded only once BOTH the link is down AND the peer is no longer
// first-hand known; retained while either condition still holds.
// ---------------------------------------------------------------------------------------------

#[test]
fn claim_survives_link_down_while_peer_remains_first_hand_known() {
    let sender = Node::new(17);
    let mut receiver = engine_with_verifier(&Node::new(18).peer_id());
    receiver.upsert_known(first_hand_entry(&sender));
    deliver_handshake(
        &mut receiver,
        &sender.peer_id(),
        Some(sender.claim(NET, PAYEE)),
    );

    receiver.link_down(&sender.peer_id()); // link gone, but still first-hand known
    assert!(
        advertised_claim(&mut receiver, &sender.peer_id(), "observer-6").is_some(),
        "SPEC §4.2.1 rule 7: the claim must outlive link teardown while the entry is still advertised"
    );
}

#[test]
fn claim_survives_removal_from_first_hand_set_while_link_stays_up() {
    let sender = Node::new(19);
    let mut receiver = engine_with_verifier(&Node::new(20).peer_id());
    receiver.upsert_known(first_hand_entry(&sender));
    deliver_handshake(
        &mut receiver,
        &sender.peer_id(),
        Some(sender.claim(NET, PAYEE)),
    );

    // Not advertisable once removed from `known` regardless of the claim, but the STORE must not
    // have discarded the claim yet (rule 7: the link is still up) — proven by re-adding the peer to
    // `known` without a second handshake and observing the claim is still there.
    receiver.remove_known(&sender.peer_id());
    receiver.upsert_known(first_hand_entry(&sender));
    assert!(
        advertised_claim(&mut receiver, &sender.peer_id(), "observer-7").is_some(),
        "SPEC §4.2.1 rule 7: the claim must outlive a first-hand removal while the link is still up"
    );
}

#[test]
fn claim_discarded_once_both_link_and_first_hand_knowledge_are_gone() {
    let sender = Node::new(21);
    let mut receiver = engine_with_verifier(&Node::new(22).peer_id());
    receiver.upsert_known(first_hand_entry(&sender));
    deliver_handshake(
        &mut receiver,
        &sender.peer_id(),
        Some(sender.claim(NET, PAYEE)),
    );

    receiver.link_down(&sender.peer_id());
    receiver.remove_known(&sender.peer_id());
    // Re-add first-hand knowledge with no NEW handshake: if the claim had wrongly survived, it
    // would show up here even though both lifetime conditions ceased in between.
    receiver.upsert_known(first_hand_entry(&sender));
    assert_eq!(
        advertised_claim(&mut receiver, &sender.peer_id(), "observer-8"),
        None,
        "SPEC §4.2.1 rule 7: once link down AND first-hand-removed have both happened, the claim is gone"
    );
}

// ---------------------------------------------------------------------------------------------
// (i) precedence: a stored verified claim overrides an embedder-attached one on the same entry.
// ---------------------------------------------------------------------------------------------

#[test]
fn stored_verified_claim_takes_precedence_over_embedder_attached_claim() {
    let sender = Node::new(23);
    let embedder_claim = sender.claim(NET, OTHER_PAYEE); // valid, but not what the link verified
    let mut receiver = engine_with_verifier(&Node::new(24).peer_id());
    receiver.upsert_known(first_hand_entry(&sender).with_payment(embedder_claim));

    let verified = sender.claim(NET, PAYEE);
    deliver_handshake(&mut receiver, &sender.peer_id(), Some(verified.clone()));

    assert_eq!(
        advertised_claim(&mut receiver, &sender.peer_id(), "observer-9"),
        Some(verified),
        "SPEC §4.2.1 rule 6: the PEX-verified claim must win over whatever the embedder attached"
    );
}

#[test]
fn a_new_stored_claim_re_advertises_as_an_added_update_at_next_delta() {
    let sender = Node::new(27);
    let mut receiver = engine_with_verifier(&Node::new(28).peer_id());
    receiver.upsert_known(first_hand_entry(&sender));

    // The observer is already told about `sender` with no claim (snapshot at t=0).
    let out = receiver.link_up("observer-11", 0);
    let PexMessage::PexSnapshot { peers } = &out[1] else {
        panic!("link_up's second message is always the snapshot");
    };
    assert!(peers
        .iter()
        .any(|e| e.peer_id == sender.peer_id() && e.payment.is_none()));

    // A verified claim arrives AFTER that snapshot already told the observer this entry.
    deliver_handshake(
        &mut receiver,
        &sender.peer_id(),
        Some(sender.claim(NET, PAYEE)),
    );

    // Past the effective interval, the next tick must re-advertise `sender` as an `added` update —
    // never `dropped`, which the wire shape restricts to bare `peer_id` strings (rule 8).
    let ticks = receiver.tick(61_000);
    assert_eq!(ticks.len(), 1);
    let (peer, msg) = &ticks[0];
    assert_eq!(peer, "observer-11");
    match msg {
        PexMessage::PexDelta { added, dropped } => {
            assert!(dropped.is_empty());
            assert!(
                added
                    .iter()
                    .any(|e| e.peer_id == sender.peer_id() && e.payment.is_some()),
                "SPEC §4.2.1 rule 8: a newly stored claim must re-advertise the entry as an update"
            );
        }
        other => panic!("expected pex_delta, got {other:?}"),
    }
}

#[test]
fn embedder_attached_claim_is_left_alone_when_nothing_is_stored() {
    let sender = Node::new(25);
    let embedder_claim = sender.claim(NET, OTHER_PAYEE);
    let mut receiver = engine_with_verifier(&Node::new(26).peer_id());
    receiver.upsert_known(first_hand_entry(&sender).with_payment(embedder_claim.clone()));

    // No handshake at all this time — nothing verified, so precedence never applies.
    assert_eq!(
        advertised_claim(&mut receiver, &sender.peer_id(), "observer-10"),
        Some(embedder_claim),
        "SPEC §4.2.1 rule 6: with no stored claim, the embedder's own attachment is advertised as-is"
    );
}
