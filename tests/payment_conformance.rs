//! Conformance tests for the **signed payment address** (SPEC §3.4) — the field the incentive layer
//! pays against.
//!
//! Every test here is built around one question: *can a relay that forwards a peer record redirect
//! that peer's earnings to itself?* So the fixtures are adversarial by construction — each one is a
//! real ECDSA P-256 key producing a real signature, differing from the honest case in exactly ONE
//! respect, so a failure tells you precisely which binding was lost.
//!
//! The verifier is injected (`dig-pex` is sans-IO and does no signature crypto itself, SPEC §3.4.3),
//! so these tests supply a genuine P-256 verifier — not a stub returning `true`, which could not
//! distinguish a bound signature from an unbound one.

use dig_pex::{
    Address, PaymentClaim, PaymentClaimError, PeerEntry, Provenance, SignatureVerifier, ValidateCtx,
};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};

/// A real ECDSA P-256 verifier — the same curve `dig-tls` issues node leaf certificates on
/// (`PKCS_ECDSA_P256_SHA256`), so these tests exercise the key type that actually produces
/// `peer_id = SHA-256(SPKI DER)` on the live network.
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

/// One node's identity: an ECDSA P-256 key pair plus the `peer_id` it induces.
struct Node {
    signing_key: SigningKey,
    spki_der: Vec<u8>,
}

impl Node {
    /// Deterministic per `seed`, so a failure reproduces exactly.
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

    /// This node's `peer_id` — `SHA-256(SPKI DER)`, exactly as `dig-tls` derives it on connect.
    fn peer_id(&self) -> String {
        dig_pex::peer_id_for_spki(&self.spki_der)
    }

    /// A claim signed by THIS node over `(peer_id, network_id, address)`. The context is passed in
    /// rather than derived, so a test can sign for one context and present the result in another —
    /// which is the replay the canonical bytes exist to defeat.
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

const MAINNET: &str = "mainnet";
const TESTNET: &str = "testnet11";
const PAYEE: &str = "xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs7lyw6y";

/// An advertisable entry for `node`, carrying `claim` (if any) and a dialable address, so every test
/// below can also observe that reachability is unaffected by the payment verdict.
fn entry_for(node: &Node, network_id: &str, claim: Option<PaymentClaim>) -> PeerEntry {
    let mut e = PeerEntry::new(node.peer_id(), network_id, 1_000, Provenance::Direct)
        .with_address(Address::direct("203.0.113.7", 9444));
    if let Some(c) = claim {
        e = e.with_payment(c);
    }
    e
}

#[test]
fn honest_claim_yields_the_payment_address() {
    let node = Node::new(7);
    let entry = entry_for(&node, MAINNET, Some(node.claim(MAINNET, PAYEE)));

    assert_eq!(
        entry.verified_payment_address(&P256Verifier),
        Ok(PAYEE),
        "a first-party signature over (peer_id, network_id, address) must yield the payee"
    );
}

/// The theft primitive this whole feature exists to prevent: a relay forwarding the record swaps in
/// its OWN payee, its OWN key, and a signature that is perfectly valid *for itself*.
///
/// The nearest wrong implementation — verify the signature against the SPKI carried in the record —
/// accepts this, because the attacker's signature over the attacker's SPKI is genuine. Only
/// recomputing `SHA-256(SPKI) == peer_id` catches it, which is what this fixture tells apart.
#[test]
fn a_relaying_attacker_cannot_substitute_its_own_payee() {
    let victim = Node::new(7);
    let attacker = Node::new(9);
    let attacker_payee = "xch1attackerattackerattackerattackerattackerattackerattackerattacke";

    // The victim's record, forwarded — except the payment claim is entirely the attacker's, signed
    // by the attacker for the attacker's own address. The `peer_id` still names the victim, because
    // rewriting it would break the very reachability the attacker is relaying.
    let entry = entry_for(&victim, MAINNET, None).with_payment(attacker.claim_signed_for(
        &victim.peer_id(),
        MAINNET,
        attacker_payee,
    ));

    assert_eq!(
        entry.verified_payment_address(&P256Verifier),
        Err(PaymentClaimError::PeerIdMismatch),
        "a signature by a key that does not hash to peer_id must never name a payee"
    );
}

/// A verbatim copy of an honest claim, lifted into a different peer's record. The signature verifies
/// against the SPKI it carries and the address is untampered — only the `SHA-256(SPKI) == peer_id`
/// recomputation separates "this peer's claim" from "some peer's claim".
#[test]
fn a_valid_claim_lifted_onto_another_peer_is_refused() {
    let earner = Node::new(7);
    let other = Node::new(11);

    let entry = entry_for(&other, MAINNET, None).with_payment(earner.claim(MAINNET, PAYEE));

    assert_eq!(
        entry.verified_payment_address(&P256Verifier),
        Err(PaymentClaimError::PeerIdMismatch),
    );
}

/// Cross-network replay: the peer's REAL claim, signed by its REAL key for its REAL `peer_id` — but
/// made on testnet and replayed into a mainnet record. Every other binding holds; only `network_id`
/// inside the canonical bytes refuses it.
#[test]
fn a_cross_network_replay_is_refused() {
    let node = Node::new(7);

    let replayed = entry_for(&node, MAINNET, None).with_payment(node.claim(TESTNET, PAYEE));
    assert_eq!(
        replayed.verified_payment_address(&P256Verifier),
        Err(PaymentClaimError::BadSignature),
        "a claim signed for another network must not be honoured on this one"
    );

    // The control: the identical claim IS honoured on the network it was signed for, so the refusal
    // above is the network binding and not a broken fixture.
    let at_home = entry_for(&node, TESTNET, None).with_payment(node.claim(TESTNET, PAYEE));
    assert_eq!(at_home.verified_payment_address(&P256Verifier), Ok(PAYEE));
}

/// The address itself is inside the signed bytes: rewriting it while keeping the peer's genuine key
/// and signature must not produce a payee.
#[test]
fn a_rewritten_address_is_refused() {
    let node = Node::new(7);
    let honest = node.claim(MAINNET, PAYEE);
    let tampered = PaymentClaim::new(
        "xch1thiefthiefthiefthiefthiefthiefthiefthiefthiefthiefthiefthiefth",
        &honest.spki_der(),
        &honest.signature(),
    );

    let entry = entry_for(&node, MAINNET, None).with_payment(tampered);

    assert_eq!(
        entry.verified_payment_address(&P256Verifier),
        Err(PaymentClaimError::BadSignature),
    );
}

/// The two verdicts on one record are genuinely different: an unusable payee must not cost the peer
/// its reachability, because that would let a corrupting relay silently partition it.
#[test]
fn an_unverifiable_claim_leaves_the_entry_dialable() {
    let victim = Node::new(7);
    let attacker = Node::new(9);
    let entry = entry_for(&victim, MAINNET, None).with_payment(attacker.claim_signed_for(
        &victim.peer_id(),
        MAINNET,
        PAYEE,
    ));

    let receiver = "a".repeat(64);
    let sender = "b".repeat(64);
    let ctx = ValidateCtx {
        receiver_peer_id: &receiver,
        sender_peer_id: &sender,
        network_id: MAINNET,
        now_secs: 1_000,
    };
    assert_eq!(entry.validate(&ctx), Ok(()), "still a usable dial hint");
    assert_eq!(entry.addresses.len(), 1);
    assert!(entry.verified_payment_address(&P256Verifier).is_err());
}

/// A record from a peer that predates this field must still decode — the field is optional and
/// serde-defaulted, and its absence is `NotPresent`, never a malformed record.
#[test]
fn a_record_without_the_field_still_decodes_and_is_simply_unpayable() {
    let legacy = concat!(
        r#"{"peer_id":"0707070707070707070707070707070707070707070707070707070707070707","#,
        r#""addresses":[{"host":"203.0.113.7","port":9444,"kind":"direct"}],"#,
        r#""network_id":"mainnet","last_seen":1000,"via":"direct","flags":["storage"]}"#
    );

    let entry: PeerEntry = serde_json::from_str(legacy).expect("a pre-payment record must decode");
    assert_eq!(entry.addresses.len(), 1);
    assert_eq!(
        entry.verified_payment_address(&P256Verifier),
        Err(PaymentClaimError::NotPresent),
    );

    // Round-trips back to a record an old peer can still read: no `payment` key is emitted.
    let json = serde_json::to_string(&entry).unwrap();
    assert!(
        !json.contains("payment"),
        "an entry with no claim must not grow a payment key: {json}"
    );
}

/// A claim survives the wire — the JSON is what a third party re-verifies from, so the encoded form
/// must carry everything verification needs.
#[test]
fn a_claim_verifies_after_a_json_round_trip() {
    let node = Node::new(7);
    let entry = entry_for(&node, MAINNET, Some(node.claim(MAINNET, PAYEE)));

    let decoded: PeerEntry = serde_json::from_str(&serde_json::to_string(&entry).unwrap()).unwrap();
    assert_eq!(
        decoded.verified_payment_address(&P256Verifier),
        Ok(PAYEE),
        "a record verified second-hand must verify from its bytes alone"
    );
}
