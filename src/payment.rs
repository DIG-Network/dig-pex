//! The **signed payment address** (SPEC §3.4) — how a peer says "pay my earnings here" in a way a
//! third party can check.
//!
//! ## Why a signature is not optional here
//!
//! Every other field of a [`PeerEntry`](crate::PeerEntry) is self-correcting: a wrong address simply
//! fails to dial, and the mTLS handshake proves identity on connect, so a lie costs the liar nothing
//! but is caught immediately. **A payee field inverts that.** PEX records are *relayed*, so an
//! unauthenticated payee means the incentive layer pays whoever last forwarded the record rather than
//! whoever earned it — and the victim never finds out, because a payment that succeeds looks
//! identical either way. An unauthenticated field naming a payee is a theft primitive, not a
//! convenience.
//!
//! ## The binding: the record proves itself, with no lookup
//!
//! A DIG `peer_id` is defined as `SHA-256(TLS SPKI DER)`. That makes a **self-contained** proof
//! available: the claim carries the peer's **SPKI DER**, a verifier recomputes
//! `SHA-256(SPKI) == peer_id`, and then checks the signature over the canonical bytes against that
//! key. No directory, no resolution step, no second identity concept, and no new trust root — which
//! matters because the parties that most need to check a claim (relays, and any node that received
//! the record second- or third-hand) are exactly the parties least likely to have a resolution path.
//!
//! ## The canonical bytes ([`payment_signing_bytes`])
//!
//! ```text
//! "dig-pex/payment-address/v1\0"
//!   || u32be(len(peer_id))    || peer_id
//!   || u32be(len(network_id)) || network_id
//!   || u32be(len(address))    || address
//! ```
//!
//! Domain-separated (so a signature made for another DIG protocol cannot be replayed in here) and
//! length-prefixed (so no concatenation of different field values can produce the same bytes).
//!
//! **What a valid signature therefore proves:** the holder of the private key whose SPKI hashes to
//! `peer_id` designated *this* address as its payee *on this network*.
//!
//! **What it does NOT prove**, and callers must not assume: that the peer is reachable, that it is
//! honest, that the address is well-formed or spendable, that the claim is *recent* (`last_seen` is
//! deliberately outside the signed bytes — see below), or that it has not been superseded by a newer
//! claim the verifier has not seen.
//!
//! ### Why `last_seen` is excluded
//!
//! Including it would make every signature expire on the advertiser's next heartbeat, forcing the
//! *advertised* peer to re-sign continuously and the advertiser to re-request a signature it cannot
//! produce itself — an availability dependency on the very peer the record exists to route around.
//! Excluding it makes the claim a durable, cacheable, relayable credential, at the stated cost that a
//! *revoked* address stays verifiable until the peer's newer claim propagates. Superseding a claim is
//! therefore the incentive layer's concern (prefer the claim on the freshest first-hand record), not
//! this signature's.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator prefixed to the canonical bytes, mirroring the `dig-tls` SPKI-binding style: a
/// signature made for a different DIG protocol can never be reinterpreted as a payment designation.
const PAYMENT_SIG_CONTEXT: &[u8] = b"dig-pex/payment-address/v1\0";

/// Maximum characters in a payment address (SPEC §3.4.2). A Chia bech32m address is 62 characters;
/// the headroom accommodates longer address forms without leaving the field unbounded to a hostile
/// sender.
pub const PEX_MAX_PAYMENT_ADDRESS_LEN: usize = 128;

/// Maximum characters in the base64 `spki` field. An ECDSA P-256 SPKI DER is 91 bytes (124 base64
/// characters); the headroom covers other key types without unbounding the field.
pub const PEX_MAX_PAYMENT_SPKI_LEN: usize = 512;

/// Maximum characters in the base64 `sig` field. An ASN.1 DER P-256 signature is at most 72 bytes
/// (96 base64 characters).
pub const PEX_MAX_PAYMENT_SIG_LEN: usize = 256;

/// The signature-verification capability a caller injects (SPEC §3.4.3).
///
/// `dig-pex` is deliberately sans-IO and carries no signature crypto of its own: it defines the field
/// and the canonical bytes, and the embedding node or relay supplies the primitive matching the key
/// type in use (ECDSA P-256, as `dig-tls` issues today). The `peer_id`-to-key binding is *not*
/// delegated — [`PaymentClaim::verify`] recomputes `SHA-256(SPKI) == peer_id` itself, so a
/// permissive verifier can never be talked into naming the wrong payee.
pub trait SignatureVerifier {
    /// Whether `signature` is a valid signature over `message` by the public key encoded in
    /// `spki_der`. MUST return `false` — never panic — on a malformed key or signature.
    fn verify(&self, spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

impl<F> SignatureVerifier for F
where
    F: Fn(&[u8], &[u8], &[u8]) -> bool,
{
    fn verify(&self, spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
        self(spki_der, message, signature)
    }
}

/// Why a claim did not yield a payment address. Every variant means the same thing to a caller —
/// **there is no payee here** — and they differ only in what to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentClaimError {
    /// The entry carries no payment claim (the ordinary case for a peer predating SPEC §3.4).
    NotPresent,
    /// A field exceeded its cap, or `spki` / `sig` was not valid base64.
    Malformed,
    /// `SHA-256(spki)` did not equal the entry's `peer_id` — the claim belongs to a different peer,
    /// or was substituted by a relay.
    PeerIdMismatch,
    /// The key is the peer's, but the signature does not cover this `(peer_id, network_id, address)`
    /// — a tampered address, or a claim replayed from another network.
    BadSignature,
}

impl std::fmt::Display for PaymentClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            PaymentClaimError::NotPresent => "no payment claim on this entry",
            PaymentClaimError::Malformed => "payment claim is malformed or over its caps",
            PaymentClaimError::PeerIdMismatch => "payment claim key does not hash to peer_id",
            PaymentClaimError::BadSignature => "payment claim signature does not verify",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for PaymentClaimError {}

/// The exact bytes a peer signs to designate `address` as its payee (SPEC §3.4.1). Identical when
/// signing and when verifying — never construct these bytes anywhere else.
///
/// Binding all three of `peer_id`, `network_id` and `address` is what makes the signature
/// non-transferable: it cannot be lifted onto another peer's record, replayed onto another network,
/// or kept while the address underneath it is rewritten.
#[must_use]
pub fn payment_signing_bytes(peer_id: &str, network_id: &str, address: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        PAYMENT_SIG_CONTEXT.len() + 12 + peer_id.len() + network_id.len() + address.len(),
    );
    msg.extend_from_slice(PAYMENT_SIG_CONTEXT);
    for field in [peer_id, network_id, address] {
        // Length-prefixed so no two different field triples can produce identical bytes. A field
        // longer than u32::MAX is unrepresentable here and unreachable in practice — the caps in
        // this module bound every field to a few hundred bytes.
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(field.as_bytes());
    }
    msg
}

/// The `peer_id` a TLS SPKI induces — `SHA-256(SPKI DER)` as 64 lowercase hex characters, the same
/// derivation `dig-tls` performs on connect. This is the function that turns a carried key into a
/// checkable claim of identity.
#[must_use]
pub fn peer_id_for_spki(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// A peer's self-signed designation of where to pay it (SPEC §3.4).
///
/// The fields are **private on purpose**: the only way to read the address is
/// [`verify`](PaymentClaim::verify) (or [`PeerEntry::verified_payment_address`]), so it is not
/// possible to obtain a payee from this type without having checked it. An unverified payee has no
/// legitimate use, and a type that cannot hand one out cannot be misused into paying a thief.
///
/// [`PeerEntry::verified_payment_address`]: crate::PeerEntry::verified_payment_address
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentClaim {
    /// The claimed payee address (`address` on the wire).
    #[serde(default)]
    address: String,
    /// The peer's TLS SubjectPublicKeyInfo DER, base64 (`spki` on the wire). Hashes to `peer_id`.
    #[serde(default)]
    spki: String,
    /// The signature over [`payment_signing_bytes`], base64 (`sig` on the wire).
    #[serde(default)]
    sig: String,
}

impl PaymentClaim {
    /// A claim naming `address`, attested by the key in `spki_der` with `signature` over
    /// [`payment_signing_bytes`]. Producing `signature` is the caller's job — this crate holds no
    /// private keys and performs no signing.
    #[must_use]
    pub fn new(address: impl Into<String>, spki_der: &[u8], signature: &[u8]) -> Self {
        PaymentClaim {
            address: address.into(),
            spki: BASE64.encode(spki_der),
            sig: BASE64.encode(signature),
        }
    }

    /// The attesting key's SPKI DER, decoded. Empty when the field is not valid base64.
    ///
    /// Exposed for diagnostics and for re-assembling a claim in tests; reading the key is harmless,
    /// which is precisely why the *address* is not exposed the same way.
    #[must_use]
    pub fn spki_der(&self) -> Vec<u8> {
        BASE64.decode(&self.spki).unwrap_or_default()
    }

    /// The raw signature bytes, decoded. Empty when the field is not valid base64.
    #[must_use]
    pub fn signature(&self) -> Vec<u8> {
        BASE64.decode(&self.sig).unwrap_or_default()
    }

    /// The three wire fields in order, for the entry's advertised-content fingerprint (SPEC §9.1) —
    /// a re-signed or replaced claim must count as changed content so it re-advertises. Crate-private
    /// because handing out the address unchecked is exactly what this type prevents.
    pub(crate) fn wire_parts(&self) -> [&str; 3] {
        [&self.address, &self.spki, &self.sig]
    }

    /// Whether every field is within its cap (SPEC §3.4.2). Checked before any decoding so a hostile
    /// sender cannot make a receiver allocate on an oversized field.
    #[must_use]
    pub fn within_caps(&self) -> bool {
        self.address.len() <= PEX_MAX_PAYMENT_ADDRESS_LEN
            && self.spki.len() <= PEX_MAX_PAYMENT_SPKI_LEN
            && self.sig.len() <= PEX_MAX_PAYMENT_SIG_LEN
    }

    /// The payee address, **only** if this claim is genuinely the one `peer_id` made for
    /// `network_id` (SPEC §3.4.3).
    ///
    /// Three checks, in order, each of which a real attack fails: fields within caps and decodable;
    /// `SHA-256(spki) == peer_id`, so the key is this peer's and not a relay's; and the signature
    /// covering [`payment_signing_bytes`], so neither the address nor the network can be rewritten
    /// underneath it.
    pub fn verify(
        &self,
        peer_id: &str,
        network_id: &str,
        verifier: &impl SignatureVerifier,
    ) -> Result<&str, PaymentClaimError> {
        if !self.within_caps() {
            return Err(PaymentClaimError::Malformed);
        }
        let (Ok(spki_der), Ok(signature)) = (BASE64.decode(&self.spki), BASE64.decode(&self.sig))
        else {
            return Err(PaymentClaimError::Malformed);
        };
        if peer_id_for_spki(&spki_der) != peer_id {
            return Err(PaymentClaimError::PeerIdMismatch);
        }
        let message = payment_signing_bytes(peer_id, network_id, &self.address);
        if !verifier.verify(&spki_der, &message, &signature) {
            return Err(PaymentClaimError::BadSignature);
        }
        Ok(&self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verifier that accepts everything — used only to prove that the checks `dig-pex` performs
    /// ITSELF (caps, base64, the `peer_id` binding) hold even when the injected primitive is useless.
    struct AcceptAll;
    impl SignatureVerifier for AcceptAll {
        fn verify(&self, _spki: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
            true
        }
    }

    #[test]
    fn signing_bytes_are_domain_separated_and_length_prefixed() {
        let bytes = payment_signing_bytes("aa", "mainnet", "xch1");
        assert!(bytes.starts_with(PAYMENT_SIG_CONTEXT));
        assert_eq!(
            bytes,
            [
                PAYMENT_SIG_CONTEXT,
                &0u32.to_be_bytes()[..3],
                &[2],
                b"aa",
                &0u32.to_be_bytes()[..3],
                &[7],
                b"mainnet",
                &0u32.to_be_bytes()[..3],
                &[4],
                b"xch1",
            ]
            .concat()
        );
    }

    /// Length prefixes exist so that shifting a boundary between two fields cannot leave the byte
    /// stream unchanged — without them, `("ab", "c")` and `("a", "bc")` would sign identically and a
    /// claim could be re-framed onto a different peer.
    #[test]
    fn a_shifted_field_boundary_changes_the_signing_bytes() {
        assert_ne!(
            payment_signing_bytes("ab", "c", "x"),
            payment_signing_bytes("a", "bc", "x")
        );
    }

    #[test]
    fn peer_id_derivation_matches_sha256_of_spki() {
        // NIST SHA-256 of the empty input, as the fixed vector anchoring the hex encoding.
        assert_eq!(
            peer_id_for_spki(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(peer_id_for_spki(b"spki").len(), 64);
    }

    /// The `peer_id` binding is enforced by this crate, not by the injected verifier — so even a
    /// verifier that approves everything cannot make a foreign key name a payee.
    #[test]
    fn a_permissive_verifier_cannot_bypass_the_peer_id_binding() {
        let claim = PaymentClaim::new("xch1payee", b"some-other-key", b"whatever");
        assert_eq!(
            claim.verify(&"a".repeat(64), "mainnet", &AcceptAll),
            Err(PaymentClaimError::PeerIdMismatch)
        );
        // ...and with the matching peer_id it does yield, confirming the refusal above is the
        // binding rather than an unconditional rejection.
        assert_eq!(
            claim.verify(&peer_id_for_spki(b"some-other-key"), "mainnet", &AcceptAll),
            Ok("xch1payee")
        );
    }

    #[test]
    fn an_over_cap_or_undecodable_field_is_malformed() {
        let spki = b"key";
        let peer_id = peer_id_for_spki(spki);

        let long = PaymentClaim::new("x".repeat(PEX_MAX_PAYMENT_ADDRESS_LEN + 1), spki, b"s");
        assert_eq!(
            long.verify(&peer_id, "mainnet", &AcceptAll),
            Err(PaymentClaimError::Malformed)
        );

        // At the cap exactly, the same claim is accepted — a bound tested only from one side proves
        // only itself.
        let at_cap = PaymentClaim::new("x".repeat(PEX_MAX_PAYMENT_ADDRESS_LEN), spki, b"s");
        assert!(at_cap.verify(&peer_id, "mainnet", &AcceptAll).is_ok());

        let bad_b64: PaymentClaim =
            serde_json::from_str(r#"{"address":"xch1","spki":"!!!","sig":"AA=="}"#).unwrap();
        assert_eq!(
            bad_b64.verify(&peer_id, "mainnet", &AcceptAll),
            Err(PaymentClaimError::Malformed)
        );
    }

    #[test]
    fn wire_field_names_are_frozen() {
        let json = serde_json::to_string(&PaymentClaim::new("xch1", b"k", b"s")).unwrap();
        assert_eq!(json, r#"{"address":"xch1","spki":"aw==","sig":"cw=="}"#);
    }

    /// A closure is accepted wherever the trait is, so an embedder with a one-line verify does not
    /// need to declare a type.
    #[test]
    fn a_closure_is_a_verifier() {
        let claim = PaymentClaim::new("xch1", b"k", b"s");
        let peer_id = peer_id_for_spki(b"k");
        let never = |_: &[u8], _: &[u8], _: &[u8]| false;
        assert_eq!(
            claim.verify(&peer_id, "mainnet", &never),
            Err(PaymentClaimError::BadSignature)
        );
    }
}
