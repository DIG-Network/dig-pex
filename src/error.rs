//! The PEX error code space (SPEC §4.5) — the `code` carried by a [`pex_error`](crate::PexMessage)
//! message, and the reasons an inbound peer entry is skipped by receiver-side validation (SPEC §3.3).

/// The advisory `pex_error` code table (SPEC §4.5). `pex_error` is best-effort and never requires a
/// reply; a receiver sends it alongside discarding a bad message / muting a direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PexErrorCode {
    /// `1` — the message was not valid PEX JSON, or violated a structural MUST (e.g. a `peer_id`
    /// appearing in both `added` and `dropped`).
    BadMessage = 1,
    /// `2` — the handshake `version` is not supported by the receiver.
    UnsupportedVersion = 2,
    /// `3` — data messages arrived faster than the enforced minimum interval (SPEC §6.4).
    RateViolation = 3,
    /// `4` — a frame exceeded `PEX_MAX_FRAME`, or a list exceeded its cap (SPEC §7).
    Oversized = 4,
    /// `5` — the handshake `network_id` differs from the receiver's.
    NetworkMismatch = 5,
    /// `6` — a state-machine violation (SPEC §5.3): data before handshake, a second snapshot, or a
    /// delta before the snapshot.
    ProtocolViolation = 6,
}

impl PexErrorCode {
    /// The numeric code as it appears on the wire.
    #[must_use]
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// A short, stable human-readable message for the `pex_error.message` field.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            PexErrorCode::BadMessage => "bad message",
            PexErrorCode::UnsupportedVersion => "unsupported version",
            PexErrorCode::RateViolation => "rate violation",
            PexErrorCode::Oversized => "oversized",
            PexErrorCode::NetworkMismatch => "network mismatch",
            PexErrorCode::ProtocolViolation => "protocol violation",
        }
    }

    /// Whether this code represents peer **misbehavior** that counts a strike toward muting (SPEC
    /// §11.2): bad-message (`1`), rate (`3`), oversize (`4`), and protocol (`6`). Version (`2`) and
    /// network (`5`) mismatch mute the direction immediately but are NOT misbehavior — the peer is
    /// simply on a different version/network, and the underlying connection MUST NOT be torn down
    /// for that reason alone (SPEC §5.2).
    #[must_use]
    pub fn is_strike(self) -> bool {
        matches!(
            self,
            PexErrorCode::BadMessage
                | PexErrorCode::RateViolation
                | PexErrorCode::Oversized
                | PexErrorCode::ProtocolViolation
        )
    }
}

/// Why a single inbound peer entry was skipped by receiver-side validation (SPEC §3.3). Skipping is
/// silent — no `pex_error`, no strike; entry-level junk is expected from honest-but-stale peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrySkip {
    /// `peer_id` is not exactly 64 lowercase hex characters.
    BadPeerId,
    /// `peer_id` equals the receiver's own or the sender's `peer_id` (SPEC §5.4).
    SelfOrPartner,
    /// An address has an empty `host`, a `port` of 0, or an unrecognized `kind` token.
    BadAddress,
    /// `addresses` has more than `PEX_MAX_ADDRESSES` elements.
    TooManyAddresses,
    /// `flags` has more than `PEX_MAX_FLAGS` elements (or a token over `PEX_MAX_FLAG_LEN` chars).
    TooManyFlags,
    /// `network_id` differs from the link's network.
    NetworkMismatch,
    /// `via` is not one of the three registered provenance tokens.
    BadVia,
    /// `last_seen` is more than `PEX_MAX_ENTRY_AGE` seconds in the past by the receiver's clock.
    TooOld,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_spec_table() {
        assert_eq!(PexErrorCode::BadMessage.as_u16(), 1);
        assert_eq!(PexErrorCode::UnsupportedVersion.as_u16(), 2);
        assert_eq!(PexErrorCode::RateViolation.as_u16(), 3);
        assert_eq!(PexErrorCode::Oversized.as_u16(), 4);
        assert_eq!(PexErrorCode::NetworkMismatch.as_u16(), 5);
        assert_eq!(PexErrorCode::ProtocolViolation.as_u16(), 6);
    }

    #[test]
    fn strike_classification() {
        assert!(PexErrorCode::BadMessage.is_strike());
        assert!(PexErrorCode::RateViolation.is_strike());
        assert!(PexErrorCode::Oversized.is_strike());
        assert!(PexErrorCode::ProtocolViolation.is_strike());
        assert!(!PexErrorCode::UnsupportedVersion.is_strike());
        assert!(!PexErrorCode::NetworkMismatch.is_strike());
    }

    #[test]
    fn messages_are_stable() {
        assert_eq!(PexErrorCode::RateViolation.message(), "rate violation");
    }
}
