//! The PEX wire — the four `type`-tagged JSON messages (SPEC §4) and their framing.
//!
//! ## The four messages
//!
//! | `type` | Purpose |
//! |---|---|
//! | `pex_handshake` | first message each direction: version + network + declared interval + own flags (§4.2) |
//! | `pex_snapshot` | the first data message: a capped picture of the sender's first-hand set (§4.3) |
//! | `pex_delta` | the periodic message: `added` / `dropped` relative to what this link was told (§4.4) |
//! | `pex_error` | the advisory error envelope (§4.5) |
//!
//! ## Framing (SPEC §4.1)
//!
//! - **Byte stream** (node↔node, §10.1): [`PexMessage::encode`] / [`PexMessage::decode`] frame each
//!   message as a **`u32` big-endian length prefix + JSON body** — byte-identical to the dig-nat /
//!   dig-dht wires. A length prefix over [`crate::caps::PEX_MAX_FRAME`] is rejected
//!   without allocating the body.
//! - **Relay WebSocket** (relay→node, §10.2): [`PexMessage::to_json`] / [`PexMessage::from_json`]
//!   carry the bare JSON object in one WebSocket text frame (the socket already delimits messages).
//!
//! JSON shapes are **frozen**: the `type` tags and field names are the wire contract, and unknown
//! fields are ignored on receive (additive evolution).

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::caps::PEX_MAX_FRAME;
use crate::entry::PeerEntry;

/// A PEX protocol message — one of the four `type`-tagged shapes (SPEC §4). The `type` tag and field
/// names are the frozen wire contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PexMessage {
    /// The first PEX message a participant sends on a link, in each direction, before anything else
    /// (SPEC §4.2). Declares the wire `version`, the sender's `network_id`, its minimum send
    /// `interval` (seconds), and its own capability `flags`.
    PexHandshake {
        /// The PEX wire version the sender speaks (this crate: `1`).
        version: u32,
        /// The sender's network. MUST match the receiver's.
        network_id: String,
        /// Seconds — the sender's declared minimum spacing between its own data messages. MUST be
        /// within `[30, 3600]`; a receiver clamps out-of-range values for enforcement.
        interval: u32,
        /// The sender's own capability flags (optional; defaults to empty).
        #[serde(default)]
        flags: Vec<String>,
    },
    /// The first **data message** in a direction — a fuller, capped picture of the sender's
    /// first-hand known-peer set, so a fresh link warms up in one message (SPEC §4.3). Exactly one
    /// per direction per link.
    PexSnapshot {
        /// The sender's first-hand peers (MAY be empty; at most `PEX_MAX_SNAPSHOT`, freshest-first).
        peers: Vec<PeerEntry>,
    },
    /// The periodic message: what changed in the sender's first-hand set **relative to what this link
    /// has already been told** (SPEC §4.4). A delta with both arrays empty MUST NOT be sent.
    PexDelta {
        /// Newly-known entries, or already-told entries whose advertised content changed (an update
        /// replaces the previous entry). At most `PEX_MAX_ADDED`.
        added: Vec<PeerEntry>,
        /// `<64hex>` peer ids the sender no longer considers good (SPEC §8.3). At most
        /// `PEX_MAX_DROPPED`. Advisory — a receiver never deletes a first-hand-verified peer on it.
        dropped: Vec<String>,
    },
    /// The advisory error envelope, either direction (SPEC §4.5). Best-effort; never requires a reply.
    PexError {
        /// A stable error code (SPEC §4.5 table).
        code: u16,
        /// A human-readable message.
        message: String,
    },
}

impl PexMessage {
    /// Serialize as a `u32` big-endian length prefix + JSON body — the byte-stream framing (§4.1).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body = self.to_json_bytes();
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Read + decode one framed message from `r`, bounded by [`PEX_MAX_FRAME`]. A length prefix over
    /// the bound errors **before** allocating or reading the body (SPEC §4.1, §7.2).
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > PEX_MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pex frame too large",
            ));
        }
        let mut body = vec![0u8; len];
        r.read_exact(&mut body).await?;
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// The bare JSON object as a string — the relay WebSocket text-frame form (§4.1, §10.2).
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("pex message serializes")
    }

    /// The bare JSON object as bytes.
    #[must_use]
    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("pex message serializes")
    }

    /// Parse a bare JSON object (the relay WebSocket text-frame form). An `Err` here is a
    /// `PEX_BAD_MESSAGE` (SPEC §7.3) the caller strikes.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// The message's `type` tag string (`"pex_handshake"` | `"pex_snapshot"` | `"pex_delta"` |
    /// `"pex_error"`).
    #[must_use]
    pub fn type_tag(&self) -> &'static str {
        match self {
            PexMessage::PexHandshake { .. } => "pex_handshake",
            PexMessage::PexSnapshot { .. } => "pex_snapshot",
            PexMessage::PexDelta { .. } => "pex_delta",
            PexMessage::PexError { .. } => "pex_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::PEX_VERSION;
    use crate::entry::{Address, PeerEntry, Provenance};
    use std::io::Cursor;

    fn hex(b: u8) -> String {
        format!("{b:02x}").repeat(32)
    }

    fn sample_entry() -> PeerEntry {
        PeerEntry::new(hex(0x07), "mainnet", 1_719_763_200, Provenance::Direct)
            .with_address(Address::direct("203.0.113.7", 9444))
            .with_flag("storage")
    }

    #[test]
    fn handshake_frozen_shape() {
        let m = PexMessage::PexHandshake {
            version: PEX_VERSION,
            network_id: "mainnet".into(),
            interval: 60,
            flags: vec!["storage".into(), "holepunch".into()],
        };
        let s = m.to_json();
        assert!(s.contains("\"type\":\"pex_handshake\""));
        assert!(s.contains("\"version\":1"));
        assert!(s.contains("\"network_id\":\"mainnet\""));
        assert!(s.contains("\"interval\":60"));
        assert!(s.contains("\"flags\":[\"storage\",\"holepunch\"]"));
    }

    #[test]
    fn snapshot_frozen_shape() {
        let m = PexMessage::PexSnapshot {
            peers: vec![sample_entry()],
        };
        let s = m.to_json();
        assert!(s.contains("\"type\":\"pex_snapshot\""));
        assert!(s.contains("\"peers\":["));
    }

    #[test]
    fn delta_frozen_shape() {
        let m = PexMessage::PexDelta {
            added: vec![sample_entry()],
            dropped: vec![hex(0x09)],
        };
        let s = m.to_json();
        assert!(s.contains("\"type\":\"pex_delta\""));
        assert!(s.contains("\"added\":["));
        assert!(s.contains("\"dropped\":["));
    }

    #[test]
    fn error_frozen_shape() {
        let m = PexMessage::PexError {
            code: 3,
            message: "rate violation".into(),
        };
        let s = m.to_json();
        assert_eq!(
            s,
            r#"{"type":"pex_error","code":3,"message":"rate violation"}"#
        );
    }

    #[test]
    fn all_messages_round_trip_through_json() {
        for m in [
            PexMessage::PexHandshake {
                version: 1,
                network_id: "mainnet".into(),
                interval: 60,
                flags: vec!["storage".into()],
            },
            PexMessage::PexSnapshot {
                peers: vec![sample_entry()],
            },
            PexMessage::PexDelta {
                added: vec![sample_entry()],
                dropped: vec![hex(0x09)],
            },
            PexMessage::PexError {
                code: 6,
                message: "protocol violation".into(),
            },
        ] {
            let back = PexMessage::from_json(&m.to_json()).unwrap();
            assert_eq!(m, back);
        }
    }

    #[tokio::test]
    async fn framed_round_trip() {
        let m = PexMessage::PexSnapshot {
            peers: vec![sample_entry()],
        };
        let bytes = m.encode();
        // u32-BE length prefix.
        let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(declared, bytes.len() - 4);
        let mut cur = Cursor::new(bytes);
        let back = PexMessage::decode(&mut cur).await.unwrap();
        assert_eq!(m, back);
    }

    #[tokio::test]
    async fn oversize_length_prefix_rejected_before_body() {
        let mut buf = ((PEX_MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(b"{}");
        let mut cur = Cursor::new(buf);
        let err = PexMessage::decode(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_frame_errors() {
        let mut buf = 100u32.to_be_bytes().to_vec();
        buf.extend_from_slice(b"{}");
        let mut cur = Cursor::new(buf);
        assert!(PexMessage::decode(&mut cur).await.is_err());
    }

    #[test]
    fn unknown_fields_ignored_on_receive() {
        // Additive evolution: a future field must not break a v1 decoder (SPEC §2, §4.1).
        let s = r#"{"type":"pex_handshake","version":1,"network_id":"mainnet","interval":60,"future":42}"#;
        let m = PexMessage::from_json(s).unwrap();
        assert_eq!(m.type_tag(), "pex_handshake");
    }

    #[test]
    fn unknown_type_tag_is_error() {
        assert!(PexMessage::from_json(r#"{"type":"pex_bogus"}"#).is_err());
    }

    #[test]
    fn missing_required_field_is_error() {
        // A snapshot missing `peers` is a malformed message (SPEC §7.3), not an empty snapshot.
        assert!(PexMessage::from_json(r#"{"type":"pex_snapshot"}"#).is_err());
    }
}
