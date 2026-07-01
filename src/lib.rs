//! # dig-pex — Peer Exchange (PEX) for the DIG Node peer network
//!
//! PEX lets a participant that already holds an **authenticated** link to another participant tell
//! it, incrementally, which peers it knows **first-hand** — so the network's address books stay warm
//! without polling and without a central directory. It adapts the proven mechanics of BitTorrent PEX
//! (`ut_pex`): peers exchange **deltas of their first-hand known-peer set** over already-established
//! connections, on a bounded periodic cadence, with hard per-message caps and **no third-party
//! re-flooding**. This crate is the normative implementation of `SPEC.md` (wire version `1`).
//!
//! PEX runs in exactly two places (SPEC §1.1):
//!
//! 1. **Node ↔ Node** — over the mutual-TLS dig-nat mux stream transport ([`PexMessage::encode`] /
//!    [`PexMessage::decode`], a u32-BE length prefix + JSON body).
//! 2. **Relay → Node** — by the `dig-relay` introducer, riding the existing `RelayMessage`
//!    WebSocket (RLY-008) as bare JSON text frames ([`PexMessage::to_json`] /
//!    [`PexMessage::from_json`]).
//!
//! ## What it is *not* (SPEC §1.3)
//!
//! - **Not a trust channel.** Every received entry is a *hint* — a candidate to dial and verify via
//!   the mTLS handshake, never an authenticated fact ([`PexEvent::Candidates`]).
//! - **Not a gossip flood.** A participant advertises only what it knows **first-hand**; the
//!   [`Provenance`] type has no `"pex"` token, so a PEX-learned entry can never be re-advertised
//!   until independently verified.
//! - **Not content discovery.** Locating which peers hold content is the DHT's job (`dig-dht`); PEX
//!   populates the pool of dialable peers underneath it.
//!
//! ## The engine (SPEC Appendix A)
//!
//! The crate ships a transport-agnostic, **sans-IO** [`PexEngine`]: you feed it link events, inbound
//! messages, local peer-set changes, and clock ticks; it returns the messages to send and the events
//! to act on. Both a DIG Node and the relay embed the same engine — only the I/O adapter differs.
//!
//! ```
//! use dig_pex::{PexConfig, PexEngine, PexMessage, PeerEntry, Provenance, Address};
//!
//! let me = "a".repeat(64);
//! let peer = "b".repeat(64);
//! let mut engine = PexEngine::new(PexConfig::new(me, "mainnet").with_jitter(false));
//!
//! // A first-hand peer we know enters our advertise set.
//! engine.upsert_known(
//!     PeerEntry::new("c".repeat(64), "mainnet", 1_000, Provenance::Direct)
//!         .with_address(Address::direct("203.0.113.7", 9444)),
//! );
//!
//! // A link comes up → we emit our handshake + a snapshot of our first-hand set.
//! let out = engine.link_up(&peer, 1_000_000);
//! assert!(matches!(out[0], PexMessage::PexHandshake { .. }));
//! assert!(matches!(out[1], PexMessage::PexSnapshot { .. }));
//! ```
//!
//! ### DIG Node embedding (node↔node, SPEC §10.1)
//!
//! On each established peer connection call [`PexEngine::link_up`] and write the returned frames on a
//! freshly opened mux stream (that stream is your sending direction). Feed each decoded inbound
//! message to [`PexEngine::on_message`]; send its replies and honor a muting
//! [`PexEvent::Violation`]. Drive [`PexEngine::tick`] ~1/s and write the returned deltas. Feed
//! first-hand knowledge back with [`PexEngine::upsert_known`] / [`PexEngine::remove_known`], and on
//! close call [`PexEngine::link_down`]. Route [`PexEvent::Candidates`] into the dig-gossip
//! `AddressManager` as new-table candidates to dial + verify (SPEC §9.3).
//!
//! ### dig-relay embedding (relay→node, SPEC §10.2)
//!
//! Create one engine for the introducer role (flags `["introducer"]`). Only after a registered
//! connection sends its `pex_handshake` do you [`PexEngine::link_up`] + [`PexEngine::on_message`] and
//! reply as WebSocket text frames. Mirror the registry into the engine
//! ([`PexEngine::upsert_known`] on register, [`PexEngine::remove_known`] on unregister); **never**
//! fold inbound node PEX data into the registry — discard node-sent [`PexEvent::Candidates`] (the
//! registry is registration-backed only, SPEC §10.2).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod caps;
pub mod engine;
pub mod entry;
pub mod error;
pub mod state;
pub mod timer;
pub mod wire;

pub use caps::{
    PEX_ARRIVAL_GRACE, PEX_DEFAULT_INTERVAL, PEX_MAX_ADDED, PEX_MAX_ADDRESSES, PEX_MAX_DROPPED,
    PEX_MAX_ENTRY_AGE, PEX_MAX_FLAGS, PEX_MAX_FLAG_LEN, PEX_MAX_FRAME, PEX_MAX_INTERVAL,
    PEX_MAX_SNAPSHOT, PEX_MIN_INTERVAL, PEX_VERSION, PEX_VIOLATION_LIMIT,
};
pub use engine::{PexConfig, PexEngine, PexEvent, PexOutcome};
pub use entry::{Address, AddressKind, PeerEntry, Provenance, ValidateCtx};
pub use error::{EntrySkip, PexErrorCode};
pub use state::{LinkState, RecvPhase};
pub use wire::PexMessage;
