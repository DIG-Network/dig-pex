//! Timing math (SPEC §6) — interval negotiation, the sender's effective interval + additive jitter,
//! and the receiver's anti-flood minimum inter-arrival floor.
//!
//! All engine timestamps are **Unix epoch milliseconds** (`now_ms`); the protocol's interval
//! constants are seconds, converted here. Keeping the timing pure + separately testable is what makes
//! the receiver's enforcement (SPEC §6.4) exact: a sender's jitter is **additive only**, so a
//! conformant sender never sends earlier than its effective interval, and the receiver's floor can be
//! a hard discard.

use rand::Rng;

use crate::caps::{PEX_ARRIVAL_GRACE, PEX_MAX_INTERVAL, PEX_MIN_INTERVAL};

/// Clamp a declared interval (seconds) into the legal `[PEX_MIN_INTERVAL, PEX_MAX_INTERVAL]` range
/// (SPEC §6.2). Both a sender's own declaration and a remote's declaration are clamped for use.
#[must_use]
pub fn clamp_interval(secs: u32) -> u32 {
    secs.clamp(PEX_MIN_INTERVAL, PEX_MAX_INTERVAL)
}

/// A sender's **effective interval** (seconds) — the minimum spacing it must honor for its own data
/// messages (SPEC §6.2): `max(own declared, remote declared once known, PEX_MIN_INTERVAL)`. The
/// remote's declaration is a floor ("don't tell me more often than this") once its handshake arrives.
#[must_use]
pub fn effective_interval_secs(own_declared: u32, remote_declared: Option<u32>) -> u32 {
    let own = clamp_interval(own_declared);
    let remote = remote_declared.map_or(0, clamp_interval);
    own.max(remote).max(PEX_MIN_INTERVAL)
}

/// The receiver's minimum inter-arrival floor in **milliseconds** for data messages, given the
/// sender's handshake-declared `interval` (SPEC §6.4): `max(declared, PEX_MIN_INTERVAL) −
/// PEX_ARRIVAL_GRACE`, in ms. A data message arriving less than this after the previous one is a
/// rate violation.
#[must_use]
pub fn arrival_floor_ms(remote_declared: u32) -> u64 {
    let declared = clamp_interval(remote_declared).max(PEX_MIN_INTERVAL);
    u64::from(declared - PEX_ARRIVAL_GRACE) * 1000
}

/// Additive send jitter in **milliseconds**: a uniformly random `0..=10%` of the effective interval
/// (SPEC §6.3), to decorrelate network-wide ticks. Additive only — a sender MUST NOT send *earlier*
/// than its effective interval.
#[must_use]
pub fn jitter_ms(effective_secs: u32) -> u64 {
    // 10% of `effective_secs` seconds, in ms = effective_secs * 1000 * 0.10 = effective_secs * 100.
    let span = u64::from(effective_secs) * 100;
    if span == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..=span)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_into_range() {
        assert_eq!(clamp_interval(0), PEX_MIN_INTERVAL);
        assert_eq!(clamp_interval(29), 30);
        assert_eq!(clamp_interval(60), 60);
        assert_eq!(clamp_interval(4000), PEX_MAX_INTERVAL);
    }

    #[test]
    fn effective_is_max_of_own_remote_and_floor() {
        // Own only, before the remote handshake: max(own, 30).
        assert_eq!(effective_interval_secs(60, None), 60);
        assert_eq!(effective_interval_secs(10, None), 30); // clamped up to the floor
                                                           // Remote declares a larger interval → it becomes the floor.
        assert_eq!(effective_interval_secs(60, Some(120)), 120);
        // Remote declares a smaller one → own still governs.
        assert_eq!(effective_interval_secs(120, Some(45)), 120);
    }

    #[test]
    fn arrival_floor_is_declared_minus_grace() {
        // 60 s declared → (60 − 5) * 1000 ms.
        assert_eq!(arrival_floor_ms(60), 55_000);
        // 30 s (the floor) → (30 − 5) * 1000.
        assert_eq!(arrival_floor_ms(30), 25_000);
        // A sub-floor declaration is clamped up to 30 first.
        assert_eq!(arrival_floor_ms(1), 25_000);
    }

    #[test]
    fn jitter_is_additive_and_bounded() {
        for _ in 0..1000 {
            let j = jitter_ms(60);
            assert!(
                j <= 6000,
                "jitter must be <= 10% of 60 s = 6000 ms, got {j}"
            );
        }
    }
}
