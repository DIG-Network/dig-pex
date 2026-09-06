# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.2.0] - 2026-08-19

### Features
- **payment:** Optional self-signed payment address on `PeerEntry` (SPEC 3.4), so the incentive
  layer can address $DIG to the peer that earned it. The claim carries the peer's TLS SPKI DER and a
  signature over domain-separated, length-prefixed bytes binding `peer_id`, `network_id` and the
  address; a verifier recomputes `SHA-256(SPKI) == peer_id`, so the record proves itself with no
  lookup. Optional and serde-defaulted — records without it decode unchanged.
- **engine:** Snapshots are now bounded by encoded bytes as well as entry count, so a sender never
  emits a frame over `PEX_MAX_FRAME` (200 maximal signed entries would have been ~281 KB against a
  256 KiB cap).

### Notes
- New public API: `PaymentClaim`, `PaymentClaimError`, `SignatureVerifier`, `payment_signing_bytes`,
  `peer_id_for_spki`, three payment caps, and `EntrySkip::OversizePayment`. Additive.

## [0.1.2] - 2026-09-04

### Documentation
- Add CONTRIBUTING.md (#3)

## [0.1.1] - 2026-07-12

### Bug Fixes
- **deps:** Re-resolve DIG git deps to rewritten (co-author/signed) revs

### CI
- Re-arm crates.io auto-publish on version tag (token in org secrets; auto-publish-everything #230)- Add flaky-test management (#489) (#1)

## [0.1.0] - 2026-07-04

### Security
- Normative PEX protocol SPEC

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation (git-cliff changelog + tag on merge); publish is manual workflow_dispatch (#230)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog

### Dig-pex
- Implement the PEX protocol engine to SPEC (wire version 1)- End-to-end conformance suite pinning SPEC §12 (PEX-01..PEX-14)- CI — gates + coverage (ci.yml) and tag-driven publish (publish.yml)
