# 📋 Changelog (`metaforge`)

All notable changes to **MetaForge** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-11-07

### Architectural Ground-Floor Rebuild (`SOVEREIGN-CHANGELOG-E2E-01`)

- **`[Protocol]` & `[Crucible/TDD]` C2PA / JUMBF Provenance & AI Generation Footprint Harvester + Signature Flood Clamping (`metaforge-forensics`)**:
  - **Root Cause Dissection**: In `v0.2.0`, `scan_embedded_payloads` detected classic polyglots (ZIP, PE, ELF, PDF, PHP, `<script`) but did not flag modern C2PA / ISO 19566-5 JUMBF provenance manifests (`c2pa`, `jumb`, `c2ma`) or embedded AI diffusion workflow footprints (`ComfyUI`, `Negative prompt:`), and lacked an upper bound on accumulated `Vec<EmbeddedPayload>` entries when scanning adversarially crafted buffers containing thousands of repeated short magic patterns (`eval(`).
  - **Architectural & Mathematical Resolution**:
    1. Expanded `PATTERNS` in `metaforge-forensics::signatures` to detect `c2pa` (C2PA Content Provenance JUMBF Manifest), `jumb` (ISO 19566-5 JUMBF Provenance Box), `c2ma` (C2PA Claim Manifest Assertion), and AI diffusion workflow footprints (`prompt`, `Negative prompt:`, `ComfyUI`).
    2. Enforced `MAX_PAYLOAD_MATCHES = 256` in `scan_embedded_payloads` to guarantee bounded $O(1)$ output vector allocation against signature-flood bombs.
  - **Empirical Verification**: Verified via `crates/metaforge-forensics/tests/adversarial_c2pa_and_flood_tests.rs`.

---

## [0.2.0] - 2026-09-27

### Added
- 7-crate OJP media forensics, statistical steganalysis (Shannon entropy, Chi-Square uniformity, Pairs-of-Values LSB detection), lossless EXIF/GPS privacy scrubbing, and pure-Rust image/audio transcoding engine.
