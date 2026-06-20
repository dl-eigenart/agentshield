# Changelog

## [2.0.0] — 2026-06-21

### Changed

- **Evaluation claims retracted and replaced.** Previous releases (2.0.0-rc1, 2.0.0-rc2) cited a "190/190 (100%) — zero bypasses, zero false positives" internal evaluation in README and package metadata. That number was not from a reproducible, properly-held-out evaluation and has been retracted. The canonical AgentShield benchmark is now hosted at [agentshield.pro/benchmark](https://agentshield.pro/benchmark): 5,972 samples across six public prompt-injection datasets, F1 0.956 headline (5 datasets) / 0.921 full set (6 datasets), per-sample false-positive / false-negative lists published. The Python implementation of the six-layer architecture is what was actually evaluated. Solana / ElizaOS-specific re-evaluation against the same benchmark + Web3-relevant attack patterns is in progress.
- README and package description rewritten for accuracy and to cross-reference the platform.
- Fixed install command typo (`@eigentart/agentshield` → `@eigenart/agentshield`).
- Repository homepage updated to [agentshield.pro](https://agentshield.pro).
- Bugs URL corrected to the actual repository path.

### Notes

- No code changes vs 2.0.0-rc2. This release is a documentation/metadata correction. Functional behavior of all six layers (L0–L5) and the on-chain transaction proxy is unchanged.
- Solana-specific evaluation results, when available, will be linked from this changelog and the README.

## [2.0.0-rc2] — 2026-03-25

> **Note:** the "190/190 (100%)" evaluation claim in this release has been retracted in 2.0.0. See above.

### Highlights

- Six-layer defense architecture fully operational (L0–L5)
- On-chain transaction proxy deployed to Solana Devnet

### Added

- **L2: Binary Classification Head v3** — MLP (384→128→2) trained on 184 samples with noise augmentation, replacing fragile margin-based cosine similarity
- **L2: Language-detection routing** — Unicode script analysis for non-Latin text with LLM-as-judge escalation (Ollama qwen3:8b)
- **L2: Question-form safety net** — Post-classification heuristic that rescues benign single-sentence questions from FINANCIAL_MANIPULATION false positives
- **L2: Multi-language attack coverage** — DE, VI, RU, JA, KO, AR social engineering and financial manipulation variants
- **L4B: Solana Transaction Proxy** — Anchor program with PDA-based queue, oracle workflow, daily limits, on-chain circuit breaker
- **L5: Merkle root anchoring on Solana** — Memo v2 program for tamper-proof audit trail
- **L5: Metrics dashboard** — Chart.js with 6 KPIs, 4 charts, live event stream

### Security

- Fixed: German Finanzamt social engineering bypass
- Fixed: Vietnamese admin impersonation bypass
- Fixed: Japanese educational false positive (staking question)
- Fixed: "Total value locked" exfiltration false positive
- Fixed: "Minimum amount to send" financial manipulation false positive

## [2.0.0-rc1] — 2026-03-24

### Added

- **L2: Fine-tuned embedding model** (agentshield-minilm-v1) — contrastive learning on 9,980 samples
- **L2: Keyword heuristic** for multi-part compound attack detection
- **L4B: Solana Transaction Proxy** (Anchor/Rust) — 10/10 on-chain tests passing
- **L5: Chart.js dashboard** with live updates

## [2.0.0-beta] — 2026-03-23

### Added

- L0: Input Normalization (NFKC, homoglyph, Base64, leetspeak)
- L1: Pattern Registry (36 patterns, 5 languages, CRUD, versioning)
- L2: Heuristic semantic classifier
- L3: Output Guard (key/seed/JWT detection, post-block compliance)
- L4A: Response Interceptor + Circuit Breaker
- L5: Merkle Audit Trail + Alert Manager
- 206 tests (196 TypeScript + 10 Anchor on-chain)

## [2.0.0-alpha] — 2026-03-22

### Added

- Initial ElizaOS v2 plugin scaffold
- Memory Guard with injection detection
- Transaction Guard with policy enforcement
- Anomaly Detector with z-score analysis
