# Changelog

## [2.0.0-rc2] — 2026-03-25

### Highlights
- **190/190 (100%)** on independent evaluation — zero bypasses, zero false positives
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
