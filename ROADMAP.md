# AgentShield v2 — Production Readiness Roadmap

**Status:** Active Development — all six layers implemented, hardening phase
**Last Updated:** 2026-03-24
**Maintainer:** Daniel Leonforte / Eigenart Filmproduktion
**Repository:** plugin-agentshield

---

## Current State (v2.0.0-beta)

AgentShield provides a six-layer defense architecture for ElizaOS v2 agents on Solana.
196 unit tests pass across 10 test files. All six layers implemented and functional.
5/5 CrAIBench attack vectors detected. 0 false positives on benign messages.
Multi-language coverage: EN, DE, ES, ZH, FR.

**Resolved Weaknesses:**

- ~~Unicode homoglyph bypass~~ → Fixed by L0 NFKC + homoglyph mapping
- ~~Base64/encoded payloads not decoded~~ → Fixed by L0 encoding detection
- ~~No output guard~~ → Fixed by L3 Output Guard (key leakage, seed phrases, JWT, post-block compliance)
- ~~No real blocking~~ → Fixed by L4A Response Interceptor + Circuit Breaker
- ~~Single-language patterns~~ → Fixed by L1 Pattern Registry (5 languages)

**Remaining Weaknesses:**

- Semantic rephrasing bypasses regex patterns → Requires L2 ONNX model (heuristic scaffold in place)
- Open-source patterns readable by attackers → Mitigated by L2 embedding classifier
- No on-chain transaction proxy → Requires L4B Solana program
- No real-time metrics dashboard → Requires L5 dashboard build
- Merkle roots not yet anchored on Solana → Requires Solana integration

---

## Architecture: Six-Layer Defense

```
┌─────────────────────────────────────────────────────────────┐
│  Incoming Message                                           │
├─────────────────────────────────────────────────────────────┤
│  Layer 0: Input Normalization          (~0.1ms)    ✅ DONE  │
│  ├── Unicode NFKC normalization                             │
│  ├── Homoglyph → ASCII mapping (460+ confusables)          │
│  ├── Zero-width character stripping                         │
│  ├── Base64 / hex / URL-encoded payload decode              │
│  ├── Leetspeak normalization (Solana address-aware)         │
│  └── Whitespace & control character cleanup                 │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Fast Pattern Guard           (~0.05ms)   ✅ DONE  │
│  ├── Configurable Pattern Registry (JSON, CRUD, versioned) │
│  ├── 36 built-in patterns across 5 languages               │
│  ├── Financial instruction detection                        │
│  ├── System override / identity hijack detection            │
│  ├── Wallet priming detection                               │
│  └── Multi-language: EN, DE, ES, ZH, FR                    │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Semantic Classifier          (~6-23ms)   ✅ DONE  │
│  ├── Heuristic intent scoring (20 weighted signals)        │
│  ├── IntentCategory taxonomy (5 categories)                 │
│  ├── ✅ GPU embedding (all-MiniLM-L6-v2, agents-pc:8810)  │
│  ├── ✅ LLM-as-judge escalation (Ollama qwen3:8b)          │
│  └── 🔲 Fine-tuned classifier on CrAIBench + custom data   │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Output Guard                 (~0.5ms)    ✅ DONE  │
│  ├── Solana/ETH private key detection (base58 + hex)       │
│  ├── BIP39 seed phrase detection (200-word sample)          │
│  ├── JWT/API key leak detection                             │
│  ├── Post-block compliance checking                         │
│  ├── Instruction echo detection                             │
│  └── Response sanitization & redaction                      │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Runtime Enforcement                      ✅ DONE  │
│  ├── ✅ Response Interceptor (hard block, denial templates) │
│  ├── ✅ Circuit Breaker (restricted/lockdown/freeze modes)  │
│  ├── ✅ Solana Transaction Proxy (Anchor, 10 tests)         │
│  └── 🔲 Multi-sig escalation for high-value operations      │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Observability & Alerting                 ✅ DONE  │
│  ├── ✅ Merkle Audit Trail (SHA-256, checkpoints)           │
│  ├── ✅ Alert Manager (Slack/Telegram/Discord/webhook)      │
│  ├── ✅ Metrics dashboard (Chart.js, live updates)          │
│  ├── ✅ Merkle root anchoring on Solana (Memo v2)           │
│  └── 🔲 Anomaly trend analysis with auto-escalation         │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer 0: Input Normalization — ✅ COMPLETE

**Status:** Done — 36 tests passing
**Files:** `src/normalizers/input-normalizer.ts`, `tests/input-normalizer.test.ts`

Implemented pipeline:

1. **Unicode NFKC Normalization** — Cyrillic "а" → Latin "a", fullwidth → ASCII
2. **Confusable/Homoglyph Map** — 460+ mappings covering Cyrillic, Greek, mathematical symbols
3. **Zero-Width & Invisible Character Stripping** — U+200B, U+200C/D, U+FEFF, U+00AD, Cf category
4. **Encoding Detection & Decode** — Base64 (≥20 chars), hex (0x prefix), URL-encoded (2+ sequences), Unicode escapes
5. **Leetspeak Normalization** — 1→i, 0→o, @→a, 3→e, $→s; Solana address detection (32-44 base58 chars) to skip
6. **Control Character & Whitespace Normalization** — Collapse whitespace, strip control chars

All 4 original bypass vectors resolved at L0+L1 level.

---

## Layer 1: Fast Pattern Guard — ✅ COMPLETE

**Status:** Done — 24 tests passing (+ 45 memory-guard tests)
**Files:** `src/config/pattern-registry.ts`, `src/guards/memory-guard.ts`, `tests/pattern-registry.test.ts`

Implemented:

1. **Configurable Pattern Registry** — PatternDefinition interface, JSON serialization, CRUD (add/remove/update), immutable operations with version bumping, hot-reload ready
2. **36 Built-in Patterns** — 16 EN, 7 DE, 5 ES, 4 ZH, 4 FR covering override, injection, financial, exfiltration, wallet_priming, social_engineering categories
3. **Wallet Priming Detection** — "remember this wallet", "use this address", address assignment patterns
4. **Language Filtering** — Match with `{ language: 'en' }` option to restrict to specific language

---

## Layer 2: Semantic Classifier — ⚠️ SCAFFOLD (heuristic only)

**Status:** Heuristic scoring implemented (8 tests passing), ML models pending
**Files:** `src/classifiers/semantic-classifier.ts`, `tests/semantic-classifier.test.ts`

### What's Done

- IntentCategory taxonomy: benign, injection, exfiltration, social_engineering, financial_manipulation
- 20 weighted keyword-based intent signals for heuristic scoring
- Three-tier architecture with placeholder hooks for ONNX + LLM-as-judge
- SemanticClassifierConfig with enableEmbedding, modelPath, enableLLMJudge, llmEndpoint
- Full GuardResult integration

### What's Needed — agents-pc (RTX 5090)

**Phase 2A: ONNX Embedding Model**
- Download `all-MiniLM-L6-v2` ONNX model (~22MB) on agents-pc
- Build curated attack embedding set from CrAIBench + Tensor Trust
- Expose as HTTP inference endpoint on agents-pc (FastAPI + onnxruntime-gpu)
- Plugin calls endpoint for cosine similarity classification (~20ms GPU inference)
- Fallback: heuristic scoring if endpoint unreachable

**Phase 2B: Fine-Tuned Classifier**
- Curate 500-1000 labeled examples (attack/benign with subcategories)
- Fine-tune on agents-pc GPU (DistilBERT or MiniLM, ~30min training)
- Export to ONNX, deploy as replacement for embedding similarity
- Target: >95% detection, <1% false positive on DeFi conversations

**Phase 2C: LLM-as-Judge Escalation**
- Route ambiguous messages (heuristic score 0.4-0.7) to Ollama qwen3:8b on agents-pc
- Structured prompt: classify intent, return JSON with confidence
- ~500ms latency, only for edge cases that pass L0+L1

---

## Layer 3: Output Guard — ✅ COMPLETE

**Status:** Done — 15 tests passing
**Files:** `src/guards/output-guard.ts`, `tests/output-guard.test.ts`

Implemented:

1. **Cryptographic Material Detection** — Solana private keys (64-88 base58), ETH keys (0x+64hex), key byte arrays ([32-64 ints]), JWT tokens
2. **BIP39 Seed Phrase Detection** — 200-word sample set, 10+ consecutive matches triggers alert
3. **Post-Block Compliance** — Checks if response echoes blocked transfer amounts/tokens/addresses
4. **Instruction Echo Detection** — "updating wallet to", "I'll send/transfer", "granting access", "disabling security"
5. **Unauthorized TX Confirmation** — Transaction confirmation language after recent blocked input
6. **Response Sanitization** — Redacts keys/JWTs, replaces entire response on compliance violation

---

## Layer 4: Runtime Enforcement — ✅ COMPLETE (4A + 4B)

**Status:** Response Interceptor + Circuit Breaker done (10 tests), Solana Transaction Proxy done (10 on-chain tests)
**Files:** `src/enforcement/response-interceptor.ts`, `tests/enforcement.test.ts`, `src/enforcement/solana/transaction-proxy.ts`, `programs/agentshield-guard/`

### Part A: Response Interceptor + Circuit Breaker — ✅ DONE

- Hard block: replaces response with policy denial + audit reference ID
- Three enforcement modes: monitor, enforce, lockdown
- Circuit Breaker: restricted mode (3 blocks/60s), lockdown (5 blocks/5min)
- Freeze-on-critical: key_leakage or exfiltration → immediate lockdown
- Auto-expiry with configurable lockdown duration
- Manual reset and force-lockdown capabilities

### Part B: Solana Transaction Proxy — ✅ DONE

**Environment:** agents-pc (Rust 1.94, Solana CLI 3.1.11, Anchor 0.32.1)
**Program ID:** `gURRDzQGXs7p4DrTt6dXPNFXHdwuK5u7WUHYobHMB1D`
**On-chain tests:** 10/10 passing (local validator)

Architecture implemented:
- Anchor program `agentshield-guard` with PDA-based transaction queue
- `GuardConfig` PDA per agent: operator, limits, allowlist, oracle, circuit breaker state
- `TransactionRequest` PDA per request: recipient, amount, memo, status lifecycle
- Auto-approve: within limits AND (allowlisted OR no oracle) → immediate approval
- Oracle workflow: non-allowlisted recipients → pending → oracle approve/deny
- On-chain circuit breaker: configurable threshold + window → auto-lockdown
- Force-lock/unlock by operator for emergencies
- Daily spending limit with automatic 24h reset
- TypeScript SDK client for ElizaOS plugin integration (`transaction-proxy.ts`)

Instructions (9 total):
1. `initialize_guard` — Create guard config for an agent
2. `set_oracle` — Set off-chain policy oracle address
3. `add_to_allowlist` / `remove_from_allowlist` — Manage trusted recipients
4. `submit_request` — Agent submits a transfer request
5. `oracle_approve` / `oracle_deny` — Oracle resolves pending requests
6. `execute_transfer` — Execute approved SOL transfer
7. `force_lock` / `unlock` — Emergency circuit breaker control
8. `update_limits` — Change per-tx and daily limits

Remaining:
- 🔲 Devnet deployment (airdrop faucet currently rate-limited)
- 🔲 Mainnet audit + deployment
- 🔲 Multi-sig escalation for high-value operations

---

## Layer 5: Observability & Alerting — ✅ COMPLETE

**Status:** Merkle Audit + Alert Manager + Dashboard + Merkle Anchoring all done
**Files:** `src/logging/merkle-audit.ts`, `src/logging/alert-manager.ts`, `src/logging/dashboard.html`, `src/logging/merkle-anchor.ts`, `tests/merkle-audit.test.ts`

### What's Done

- **Merkle Audit Trail** — SHA-256 leaf hashing, tree construction, periodic checkpoints, tamper-proof verification, deterministic roots
- **Alert Manager** — Slack Block Kit, Telegram Markdown, Discord embeds, generic webhook; severity-based routing; batch digests for medium/low severity; configurable channels
- **Metrics Dashboard** — Interactive HTML/Chart.js dashboard with:
  - 6 KPI cards (total scans, blocked, block rate, latency, circuit breaker state, merkle events)
  - Threat timeline (line chart, hourly buckets)
  - Threat category distribution (doughnut)
  - Layer-wise detection counts (bar chart with L0-L4 color-coded)
  - Latency histogram (ms distribution)
  - Merkle audit trail visualization (current root, last checkpoint, Solana TX)
  - Recent events table (time, layer, category, severity, input preview, action, latency)
  - Time range + layer filters, live event simulation (5s interval)
- **Merkle Root Anchoring on Solana** — `MerkleAnchor` service:
  - Writes Merkle roots to Solana via Memo Program v2 (~0.000005 SOL/anchor)
  - Auto-anchor with configurable interval + minimum events threshold
  - On-chain verification: fetch TX memo, compare root hash
  - Anchor history tracking with cost accounting
  - Dashboard stats integration (total anchors, last root, last signature, cost)

### Remaining

- 🔲 Anomaly trend analysis (time-series escalation detection, coordinated attack detection)

---

## Infrastructure: agents-pc (JARVIS Server)

```
Host:  eigenart@100.102.59.70 (Tailscale)
GPU:   RTX 5090 32GB (Blackwell, sm_120, CUDA 12.8)
OS:    Ubuntu 24, Python 3.13, PyTorch 2.8.0+cu128
VRAM:  ~23.5GB free (8.5GB used by Ollama + Qwen3-TTS + ComfyUI)
LLM:   Ollama qwen3:8b (keep_alive=10m)
```

**Planned AgentShield services on agents-pc:**

| Service | Purpose | VRAM | Port |
|---------|---------|------|------|
| AgentShield Classifier API | ONNX embedding inference | ~0.5GB | 8810 |
| LLM-as-Judge | Ollama qwen3:8b (shared) | 0 (shared) | 11434 |
| Solana Validator (test) | Devnet RPC for L4B testing | 0 | 8899 |

Total additional VRAM: ~0.5GB → well within budget.

---

## Revised Implementation Timeline

```
✅ Week 1:     Layer 0 (Input Normalization) — DONE
✅ Week 1-2:   Layer 1 (Pattern Registry, multi-language) — DONE
✅ Week 2:     Layer 3 (Output Guard) — DONE
✅ Week 2:     Layer 4A (Response Interceptor + Circuit Breaker) — DONE
✅ Week 2:     Layer 5 core (Merkle Audit + Alert Manager) — DONE
✅ Week 2:     Layer 2 scaffold (heuristic classifier) — DONE
✅ Week 3:     L2 GPU classifier on agents-pc (embedding + LLM-as-judge) — DONE
✅ Week 3:     L4B Solana Transaction Proxy (Anchor, 10 on-chain tests) — DONE
✅ Week 3:     L5 dashboard (Chart.js, 6 KPIs, 4 charts, live updates) — DONE
✅ Week 3:     L5 Merkle anchoring on Solana (Memo v2 program) — DONE
── Week 4:     Devnet deployment (pending airdrop)
── Week 4-5:   Red-teaming + adversarial dataset expansion
── Week 6:     Mainnet audit + grant application
```

## Versioning Plan

| Version | Layers | Milestone | Status |
|---------|--------|-----------|--------|
| v2.0.0-alpha | L1 (partial) | Regex patterns, unit tests | ✅ Done |
| v2.0.0-beta | L0–L5 (scaffolds) | All layers implemented, 196 tests | ✅ Done |
| v2.0.0-rc1 | L0–L5 + GPU classifier + L4B | ML classifier, Solana proxy, 206 tests | ✅ **Current** |
| v2.0.0 | Full production | Red-teamed, audited, Mainnet | 🔲 Planned |
| v2.1.0 | + advanced ML | Fine-tuned classifier, anomaly trends | 🔲 Future |

## Testing Strategy

196 TypeScript unit tests + 10 on-chain Anchor tests = 206 total:

| Test File | Tests | Layer |
|-----------|-------|-------|
| input-normalizer.test.ts | 36 | L0 |
| memory-guard.test.ts | 45 | L0+L1 |
| pattern-registry.test.ts | 24 | L1 |
| transaction-guard.test.ts | 19 | L1 |
| anomaly-detector.test.ts | 18 | L1 |
| policy-engine.test.ts | 13 | L1 |
| output-guard.test.ts | 15 | L3 |
| enforcement.test.ts | 10 | L4A |
| semantic-classifier.test.ts | 8 | L2 |
| merkle-audit.test.ts | 8 | L5 |
| agentshield-guard.ts (Anchor) | 10 | L4B |

## Red Team Protocol

Before each version bump, run a structured red-team exercise:

1. Generate 100 novel attack prompts using an adversarial LLM
2. Include multi-language, multi-turn, encoded, and social engineering variants
3. Measure: detection rate, false positive rate, latency impact
4. Any bypass at severity ≥ 4 blocks the release
5. Publish results transparently in the release notes

---

## References

- CrAIBench (Princeton, 2025): arxiv.org/html/2503.16248v3
- Unicode Confusables: unicode.org/reports/tr39
- Tensor Trust Dataset: tensortrust.ai
- ElizaOS v2 Plugin Architecture: elizaos.ai/docs
- Solana Program Library: github.com/solana-labs/solana-program-library
- ONNX Runtime: onnxruntime.ai
- Sentence Transformers: sbert.net
