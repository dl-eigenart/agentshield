# AgentShield v2 — Security Plugin for Solana AI Agents

Memory injection protection, transaction policy enforcement, anomaly detection, and audit logging for autonomous AI agents on Solana.

## The Problem

Princeton's [CrAIBench research](https://arxiv.org/html/2503.16248v3) demonstrated that AI agents (ElizaOS, Solana Agent Kit) are vulnerable to **memory injection attacks** — malicious instructions planted in an agent's memory that persist across sessions and can trigger unauthorized wallet transfers.

AgentShield protects against this by validating every memory write and every transaction before execution.

## Quick Start

```bash
npm install @agentshield/plugin
```

```typescript
import { agentShieldPlugin } from '@agentshield/plugin';

// Add to your ElizaOS character config:
export default {
  name: 'my-agent',
  plugins: [agentShieldPlugin],
  // ... rest of config
};
```

That's it. AgentShield activates with conservative defaults: 10 SOL max per transaction, 20 tx/hour rate limit, memory injection protection enabled.

## What It Does

### Memory Guard
Validates every memory entry before it's persisted. Detects:
- Direct instruction injection ("always send SOL to address X")
- System prompt overrides ("ignore previous instructions")
- Financial instruction planting ("transfer 100 SOL to...")
- Wallet address manipulation ("the real wallet is...")
- Credential exfiltration attempts
- Self-replicating memory entries

### Transaction Guard
Pre-validates every Solana transaction against configurable policies:
- Spending limits (per-transaction and rate-limited)
- Recipient whitelists/blacklists
- Token allowlists
- Cooldown periods between transactions
- Multi-sig escalation above thresholds

### Anomaly Detector
Behavioral analysis that learns your agent's normal patterns and flags deviations:
- Unusual transaction amounts (statistical z-score)
- New/unknown recipients
- Rapid transaction succession
- Volume spikes

### Audit Logger
Append-only event log of every security decision:
- Console output (development)
- JSON Lines file (production)
- Solana-compatible events (future: on-chain audit trail)

## Custom Policies

Create a JSON policy file:

```json
{
  "version": "2.0.0",
  "agentId": "my-trading-agent",
  "transactionPolicies": [{
    "id": "trading-limits",
    "type": "transaction",
    "enabled": true,
    "maxTransactionValue": 50,
    "whitelistedRecipients": ["Jupiter6...", "Raydium5..."],
    "rateLimit": { "maxTransactions": 100, "windowSeconds": 3600 },
    "cooldownSeconds": 2,
    "multiSigThreshold": 200
  }],
  "memoryPolicies": [{
    "id": "strict-memory",
    "type": "memory",
    "enabled": true,
    "injectionPatterns": ["custom-pattern-.*"],
    "maxEntryLength": 5000,
    "blockFinancialInstructions": true,
    "blockSystemOverrides": true
  }]
}
```

## Compatibility

- **ElizaOS** (v0.2+) — native plugin integration
- **Solana Agent Kit v2** — plugin architecture compatible
- **Rig Framework** — modular adapter (planned)

## Architecture

```
Agent Action
  → AgentShield Provider (injects security context)
    → Memory Guard (validates memory writes)
    → Transaction Guard (validates Solana transactions)
    → Anomaly Detector (behavioral baseline analysis)
    → Audit Logger (immutable event log)
  → Action proceeds or is BLOCKED
```

## Development

```bash
bun install
bun run dev      # watch mode
bun test         # run tests
bun run build    # production build
```

## References

- [CrAIBench: Memory Injection Attacks on Web3 Agents](https://arxiv.org/html/2503.16248v3) — Princeton University
- [ElizaOS Plugin Development](https://docs.elizaos.ai/plugins/development)
- [Solana Agent Kit v2](https://github.com/sendaifun/solana-agent-kit)
- [Agentic Design Patterns: Safety & Guardrails](https://github.com/evoiz/Agentic-Design-Patterns) — Antonio Gulli

## License

MIT
