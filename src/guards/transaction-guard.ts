/**
 * AgentShield v2 — Transaction Guard
 * 
 * Pre-execution validation for all Solana transactions initiated by agents.
 * Implements the before_tool_callback pattern from ADK, adapted for
 * Solana transaction lifecycle.
 * 
 * Checks: spending limits, recipient whitelists/blacklists, rate limiting,
 * cooldown periods, token allowlists, and multi-sig thresholds.
 * 
 * Design Pattern: before_tool_callback + state-based fallback (Ch. 12/18)
 */

import type {
  TransactionPolicy,
  TransactionRequest,
  TransactionVerdict,
  PolicyDecision,
} from '../types/index.js';

// ─── Rate Limit Tracker ─────────────────────────────────────────

interface RateLimitWindow {
  timestamps: number[];
  lastTransaction: number;
}

// ─── Transaction Guard Implementation ───────────────────────────

export class TransactionGuard {
  private policies: TransactionPolicy[];
  private rateLimitWindows: Map<string, RateLimitWindow> = new Map();

  constructor(policies: TransactionPolicy[]) {
    this.policies = policies.filter(p => p.enabled);
  }

  /**
   * Evaluate a transaction request against all active policies.
   * Returns a verdict: allow, block, or escalate.
   * 
   * This is the primary guard — called before every transaction send.
   */
  evaluate(tx: TransactionRequest): TransactionVerdict {
    const triggeredRules: string[] = [];
    let worstDecision: PolicyDecision = 'allow';
    let riskScore = 0;
    const reasons: string[] = [];
    let escalationAction: TransactionVerdict['escalationAction'] | undefined;

    for (const policy of this.policies) {
      // 1. Spending limit check
      const amountInSol = tx.amount / 1_000_000_000; // lamports to SOL
      if (policy.maxTransactionValue > 0 && amountInSol > policy.maxTransactionValue) {
        triggeredRules.push(policy.id);
        riskScore += 40;
        reasons.push(
          `Amount ${amountInSol.toFixed(4)} SOL exceeds limit ${policy.maxTransactionValue} SOL`
        );

        // Escalate if above multi-sig threshold, block if above max
        if (policy.multiSigThreshold > 0 && amountInSol > policy.multiSigThreshold) {
          worstDecision = 'escalate';
          escalationAction = 'require_multisig';
        } else {
          worstDecision = 'block';
        }
      }

      // 2. Blocked recipients
      if (policy.blockedRecipients.includes(tx.to)) {
        triggeredRules.push(policy.id);
        worstDecision = 'block';
        riskScore += 50;
        reasons.push(`Recipient ${this.truncateAddress(tx.to)} is on blocklist`);
      }

      // 3. Whitelist check (if whitelist is set, ONLY these addresses are allowed)
      if (
        policy.whitelistedRecipients.length > 0 &&
        !policy.whitelistedRecipients.includes(tx.to)
      ) {
        triggeredRules.push(policy.id);
        worstDecision = 'block';
        riskScore += 30;
        reasons.push(
          `Recipient ${this.truncateAddress(tx.to)} is not on whitelist`
        );
      }

      // 4. Token allowlist
      if (tx.tokenMint && policy.allowedTokens.length > 0) {
        if (!policy.allowedTokens.includes(tx.tokenMint)) {
          triggeredRules.push(policy.id);
          worstDecision = 'block';
          riskScore += 25;
          reasons.push(
            `Token ${this.truncateAddress(tx.tokenMint)} is not in allowed tokens`
          );
        }
      }

      // 5. Rate limiting
      const rateLimitResult = this.checkRateLimit(tx.agentId, policy);
      if (rateLimitResult !== null) {
        triggeredRules.push(policy.id);
        worstDecision = this.escalateDecision(worstDecision, 'block');
        riskScore += 35;
        reasons.push(rateLimitResult);
      }

      // 6. Cooldown check
      const cooldownResult = this.checkCooldown(tx.agentId, policy);
      if (cooldownResult !== null) {
        triggeredRules.push(policy.id);
        worstDecision = this.escalateDecision(worstDecision, 'block');
        riskScore += 20;
        reasons.push(cooldownResult);
      }
    }

    // Clamp risk score
    riskScore = Math.min(100, riskScore);

    // Record this transaction for rate limiting
    if (worstDecision === 'allow') {
      this.recordTransaction(tx.agentId, tx.timestamp);
    }

    return {
      decision: worstDecision,
      reason: reasons.length > 0 ? reasons.join('; ') : 'All policy checks passed',
      triggeredRules: [...new Set(triggeredRules)],
      riskScore,
      escalationAction,
    };
  }

  // ─── Rate Limiting ──────────────────────────────────────────

  private checkRateLimit(agentId: string, policy: TransactionPolicy): string | null {
    const { maxTransactions, windowSeconds } = policy.rateLimit;
    if (maxTransactions <= 0) return null;

    const window = this.rateLimitWindows.get(agentId);
    if (!window) return null;

    const now = Date.now();
    const windowStart = now - windowSeconds * 1000;
    const recentTxCount = window.timestamps.filter(t => t > windowStart).length;

    if (recentTxCount >= maxTransactions) {
      return `Rate limit exceeded: ${recentTxCount}/${maxTransactions} transactions in ${windowSeconds}s window`;
    }
    return null;
  }

  private checkCooldown(agentId: string, policy: TransactionPolicy): string | null {
    if (policy.cooldownSeconds <= 0) return null;

    const window = this.rateLimitWindows.get(agentId);
    if (!window || window.lastTransaction === 0) return null;

    const elapsed = (Date.now() - window.lastTransaction) / 1000;
    if (elapsed < policy.cooldownSeconds) {
      const remaining = Math.ceil(policy.cooldownSeconds - elapsed);
      return `Cooldown active: ${remaining}s remaining (requires ${policy.cooldownSeconds}s between transactions)`;
    }
    return null;
  }

  private recordTransaction(agentId: string, timestamp: number): void {
    const existing = this.rateLimitWindows.get(agentId) || {
      timestamps: [],
      lastTransaction: 0,
    };

    existing.timestamps.push(timestamp);
    existing.lastTransaction = timestamp;

    // Keep only last 1000 timestamps to prevent memory leak
    if (existing.timestamps.length > 1000) {
      existing.timestamps = existing.timestamps.slice(-500);
    }

    this.rateLimitWindows.set(agentId, existing);
  }

  // ─── Helpers ────────────────────────────────────────────────

  private escalateDecision(current: PolicyDecision, incoming: PolicyDecision): PolicyDecision {
    const severity: Record<PolicyDecision, number> = { allow: 0, escalate: 1, block: 2 };
    return severity[incoming] > severity[current] ? incoming : current;
  }

  private truncateAddress(address: string): string {
    if (address.length <= 12) return address;
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }
}
