/**
 * AgentShield v2 — Policy Engine
 * 
 * Central orchestrator that loads policy configs and routes
 * validation requests to the appropriate guards.
 * 
 * Supports JSON/YAML policy files and inline configuration.
 * 
 * Design Pattern: Routing pattern (Ch. 2) — dynamically selects
 * which guard to invoke based on the type of action.
 */

import { MemoryGuard } from '../guards/memory-guard.js';
import { TransactionGuard } from '../guards/transaction-guard.js';
import type {
  AgentShieldPolicy,
  MemoryEntry,
  TransactionRequest,
  GuardResult,
  PolicyEvaluation,
  PolicyDecision,
} from '../types/index.js';

// ─── Default Policy ─────────────────────────────────────────────

export const DEFAULT_POLICY: AgentShieldPolicy = {
  version: '2.0.0',
  agentId: '*',
  transactionPolicies: [
    {
      id: 'default-tx-limits',
      description: 'Default transaction safety limits',
      type: 'transaction',
      priority: 1,
      enabled: true,
      maxTransactionValue: 10, // 10 SOL max per transaction
      allowedTokens: [],       // all tokens allowed by default
      blockedRecipients: [],
      whitelistedRecipients: [],
      rateLimit: {
        maxTransactions: 20,
        windowSeconds: 3600,   // 20 tx per hour
      },
      cooldownSeconds: 5,
      multiSigThreshold: 50,   // require multi-sig above 50 SOL
    },
  ],
  memoryPolicies: [
    {
      id: 'default-memory-safety',
      description: 'Default memory injection protection',
      type: 'memory',
      priority: 1,
      enabled: true,
      injectionPatterns: [],    // uses built-in patterns
      maxEntryLength: 10000,
      blockFinancialInstructions: true,
      blockSystemOverrides: true,
    },
  ],
};

// ─── Policy Engine Implementation ───────────────────────────────

export class PolicyEngine {
  private policy: AgentShieldPolicy;
  private memoryGuard: MemoryGuard;
  private transactionGuard: TransactionGuard;

  constructor(policy?: AgentShieldPolicy | string) {
    this.policy = this.loadPolicy(policy);
    this.memoryGuard = new MemoryGuard(this.policy.memoryPolicies);
    this.transactionGuard = new TransactionGuard(this.policy.transactionPolicies);
  }

  /**
   * Validate a memory entry before persistence.
   * Returns a GuardResult with the decision and all evaluations.
   */
  validateMemory(entry: MemoryEntry): GuardResult {
    const start = performance.now();
    const result = this.memoryGuard.validate(entry);

    const evaluations: PolicyEvaluation[] = result.threats.map(threat => ({
      ruleId: threat.matchedPattern,
      decision: (threat.severity >= 4 ? 'block' : 'allow') as PolicyDecision,
      reason: `${threat.type}: ${threat.suspiciousContent}`,
      confidence: threat.severity / 5,
      timestamp: Date.now(),
    }));

    // Add a passing evaluation if no threats
    if (evaluations.length === 0) {
      evaluations.push({
        ruleId: 'memory-guard',
        decision: 'allow',
        reason: 'No threats detected',
        confidence: 1,
        timestamp: Date.now(),
      });
    }

    const decision: PolicyDecision = result.isSafe ? 'allow' : 'block';

    return {
      decision,
      evaluations,
      input: entry,
      processingTimeMs: performance.now() - start,
    };
  }

  /**
   * Evaluate a transaction request before execution.
   * Returns a GuardResult with the decision and all evaluations.
   */
  validateTransaction(tx: TransactionRequest): GuardResult {
    const start = performance.now();
    const verdict = this.transactionGuard.evaluate(tx);

    const evaluations: PolicyEvaluation[] = [{
      ruleId: verdict.triggeredRules.join(',') || 'transaction-guard',
      decision: verdict.decision,
      reason: verdict.reason,
      confidence: 1 - (verdict.riskScore / 100),
      timestamp: Date.now(),
    }];

    return {
      decision: verdict.decision,
      evaluations,
      input: tx,
      processingTimeMs: performance.now() - start,
    };
  }

  /**
   * Get the current active policy.
   */
  getPolicy(): AgentShieldPolicy {
    return this.policy;
  }

  /**
   * Update the policy at runtime.
   * Recreates guards with new policy configuration.
   */
  updatePolicy(newPolicy: AgentShieldPolicy): void {
    this.policy = newPolicy;
    this.memoryGuard = new MemoryGuard(newPolicy.memoryPolicies);
    this.transactionGuard = new TransactionGuard(newPolicy.transactionPolicies);
  }

  // ─── Policy Loading ─────────────────────────────────────────

  private loadPolicy(input?: AgentShieldPolicy | string): AgentShieldPolicy {
    if (!input) {
      return DEFAULT_POLICY;
    }

    if (typeof input === 'string') {
      return this.parsePolicyFile(input);
    }

    return this.mergeWithDefaults(input);
  }

  private parsePolicyFile(pathOrContent: string): AgentShieldPolicy {
    try {
      // Try parsing as JSON string first
      const parsed = JSON.parse(pathOrContent);
      return this.mergeWithDefaults(parsed as AgentShieldPolicy);
    } catch {
      // If it's a file path, we'd read it here
      // For now, fall back to defaults
      console.warn('[AgentShield] Could not parse policy, using defaults');
      return DEFAULT_POLICY;
    }
  }

  private mergeWithDefaults(partial: Partial<AgentShieldPolicy>): AgentShieldPolicy {
    return {
      version: partial.version || DEFAULT_POLICY.version,
      agentId: partial.agentId || DEFAULT_POLICY.agentId,
      transactionPolicies: partial.transactionPolicies || DEFAULT_POLICY.transactionPolicies,
      memoryPolicies: partial.memoryPolicies || DEFAULT_POLICY.memoryPolicies,
    };
  }
}
