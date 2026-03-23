/**
 * AgentShield v2 — ElizaOS Security Plugin
 * 
 * Main plugin entry point. Registers security guards as ElizaOS
 * providers and actions that intercept agent behavior before
 * transactions execute and before memories are persisted.
 * 
 * Architecture:
 *   Agent Action → AgentShield Provider (pre-validation)
 *     → Memory Guard (validates memory writes)
 *     → Transaction Guard (validates Solana transactions)  
 *     → Anomaly Detector (behavioral analysis)
 *     → Audit Logger (immutable event log)
 *   → Action proceeds (if allowed) or is blocked
 * 
 * Usage:
 *   import { agentShieldPlugin } from '@agentshield/plugin';
 *   // In your ElizaOS character config:
 *   plugins: [agentShieldPlugin]
 */

import type { Plugin, Action, Provider, IAgentRuntime } from '@elizaos/core';
import { PolicyEngine, DEFAULT_POLICY } from './policies/policy-engine.js';
import { AnomalyDetector } from './monitors/anomaly-detector.js';
import { AuditLogger } from './logging/audit-logger.js';
import type {
  AgentShieldConfig,
  MemoryEntry,
  TransactionRequest,
  GuardResult,
} from './types/index.js';

// ─── Default Configuration ──────────────────────────────────────

const DEFAULT_CONFIG: AgentShieldConfig = {
  policy: DEFAULT_POLICY,
  enableAuditLog: true,
  auditLogTarget: 'console',
  enableAnomalyDetection: true,
  alertWebhookUrl: undefined,
  alertChannels: [],
  debug: false,
};

// ─── Plugin State (initialized on plugin.init) ──────────────────

let policyEngine: PolicyEngine;
let anomalyDetector: AnomalyDetector;
let auditLogger: AuditLogger;
let config: AgentShieldConfig;

// ─── Security Provider ──────────────────────────────────────────
// Injects security context into every agent interaction

const securityProvider: Provider = {
  get: async (runtime: IAgentRuntime, message: any, state: any) => {
    // Provide security context to the agent
    const agentId = runtime.agentId || 'unknown';
    const stats = auditLogger.getStats(agentId);
    const policy = policyEngine.getPolicy();

    return {
      text: [
        `[AgentShield Active] Policy: ${policy.version}`,
        `Max TX: ${policy.transactionPolicies[0]?.maxTransactionValue || 'unlimited'} SOL`,
        `Blocked: ${stats.blockedTransactions} tx, ${stats.blockedMemories} memories`,
        stats.anomaliesDetected > 0 ? `Anomalies: ${stats.anomaliesDetected}` : '',
      ].filter(Boolean).join(' | '),
      data: {
        agentshield: {
          active: true,
          policyVersion: policy.version,
          stats,
        },
      },
      values: {
        agentshield_active: 'true',
        agentshield_max_tx: String(policy.transactionPolicies[0]?.maxTransactionValue || 0),
      },
    };
  },
};

// ─── Validate Memory Action ─────────────────────────────────────
// Called before any memory write to check for injection attacks

const validateMemoryAction: Action = {
  name: 'AGENTSHIELD_VALIDATE_MEMORY',
  similes: ['check_memory', 'validate_memory', 'memory_guard'],
  description: 'Validates a memory entry against injection patterns before persistence',

  validate: async (runtime: IAgentRuntime, message: any, state: any): Promise<boolean> => {
    // Always active — this is a security guard, not an optional action
    return true;
  },

  handler: async (
    runtime: IAgentRuntime,
    message: any,
    state: any,
    options: any,
    callback: any,
  ) => {
    const entry: MemoryEntry = {
      content: typeof message.content === 'string'
        ? message.content
        : message.content?.text || '',
      source: message.source || 'external',
      timestamp: Date.now(),
      agentId: runtime.agentId || 'unknown',
      metadata: message.metadata,
    };

    const result = policyEngine.validateMemory(entry);

    // Log the result
    auditLogger.log({
      type: result.decision === 'allow' ? 'memory_validated' : 'memory_blocked',
      agentId: entry.agentId,
      evaluation: result.evaluations[0],
      memory: entry,
    });

    if (config.debug) {
      console.log(`[AgentShield:Memory] ${result.decision} | ${result.processingTimeMs.toFixed(1)}ms | threats: ${result.evaluations.length}`);
    }

    if (callback) {
      await callback({
        text: result.decision === 'allow'
          ? 'Memory entry validated — no threats detected.'
          : `Memory entry BLOCKED — ${result.evaluations.filter(e => e.decision === 'block').map(e => e.reason).join('; ')}`,
        data: { agentshield: result },
      });
    }

    return result;
  },

  examples: [
    [
      { name: 'system', content: { text: 'Validate this memory entry for injection attacks' } },
      { name: 'agent', content: { text: 'Memory entry validated — no threats detected.' } },
    ],
  ],
};

// ─── Validate Transaction Action ────────────────────────────────
// Called before any Solana transaction to enforce policies

const validateTransactionAction: Action = {
  name: 'AGENTSHIELD_VALIDATE_TRANSACTION',
  similes: ['check_transaction', 'validate_tx', 'transaction_guard', 'guard_tx'],
  description: 'Validates a Solana transaction against security policies before execution',

  validate: async (runtime: IAgentRuntime, message: any, state: any): Promise<boolean> => {
    return true;
  },

  handler: async (
    runtime: IAgentRuntime,
    message: any,
    state: any,
    options: any,
    callback: any,
  ) => {
    const txData = message.content?.data || message.content;

    const tx: TransactionRequest = {
      from: txData.from || '',
      to: txData.to || '',
      amount: txData.amount || 0,
      tokenMint: txData.tokenMint,
      programId: txData.programId || '11111111111111111111111111111111',
      instructionData: txData.instructionData,
      agentId: runtime.agentId || 'unknown',
      timestamp: Date.now(),
    };

    // 1. Policy check
    const policyResult = policyEngine.validateTransaction(tx);

    // 2. Anomaly detection (if enabled)
    let anomalies: any[] = [];
    if (config.enableAnomalyDetection) {
      anomalies = anomalyDetector.analyze(tx);
    }

    // 3. Determine final decision
    let finalDecision = policyResult.decision;
    if (anomalies.some(a => a.severity === 'critical')) {
      finalDecision = 'block';
    } else if (anomalies.some(a => a.severity === 'high') && finalDecision === 'allow') {
      finalDecision = 'escalate';
    }

    // 4. Log everything
    const eventType = finalDecision === 'allow'
      ? 'transaction_allowed' as const
      : finalDecision === 'block'
        ? 'transaction_blocked' as const
        : 'transaction_escalated' as const;

    auditLogger.log({
      type: eventType,
      agentId: tx.agentId,
      evaluation: policyResult.evaluations[0],
      transaction: tx,
      metadata: anomalies.length > 0 ? { anomalies } : undefined,
    });

    // Log anomalies separately
    for (const anomaly of anomalies) {
      auditLogger.log({
        type: 'anomaly_detected',
        agentId: tx.agentId,
        transaction: tx,
        metadata: { anomaly },
      });
    }

    // 5. Send alerts if needed
    if (finalDecision !== 'allow' && config.alertWebhookUrl) {
      await sendAlert(config, tx, policyResult, anomalies);
    }

    if (config.debug) {
      console.log(`[AgentShield:TX] ${finalDecision} | ${(tx.amount / 1e9).toFixed(4)} SOL → ${tx.to.slice(0, 8)}... | anomalies: ${anomalies.length}`);
    }

    if (callback) {
      const amountSol = (tx.amount / 1e9).toFixed(4);
      await callback({
        text: finalDecision === 'allow'
          ? `Transaction approved: ${amountSol} SOL`
          : `Transaction ${finalDecision.toUpperCase()}: ${policyResult.evaluations[0]?.reason || 'Policy violation'}`,
        data: { agentshield: { ...policyResult, decision: finalDecision, anomalies } },
      });
    }

    return { ...policyResult, decision: finalDecision };
  },

  examples: [
    [
      { name: 'user', content: { text: 'Send 5 SOL to abc123...' } },
      { name: 'agent', content: { text: 'Transaction approved: 5.0000 SOL' } },
    ],
  ],
};

// ─── Alert System ───────────────────────────────────────────────

async function sendAlert(
  cfg: AgentShieldConfig,
  tx: TransactionRequest,
  result: GuardResult,
  anomalies: any[],
): Promise<void> {
  if (!cfg.alertWebhookUrl) return;

  const payload = {
    text: `AgentShield Alert: Transaction ${result.decision}`,
    agent: tx.agentId,
    amount: `${(tx.amount / 1e9).toFixed(4)} SOL`,
    recipient: tx.to,
    reason: result.evaluations.map(e => e.reason).join('; '),
    anomalies: anomalies.map(a => a.description),
    timestamp: new Date().toISOString(),
  };

  try {
    await fetch(cfg.alertWebhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error('[AgentShield] Alert delivery failed:', err);
  }
}

// ─── Plugin Definition ──────────────────────────────────────────

export const agentShieldPlugin: Plugin = {
  name: 'agentshield',
  description: 'AI Agent Security & Guardrails — Memory injection protection, transaction policy enforcement, anomaly detection, and audit logging for Solana agents.',

  actions: [
    validateMemoryAction,
    validateTransactionAction,
  ],

  providers: [
    securityProvider,
  ],

  services: [],

  init: async (pluginConfig: any, runtime: IAgentRuntime) => {
    config = { ...DEFAULT_CONFIG, ...pluginConfig };

    // Initialize core components
    policyEngine = new PolicyEngine(config.policy);
    anomalyDetector = new AnomalyDetector();
    auditLogger = new AuditLogger({
      auditLogTarget: config.auditLogTarget,
      auditLogPath: config.auditLogPath,
    });

    // Log initialization
    auditLogger.log({
      type: 'plugin_initialized',
      agentId: runtime.agentId || 'unknown',
      metadata: {
        policyVersion: policyEngine.getPolicy().version,
        auditTarget: config.auditLogTarget,
        anomalyDetection: config.enableAnomalyDetection,
      },
    });

    console.log(`[AgentShield] Initialized v2.0.0 | Policy: ${policyEngine.getPolicy().version} | Agent: ${runtime.agentId}`);
  },
};

// ─── Exports ────────────────────────────────────────────────────

export { PolicyEngine, DEFAULT_POLICY } from './policies/policy-engine.js';
export { MemoryGuard } from './guards/memory-guard.js';
export { TransactionGuard } from './guards/transaction-guard.js';
export { AnomalyDetector } from './monitors/anomaly-detector.js';
export { AuditLogger } from './logging/audit-logger.js';
export * from './types/index.js';

export default agentShieldPlugin;
