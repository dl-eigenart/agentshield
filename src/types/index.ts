/**
 * AgentShield v2 — Core Type Definitions
 * 
 * Type system for the security plugin covering:
 * - Policy configuration and evaluation
 * - Memory integrity validation
 * - Transaction monitoring
 * - Audit logging
 * 
 * Design Pattern References:
 * - before_tool_callback (ADK Validate Tool pattern)
 * - Structured PolicyEvaluation output (CrewAI Guardrails pattern)
 * - Append-only event log (ADK Session Memory pattern)
 */

// ─── Policy Types ───────────────────────────────────────────────

export type PolicyDecision = 'allow' | 'block' | 'escalate';

export interface PolicyRule {
  /** Unique rule identifier */
  id: string;
  /** Human-readable description */
  description: string;
  /** Rule priority (lower = higher priority) */
  priority: number;
  /** Whether this rule is active */
  enabled: boolean;
}

export interface TransactionPolicy extends PolicyRule {
  type: 'transaction';
  /** Maximum transaction value in SOL (0 = unlimited) */
  maxTransactionValue: number;
  /** Allowed token mints (empty = all allowed) */
  allowedTokens: string[];
  /** Blocked recipient addresses */
  blockedRecipients: string[];
  /** Whitelisted recipient addresses (if set, ONLY these are allowed) */
  whitelistedRecipients: string[];
  /** Maximum transactions per time window */
  rateLimit: {
    maxTransactions: number;
    windowSeconds: number;
  };
  /** Cooldown between transactions in seconds */
  cooldownSeconds: number;
  /** Require multi-sig above this SOL value (0 = disabled) */
  multiSigThreshold: number;
}

export interface MemoryPolicy extends PolicyRule {
  type: 'memory';
  /** Block memory entries matching these injection patterns */
  injectionPatterns: string[];
  /** Maximum allowed memory entry length */
  maxEntryLength: number;
  /** Block entries referencing wallet/transfer actions */
  blockFinancialInstructions: boolean;
  /** Block entries that attempt to override system prompts */
  blockSystemOverrides: boolean;
}

export interface AgentShieldPolicy {
  /** Policy version for migration support */
  version: string;
  /** Agent identifier this policy applies to */
  agentId: string;
  /** Transaction rules */
  transactionPolicies: TransactionPolicy[];
  /** Memory integrity rules */
  memoryPolicies: MemoryPolicy[];
}

// ─── Evaluation Types ───────────────────────────────────────────

export interface PolicyEvaluation {
  /** Which policy rule was evaluated */
  ruleId: string;
  /** The decision */
  decision: PolicyDecision;
  /** Human-readable reason */
  reason: string;
  /** Confidence score 0-1 (for ML-based checks) */
  confidence: number;
  /** Timestamp of evaluation */
  timestamp: number;
}

export interface GuardResult {
  /** Overall decision (block if ANY rule blocks) */
  decision: PolicyDecision;
  /** All individual evaluations */
  evaluations: PolicyEvaluation[];
  /** Original action/memory that was evaluated */
  input: unknown;
  /** Processing time in ms */
  processingTimeMs: number;
}

// ─── Memory Guard Types ─────────────────────────────────────────

export interface MemoryEntry {
  /** The content of the memory entry */
  content: string;
  /** Source of the memory (user, agent, system, external) */
  source: 'user' | 'agent' | 'system' | 'external';
  /** Timestamp of creation */
  timestamp: number;
  /** Associated agent ID */
  agentId: string;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

export interface MemoryValidationResult {
  /** Is this memory entry safe? */
  isSafe: boolean;
  /** Detected threats */
  threats: MemoryThreat[];
  /** Sanitized content (if applicable) */
  sanitizedContent?: string;
}

export interface MemoryThreat {
  /** Type of threat detected */
  type: 'injection' | 'override' | 'financial_instruction' | 'exfiltration' | 'unknown';
  /** Severity 1-5 */
  severity: number;
  /** Which pattern matched */
  matchedPattern: string;
  /** The suspicious content segment */
  suspiciousContent: string;
}

// ─── Transaction Monitor Types ──────────────────────────────────

export interface TransactionRequest {
  /** Sender wallet address */
  from: string;
  /** Recipient wallet address */
  to: string;
  /** Amount in lamports */
  amount: number;
  /** Token mint address (native SOL if undefined) */
  tokenMint?: string;
  /** The Solana program being called */
  programId: string;
  /** Raw instruction data */
  instructionData?: Uint8Array;
  /** Agent ID initiating the transaction */
  agentId: string;
  /** Timestamp of request */
  timestamp: number;
}

export interface TransactionVerdict {
  /** Allow, block, or escalate for human review */
  decision: PolicyDecision;
  /** Reason for the decision */
  reason: string;
  /** Which policy rules were triggered */
  triggeredRules: string[];
  /** Risk score 0-100 */
  riskScore: number;
  /** Suggested action if escalated */
  escalationAction?: 'notify_owner' | 'require_multisig' | 'delay_execution';
}

// ─── Audit Log Types ────────────────────────────────────────────

export type AuditEventType = 
  | 'transaction_allowed'
  | 'transaction_blocked'
  | 'transaction_escalated'
  | 'memory_validated'
  | 'memory_blocked'
  | 'anomaly_detected'
  | 'policy_updated'
  | 'plugin_initialized'
  | 'plugin_error';

export interface AuditEvent {
  /** Unique event ID */
  id: string;
  /** Event type */
  type: AuditEventType;
  /** Agent ID */
  agentId: string;
  /** Timestamp (Unix ms) */
  timestamp: number;
  /** The policy evaluation result */
  evaluation?: PolicyEvaluation;
  /** Transaction details (if applicable) */
  transaction?: TransactionRequest;
  /** Memory entry (if applicable) */
  memory?: MemoryEntry;
  /** Additional context */
  metadata?: Record<string, unknown>;
}

// ─── Plugin Configuration ───────────────────────────────────────

export interface AgentShieldConfig {
  /** Path to policy YAML/JSON file, or inline policy */
  policy: AgentShieldPolicy | string;
  /** Enable audit logging */
  enableAuditLog: boolean;
  /** Audit log output: console, file, or Solana-compatible event */
  auditLogTarget: 'console' | 'file' | 'solana';
  /** File path for audit log (if target is 'file') */
  auditLogPath?: string;
  /** Enable anomaly detection (pattern-based) */
  enableAnomalyDetection: boolean;
  /** Webhook URL for alerts */
  alertWebhookUrl?: string;
  /** Alert channels */
  alertChannels: ('webhook' | 'discord' | 'telegram')[];
  /** Verbose logging for development */
  debug: boolean;
}
