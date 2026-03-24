/**
 * AgentShield Layer 4A — Response Interceptor & Circuit Breaker
 *
 * Transforms "warnings" into hard blocks. When AgentShield says
 * "blocked", this layer ensures the agent cannot send the response.
 *
 * Components:
 *   A. Response Interceptor: replaces blocked responses with policy denials
 *   B. Circuit Breaker: auto-lockdown on repeated attack patterns
 *
 * Integration: Post-processing hook on agent responses. The interceptor
 * checks the runtime state flags set by the Provider and Output Guard.
 */

import type { GuardResult } from '../types/index.js';

// ─── Types ──────────────────────────────────────────────────────

export type EnforcementMode = 'monitor' | 'enforce' | 'lockdown';

export interface CircuitBreakerConfig {
  /** Max blocked messages before entering restricted mode */
  restrictedModeThreshold: number;
  /** Time window for threshold (ms) */
  restrictedModeWindowMs: number;
  /** Max blocked messages before full lockdown */
  lockdownThreshold: number;
  /** Time window for lockdown threshold (ms) */
  lockdownWindowMs: number;
  /** Auto-reset lockdown after this duration (ms). 0 = manual only */
  lockdownDurationMs: number;
  /** Immediately freeze on critical severity threats */
  freezeOnCritical: boolean;
}

export interface EnforcementState {
  mode: EnforcementMode;
  blockedCount: number;
  lastBlockTimestamp: number | null;
  lockdownStarted: number | null;
  lockdownReason: string | null;
  recentBlocks: BlockEvent[];
}

interface BlockEvent {
  timestamp: number;
  reason: string;
  severity: number;
  source: 'input' | 'output';
}

export interface InterceptResult {
  /** Whether the response was intercepted (replaced) */
  intercepted: boolean;
  /** The response to send (original or replacement) */
  response: string;
  /** The current enforcement mode */
  mode: EnforcementMode;
  /** Audit reference ID for tracking */
  auditRefId?: string;
}

// ─── Default Configuration ──────────────────────────────────────

export const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  restrictedModeThreshold: 3,
  restrictedModeWindowMs: 60_000, // 3 blocks in 60 seconds
  lockdownThreshold: 5,
  lockdownWindowMs: 300_000, // 5 blocks in 5 minutes
  lockdownDurationMs: 600_000, // 10 minute lockdown
  freezeOnCritical: true,
};

// ─── Standard Denial Messages ───────────────────────────────────

const DENIAL_TEMPLATES = {
  blocked: (threatType: string, auditRef: string) =>
    `I cannot process this request. AgentShield detected a security policy violation (type: ${threatType}). If you believe this is an error, contact the agent operator. Reference: ${auditRef}`,

  restricted: (auditRef: string) =>
    `This agent is currently in restricted mode due to elevated threat activity. Only read-only operations are permitted. Reference: ${auditRef}`,

  lockdown: (reason: string, auditRef: string) =>
    `This agent has been locked down due to sustained security threats: ${reason}. All operations are paused. Contact the agent operator to restore service. Reference: ${auditRef}`,
};

// ─── Response Interceptor ───────────────────────────────────────

export class ResponseInterceptor {
  private config: CircuitBreakerConfig;
  private state: EnforcementState;
  private auditCounter = 0;

  constructor(config?: Partial<CircuitBreakerConfig>) {
    this.config = { ...DEFAULT_CIRCUIT_BREAKER_CONFIG, ...config };
    this.state = {
      mode: 'enforce',
      blockedCount: 0,
      lastBlockTimestamp: null,
      lockdownStarted: null,
      lockdownReason: null,
      recentBlocks: [],
    };
  }

  /**
   * Process an agent response through the enforcement pipeline.
   *
   * @param response - The agent's original response text
   * @param inputGuardResult - Result from the input guard (if available)
   * @param outputGuardResult - Result from the output guard (if available)
   */
  intercept(
    response: string,
    inputGuardResult?: GuardResult | null,
    outputGuardResult?: GuardResult | null,
  ): InterceptResult {
    const auditRef = this.generateAuditRef();

    // Check if lockdown has expired
    this.checkLockdownExpiry();

    // If in lockdown, block everything
    if (this.state.mode === 'lockdown') {
      return {
        intercepted: true,
        response: DENIAL_TEMPLATES.lockdown(this.state.lockdownReason || 'elevated threats', auditRef),
        mode: 'lockdown',
        auditRefId: auditRef,
      };
    }

    // Check input guard
    if (inputGuardResult && inputGuardResult.decision !== 'allow') {
      const threatTypes = inputGuardResult.evaluations
        .filter(e => e.decision === 'block')
        .map(e => e.ruleId)
        .join(', ');

      this.recordBlock({
        timestamp: Date.now(),
        reason: threatTypes,
        severity: this.maxSeverity(inputGuardResult),
        source: 'input',
      });

      return {
        intercepted: true,
        response: DENIAL_TEMPLATES.blocked(threatTypes, auditRef),
        mode: this.state.mode,
        auditRefId: auditRef,
      };
    }

    // Check output guard
    if (outputGuardResult && outputGuardResult.decision !== 'allow') {
      const threatTypes = outputGuardResult.evaluations
        .filter(e => e.decision === 'block')
        .map(e => e.ruleId)
        .join(', ');

      this.recordBlock({
        timestamp: Date.now(),
        reason: threatTypes,
        severity: this.maxSeverity(outputGuardResult),
        source: 'output',
      });

      return {
        intercepted: true,
        response: DENIAL_TEMPLATES.blocked(threatTypes, auditRef),
        mode: this.state.mode,
        auditRefId: auditRef,
      };
    }

    // In restricted mode, block transaction-like responses
    if (this.state.mode === 'enforce' && this.isInRestrictedMode()) {
      const hasTxContent = /(?:sent|transferred|approved|signed|executed)\s+.*(?:SOL|USDC|lamports)/i.test(response);
      if (hasTxContent) {
        return {
          intercepted: true,
          response: DENIAL_TEMPLATES.restricted(auditRef),
          mode: 'monitor', // downgrade display
          auditRefId: auditRef,
        };
      }
    }

    // Response is safe
    return {
      intercepted: false,
      response,
      mode: this.state.mode,
    };
  }

  /**
   * Record a block event and check circuit breaker thresholds.
   */
  recordBlock(event: BlockEvent): void {
    this.state.recentBlocks.push(event);
    this.state.blockedCount++;
    this.state.lastBlockTimestamp = event.timestamp;

    // Trim old events
    const cutoff = Date.now() - this.config.lockdownWindowMs;
    this.state.recentBlocks = this.state.recentBlocks.filter(b => b.timestamp > cutoff);

    // Check for immediate freeze on critical
    if (this.config.freezeOnCritical && event.severity >= 5 &&
        (event.reason.includes('key_leakage') || event.reason.includes('exfiltration'))) {
      this.enterLockdown(`Critical threat: ${event.reason}`);
      return;
    }

    // Check lockdown threshold
    const recentInLockdownWindow = this.state.recentBlocks.filter(
      b => b.timestamp > Date.now() - this.config.lockdownWindowMs,
    ).length;
    if (recentInLockdownWindow >= this.config.lockdownThreshold) {
      this.enterLockdown(`${recentInLockdownWindow} blocked messages in ${this.config.lockdownWindowMs / 1000}s`);
      return;
    }
  }

  /**
   * Check if currently in restricted mode (elevated threat, but not full lockdown).
   */
  isInRestrictedMode(): boolean {
    const recentInWindow = this.state.recentBlocks.filter(
      b => b.timestamp > Date.now() - this.config.restrictedModeWindowMs,
    ).length;
    return recentInWindow >= this.config.restrictedModeThreshold;
  }

  /**
   * Get the current enforcement state.
   */
  getState(): EnforcementState {
    return { ...this.state };
  }

  /**
   * Get the current mode.
   */
  getMode(): EnforcementMode {
    this.checkLockdownExpiry();
    if (this.state.mode === 'lockdown') return 'lockdown';
    if (this.isInRestrictedMode()) return 'monitor';
    return this.state.mode;
  }

  /**
   * Manually reset from lockdown. Requires explicit operator action.
   */
  resetLockdown(): void {
    this.state.mode = 'enforce';
    this.state.lockdownStarted = null;
    this.state.lockdownReason = null;
    this.state.recentBlocks = [];
  }

  /**
   * Force lockdown mode (e.g., from external trigger).
   */
  forceLockdown(reason: string): void {
    this.enterLockdown(reason);
  }

  // ─── Internal ─────────────────────────────────────────────────

  private enterLockdown(reason: string): void {
    this.state.mode = 'lockdown';
    this.state.lockdownStarted = Date.now();
    this.state.lockdownReason = reason;
    console.error(`[AgentShield] LOCKDOWN ACTIVATED: ${reason}`);
  }

  private checkLockdownExpiry(): void {
    if (
      this.state.mode === 'lockdown' &&
      this.config.lockdownDurationMs > 0 &&
      this.state.lockdownStarted &&
      Date.now() - this.state.lockdownStarted > this.config.lockdownDurationMs
    ) {
      console.warn('[AgentShield] Lockdown auto-expired, returning to enforce mode');
      this.state.mode = 'enforce';
      this.state.lockdownStarted = null;
      this.state.lockdownReason = null;
    }
  }

  private maxSeverity(result: GuardResult): number {
    let max = 0;
    for (const e of result.evaluations) {
      const sev = e.confidence * 5;
      if (sev > max) max = sev;
    }
    return Math.round(max);
  }

  private generateAuditRef(): string {
    this.auditCounter++;
    const ts = Date.now().toString(36);
    const cnt = this.auditCounter.toString(36).padStart(3, '0');
    return `AS-${ts}-${cnt}`;
  }
}
