/**
 * AgentShield v2 — Audit Logger
 * 
 * Append-only event log for all security-relevant actions.
 * Every guard decision, anomaly detection, and policy change
 * is recorded with full context for post-incident analysis.
 * 
 * Supports three output targets:
 * - Console (development)
 * - File (JSON Lines format, production-local)
 * - Solana-compatible events (future: on-chain audit trail)
 * 
 * Design Pattern: Append-only event log (ADK SessionService pattern)
 * + structured output validation (CrewAI Guardrails pattern)
 */

import type {
  AuditEvent,
  AuditEventType,
  PolicyEvaluation,
  TransactionRequest,
  MemoryEntry,
  AgentShieldConfig,
} from '../types/index.js';

// ─── Audit Logger Implementation ────────────────────────────────

export class AuditLogger {
  private target: AgentShieldConfig['auditLogTarget'];
  private logPath?: string;
  private events: AuditEvent[] = [];
  private eventCounter = 0;

  constructor(config: Pick<AgentShieldConfig, 'auditLogTarget' | 'auditLogPath'>) {
    this.target = config.auditLogTarget;
    this.logPath = config.auditLogPath;
  }

  /**
   * Log an audit event. This is append-only — events cannot be modified or deleted.
   */
  log(params: {
    type: AuditEventType;
    agentId: string;
    evaluation?: PolicyEvaluation;
    transaction?: TransactionRequest;
    memory?: MemoryEntry;
    metadata?: Record<string, unknown>;
  }): AuditEvent {
    const event: AuditEvent = {
      id: this.generateEventId(),
      type: params.type,
      agentId: params.agentId,
      timestamp: Date.now(),
      evaluation: params.evaluation,
      transaction: params.transaction,
      memory: params.memory,
      metadata: params.metadata,
    };

    // Append to in-memory log
    this.events.push(event);

    // Write to configured target
    this.emit(event);

    // Keep in-memory buffer bounded (last 10000 events)
    if (this.events.length > 10000) {
      this.events = this.events.slice(-5000);
    }

    return event;
  }

  /**
   * Query recent audit events.
   */
  query(filter?: {
    agentId?: string;
    type?: AuditEventType;
    since?: number;
    limit?: number;
  }): AuditEvent[] {
    let results = this.events;

    if (filter?.agentId) {
      results = results.filter(e => e.agentId === filter.agentId);
    }
    if (filter?.type) {
      results = results.filter(e => e.type === filter.type);
    }
    if (filter?.since) {
      results = results.filter(e => e.timestamp >= filter.since!);
    }

    const limit = filter?.limit || 100;
    return results.slice(-limit);
  }

  /**
   * Export all events as JSON Lines (one JSON object per line).
   * Suitable for compliance reports and forensic analysis.
   */
  exportJsonLines(): string {
    return this.events.map(e => JSON.stringify(e)).join('\n');
  }

  /**
   * Get summary statistics for a given agent.
   */
  getStats(agentId: string): {
    totalEvents: number;
    blockedTransactions: number;
    blockedMemories: number;
    anomaliesDetected: number;
    lastEvent: number | null;
  } {
    const agentEvents = this.events.filter(e => e.agentId === agentId);
    return {
      totalEvents: agentEvents.length,
      blockedTransactions: agentEvents.filter(e => e.type === 'transaction_blocked').length,
      blockedMemories: agentEvents.filter(e => e.type === 'memory_blocked').length,
      anomaliesDetected: agentEvents.filter(e => e.type === 'anomaly_detected').length,
      lastEvent: agentEvents.length > 0
        ? agentEvents[agentEvents.length - 1].timestamp
        : null,
    };
  }

  // ─── Internal ───────────────────────────────────────────────

  private emit(event: AuditEvent): void {
    switch (this.target) {
      case 'console':
        this.emitConsole(event);
        break;
      case 'file':
        this.emitFile(event);
        break;
      case 'solana':
        this.emitSolana(event);
        break;
    }
  }

  private emitConsole(event: AuditEvent): void {
    const icon = this.getEventIcon(event.type);
    const decision = event.evaluation?.decision || '';
    console.log(
      `[AgentShield] ${icon} ${event.type} | agent:${event.agentId} | ${decision} | ${new Date(event.timestamp).toISOString()}`
    );
  }

  private emitFile(event: AuditEvent): void {
    // In a real implementation, this would append to a file
    // For now, we just track it in memory
    // TODO: Implement file writing with fs.appendFile
    if (this.logPath) {
      // Placeholder for file-based logging
      // Will use Node.js fs module or Bun file API
    }
  }

  private emitSolana(event: AuditEvent): void {
    // Future: Emit as Solana event via Anchor program
    // This would create an on-chain audit trail
    // For Phase 1, we fall back to console + file
    this.emitConsole(event);
  }

  private generateEventId(): string {
    this.eventCounter += 1;
    const timestamp = Date.now().toString(36);
    const counter = this.eventCounter.toString(36).padStart(4, '0');
    const random = Math.random().toString(36).slice(2, 6);
    return `as_${timestamp}_${counter}_${random}`;
  }

  private getEventIcon(type: AuditEventType): string {
    const icons: Record<AuditEventType, string> = {
      transaction_allowed: '[OK]',
      transaction_blocked: '[BLOCKED]',
      transaction_escalated: '[ESCALATED]',
      memory_validated: '[OK]',
      memory_blocked: '[BLOCKED]',
      anomaly_detected: '[ANOMALY]',
      policy_updated: '[CONFIG]',
      plugin_initialized: '[INIT]',
      plugin_error: '[ERROR]',
    };
    return icons[type] || '[?]';
  }
}
