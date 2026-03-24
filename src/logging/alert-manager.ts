/**
 * AgentShield Layer 5 — Alert Manager
 *
 * Configurable webhook alerting for different severity levels.
 * Supports Slack Block Kit, Telegram Bot API, Discord webhooks,
 * and generic JSON webhooks.
 *
 * Batching: Low-severity alerts are batched into periodic digests.
 * Critical alerts are sent immediately.
 */

// ─── Types ──────────────────────────────────────────────────────

export type AlertChannel = 'webhook' | 'slack' | 'telegram' | 'discord';
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface AlertConfig {
  channels: AlertChannelConfig[];
  /** Batch interval for non-critical alerts (ms) */
  batchIntervalMs: number;
  /** Maximum alerts per batch */
  maxBatchSize: number;
  /** Enable/disable alerting globally */
  enabled: boolean;
}

export interface AlertChannelConfig {
  type: AlertChannel;
  url: string;
  /** Minimum severity to send on this channel */
  minSeverity: AlertSeverity;
  /** Optional: custom headers */
  headers?: Record<string, string>;
}

export interface AlertPayload {
  severity: AlertSeverity;
  title: string;
  agentId: string;
  details: string;
  timestamp: number;
  auditRef?: string;
  metadata?: Record<string, unknown>;
}

const SEVERITY_ORDER: Record<AlertSeverity, number> = {
  critical: 4, high: 3, medium: 2, low: 1,
};

const DEFAULT_ALERT_CONFIG: AlertConfig = {
  channels: [],
  batchIntervalMs: 300_000, // 5 minutes
  maxBatchSize: 50,
  enabled: true,
};

// ─── Alert Manager Implementation ───────────────────────────────

export class AlertManager {
  private config: AlertConfig;
  private pendingBatch: AlertPayload[] = [];
  private batchTimer: ReturnType<typeof setInterval> | null = null;
  private sentCount = 0;
  private failCount = 0;

  constructor(config?: Partial<AlertConfig>) {
    this.config = { ...DEFAULT_ALERT_CONFIG, ...config };
    if (this.config.enabled && this.config.channels.length > 0) {
      this.startBatchTimer();
    }
  }

  /** Send an alert. Critical alerts go immediately; others are batched. */
  async alert(payload: AlertPayload): Promise<void> {
    if (!this.config.enabled) return;
    if (payload.severity === 'critical' || payload.severity === 'high') {
      await this.sendImmediate(payload);
    } else {
      this.pendingBatch.push(payload);
      if (this.pendingBatch.length >= this.config.maxBatchSize) {
        await this.flushBatch();
      }
    }
  }

  /** Force-send all pending alerts. */
  async flushBatch(): Promise<void> {
    if (this.pendingBatch.length === 0) return;
    const batch = this.pendingBatch.splice(0);
    const digestPayload: AlertPayload = {
      severity: 'medium',
      title: `AgentShield Digest: ${batch.length} events`,
      agentId: batch[0]?.agentId || 'unknown',
      details: batch.map(a => `[${a.severity}] ${a.title}`).join('\n'),
      timestamp: Date.now(),
    };
    await this.sendImmediate(digestPayload);
  }

  /** Get alert stats. */
  getStats(): { sent: number; failed: number; pending: number } {
    return { sent: this.sentCount, failed: this.failCount, pending: this.pendingBatch.length };
  }

  /** Stop the batch timer (for cleanup). */
  destroy(): void {
    if (this.batchTimer) { clearInterval(this.batchTimer); this.batchTimer = null; }
  }

  /** Add a channel at runtime. */
  addChannel(channel: AlertChannelConfig): void {
    this.config.channels.push(channel);
    if (!this.batchTimer) this.startBatchTimer();
  }

  // ─── Internal ─────────────────────────────────────────────────

  private async sendImmediate(payload: AlertPayload): Promise<void> {
    const severityNum = SEVERITY_ORDER[payload.severity];
    for (const channel of this.config.channels) {
      const minSev = SEVERITY_ORDER[channel.minSeverity];
      if (severityNum < minSev) continue;
      try {
        const body = this.formatPayload(payload, channel.type);
        await fetch(channel.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...channel.headers },
          body: JSON.stringify(body),
        });
        this.sentCount++;
      } catch (err) {
        this.failCount++;
        console.error(`[AgentShield:Alert] Failed to send to ${channel.type}: ${err}`);
      }
    }
  }

  private formatPayload(payload: AlertPayload, type: AlertChannel): unknown {
    const ts = new Date(payload.timestamp).toISOString();
    switch (type) {
      case 'slack':
        return {
          blocks: [
            { type: 'header', text: { type: 'plain_text', text: `🛡️ ${payload.title}` } },
            { type: 'section', text: { type: 'mrkdwn',
              text: `*Severity:* ${payload.severity}\n*Agent:* ${payload.agentId}\n*Time:* ${ts}\n\n${payload.details}` } },
          ],
        };
      case 'telegram':
        return {
          text: `🛡️ *AgentShield Alert*\n\n*${payload.title}*\nSeverity: ${payload.severity}\nAgent: ${payload.agentId}\nTime: ${ts}\n\n${payload.details}`,
          parse_mode: 'Markdown',
        };
      case 'discord':
        return {
          embeds: [{
            title: `🛡️ ${payload.title}`,
            description: payload.details,
            color: payload.severity === 'critical' ? 0xFF0000 : payload.severity === 'high' ? 0xFF8800 : 0xFFCC00,
            fields: [
              { name: 'Severity', value: payload.severity, inline: true },
              { name: 'Agent', value: payload.agentId, inline: true },
            ],
            timestamp: ts,
          }],
        };
      default:
        return payload;
    }
  }

  private startBatchTimer(): void {
    this.batchTimer = setInterval(() => { this.flushBatch().catch(console.error); }, this.config.batchIntervalMs);
  }
}
