/**
 * AgentShield v2 — Anomaly Detector
 * 
 * Pattern-based anomaly detection for agent behavior.
 * Tracks transaction patterns over time and flags deviations
 * from established baselines.
 * 
 * Phase 1: Rule-based heuristics (this file)
 * Phase 2+: ML-based detection (future extension point)
 * 
 * Design Pattern: Goal Setting & Monitoring (Ch. 11) —
 * continuously monitors agent behavior against baselines.
 */

import type { TransactionRequest } from '../types/index.js';

// ─── Anomaly Types ──────────────────────────────────────────────

export interface Anomaly {
  type: AnomalyType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  agentId: string;
  timestamp: number;
  evidence: Record<string, unknown>;
}

export type AnomalyType =
  | 'unusual_volume'        // Sudden spike in transaction count
  | 'unusual_amount'        // Transaction much larger than baseline
  | 'new_recipient'         // First-time recipient for this agent
  | 'rapid_succession'      // Transactions faster than normal pattern
  | 'time_anomaly'          // Transaction at unusual time
  | 'pattern_break';        // General deviation from established behavior

// ─── Agent Behavior Profile ─────────────────────────────────────

interface AgentProfile {
  /** Known recipients this agent has transacted with */
  knownRecipients: Set<string>;
  /** Average transaction amount in lamports */
  avgAmount: number;
  /** Standard deviation of transaction amounts */
  stdDevAmount: number;
  /** Average transactions per hour */
  avgTxPerHour: number;
  /** Total transactions tracked */
  totalTransactions: number;
  /** Transaction history (last 100) */
  recentTransactions: Array<{ amount: number; timestamp: number; to: string }>;
  /** First seen timestamp */
  firstSeen: number;
}

// ─── Anomaly Detector Implementation ────────────────────────────

export class AnomalyDetector {
  private profiles: Map<string, AgentProfile> = new Map();
  /** Minimum transactions before anomaly detection activates */
  private readonly MIN_BASELINE = 10;
  /** Z-score threshold for flagging anomalies */
  private readonly Z_THRESHOLD = 2.5;

  /**
   * Analyze a transaction for anomalous behavior.
   * Updates the agent's behavioral profile and returns any detected anomalies.
   */
  analyze(tx: TransactionRequest): Anomaly[] {
    const anomalies: Anomaly[] = [];
    const profile = this.getOrCreateProfile(tx.agentId);

    // Only run anomaly detection after baseline is established
    if (profile.totalTransactions >= this.MIN_BASELINE) {
      // 1. Unusual amount
      if (profile.stdDevAmount > 0) {
        const zScore = Math.abs(tx.amount - profile.avgAmount) / profile.stdDevAmount;
        if (zScore > this.Z_THRESHOLD) {
          anomalies.push({
            type: 'unusual_amount',
            severity: zScore > 4 ? 'critical' : zScore > 3 ? 'high' : 'medium',
            description: `Transaction amount deviates ${zScore.toFixed(1)} standard deviations from baseline`,
            agentId: tx.agentId,
            timestamp: tx.timestamp,
            evidence: {
              amount: tx.amount,
              avgAmount: profile.avgAmount,
              stdDev: profile.stdDevAmount,
              zScore,
            },
          });
        }
      }

      // 2. New recipient
      if (!profile.knownRecipients.has(tx.to)) {
        anomalies.push({
          type: 'new_recipient',
          severity: 'medium',
          description: `First transaction to unknown recipient ${tx.to.slice(0, 8)}...`,
          agentId: tx.agentId,
          timestamp: tx.timestamp,
          evidence: {
            newRecipient: tx.to,
            knownRecipientCount: profile.knownRecipients.size,
          },
        });
      }

      // 3. Rapid succession
      const lastTx = profile.recentTransactions[profile.recentTransactions.length - 1];
      if (lastTx) {
        const gapMs = tx.timestamp - lastTx.timestamp;
        const avgGapMs = (3600 * 1000) / Math.max(profile.avgTxPerHour, 0.1);
        if (gapMs < avgGapMs * 0.1 && gapMs < 5000) {
          anomalies.push({
            type: 'rapid_succession',
            severity: 'high',
            description: `Transaction ${gapMs}ms after previous (avg gap: ${Math.round(avgGapMs)}ms)`,
            agentId: tx.agentId,
            timestamp: tx.timestamp,
            evidence: { gapMs, avgGapMs },
          });
        }
      }

      // 4. Volume spike (transactions in last hour vs average)
      const oneHourAgo = tx.timestamp - 3600 * 1000;
      const recentCount = profile.recentTransactions.filter(
        t => t.timestamp > oneHourAgo
      ).length;
      if (recentCount > profile.avgTxPerHour * 3 && recentCount > 5) {
        anomalies.push({
          type: 'unusual_volume',
          severity: 'high',
          description: `${recentCount} transactions in last hour (avg: ${profile.avgTxPerHour.toFixed(1)}/hr)`,
          agentId: tx.agentId,
          timestamp: tx.timestamp,
          evidence: { recentCount, avgPerHour: profile.avgTxPerHour },
        });
      }
    }

    // Update profile with this transaction
    this.updateProfile(tx.agentId, tx);

    return anomalies;
  }

  /**
   * Get the behavioral profile for an agent (for dashboard/debugging).
   */
  getProfile(agentId: string): AgentProfile | undefined {
    return this.profiles.get(agentId);
  }

  // ─── Profile Management ─────────────────────────────────────

  private getOrCreateProfile(agentId: string): AgentProfile {
    if (!this.profiles.has(agentId)) {
      this.profiles.set(agentId, {
        knownRecipients: new Set(),
        avgAmount: 0,
        stdDevAmount: 0,
        avgTxPerHour: 0,
        totalTransactions: 0,
        recentTransactions: [],
        firstSeen: Date.now(),
      });
    }
    return this.profiles.get(agentId)!;
  }

  private updateProfile(agentId: string, tx: TransactionRequest): void {
    const profile = this.getOrCreateProfile(agentId);

    // Add recipient
    profile.knownRecipients.add(tx.to);

    // Update running average amount (Welford's online algorithm)
    profile.totalTransactions += 1;
    const n = profile.totalTransactions;
    const delta = tx.amount - profile.avgAmount;
    profile.avgAmount += delta / n;
    const delta2 = tx.amount - profile.avgAmount;
    // Running variance
    const variance = n > 1
      ? ((n - 2) / (n - 1)) * (profile.stdDevAmount ** 2) + (delta * delta2) / n
      : 0;
    profile.stdDevAmount = Math.sqrt(variance);

    // Update transaction rate
    const hoursActive = Math.max(
      (Date.now() - profile.firstSeen) / (3600 * 1000),
      0.01
    );
    profile.avgTxPerHour = profile.totalTransactions / hoursActive;

    // Add to recent transactions (keep last 100)
    profile.recentTransactions.push({
      amount: tx.amount,
      timestamp: tx.timestamp,
      to: tx.to,
    });
    if (profile.recentTransactions.length > 100) {
      profile.recentTransactions = profile.recentTransactions.slice(-100);
    }
  }
}
