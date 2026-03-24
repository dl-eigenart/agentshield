/**
 * AgentShield Layer 5 — Merkle Audit Trail
 *
 * Tamper-proof audit log using a Merkle tree. Events are hashed
 * and chained so any retroactive modification is detectable.
 *
 * The Merkle root can be anchored on Solana periodically to provide
 * cryptographic proof that logs haven't been tampered with.
 *
 * Uses SHA-256 via Node.js crypto module (zero dependencies).
 */

import { createHash } from 'crypto';

// ─── Types ──────────────────────────────────────────────────────

export interface MerkleNode {
  hash: string;
  left?: string;
  right?: string;
}

export interface AuditCheckpoint {
  /** Merkle root at this checkpoint */
  merkleRoot: string;
  /** Number of events included */
  eventCount: number;
  /** Timestamp of checkpoint */
  timestamp: number;
  /** Optional: Solana transaction signature anchoring this root */
  solanaSignature?: string;
}

// ─── Merkle Audit Trail ─────────────────────────────────────────

export class MerkleAuditTrail {
  private leaves: string[] = [];
  private checkpoints: AuditCheckpoint[] = [];
  private checkpointInterval: number;

  constructor(options?: { checkpointInterval?: number }) {
    this.checkpointInterval = options?.checkpointInterval ?? 100;
  }

  /** Add an event to the audit trail. Returns its leaf hash. */
  addEvent(eventData: string): string {
    const leaf = this.hashLeaf(eventData);
    this.leaves.push(leaf);
    // Auto-checkpoint
    if (this.leaves.length % this.checkpointInterval === 0) {
      this.createCheckpoint();
    }
    return leaf;
  }

  /** Compute the current Merkle root. */
  computeRoot(): string {
    if (this.leaves.length === 0) return this.hash('empty');
    return this.buildTree(this.leaves);
  }

  /** Create a checkpoint with the current Merkle root. */
  createCheckpoint(): AuditCheckpoint {
    const checkpoint: AuditCheckpoint = {
      merkleRoot: this.computeRoot(),
      eventCount: this.leaves.length,
      timestamp: Date.now(),
    };
    this.checkpoints.push(checkpoint);
    return checkpoint;
  }

  /** Verify that a specific event exists in the trail. */
  verifyEvent(eventData: string): boolean {
    const leaf = this.hashLeaf(eventData);
    return this.leaves.includes(leaf);
  }

  /** Verify the entire trail integrity against a checkpoint. */
  verifyIntegrity(checkpoint?: AuditCheckpoint): boolean {
    const target = checkpoint || this.checkpoints[this.checkpoints.length - 1];
    if (!target) return this.leaves.length === 0;
    const currentRoot = this.buildTree(this.leaves.slice(0, target.eventCount));
    return currentRoot === target.merkleRoot;
  }

  /** Get all checkpoints. */
  getCheckpoints(): AuditCheckpoint[] { return [...this.checkpoints]; }

  /** Get event count. */
  getEventCount(): number { return this.leaves.length; }

  /** Get leaf hashes for external verification. */
  getLeaves(): string[] { return [...this.leaves]; }

  // ─── Internal ─────────────────────────────────────────────────

  private hashLeaf(data: string): string {
    return this.hash(`leaf:${data}`);
  }

  private hash(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }

  private hashPair(left: string, right: string): string {
    // Ensure consistent ordering for deterministic trees
    const ordered = left < right ? left + right : right + left;
    return this.hash(ordered);
  }

  private buildTree(leaves: string[]): string {
    if (leaves.length === 0) return this.hash('empty');
    if (leaves.length === 1) return leaves[0];

    let level = [...leaves];
    while (level.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 < level.length) {
          nextLevel.push(this.hashPair(level[i], level[i + 1]));
        } else {
          // Odd node: promote to next level
          nextLevel.push(level[i]);
        }
      }
      level = nextLevel;
    }
    return level[0];
  }
}
