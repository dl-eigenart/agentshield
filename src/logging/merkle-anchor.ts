/**
 * AgentShield Layer 5 — Merkle Root Anchoring on Solana
 *
 * Periodically writes the MerkleAuditTrail root hash to Solana
 * to provide immutable, cryptographic proof that audit logs
 * haven't been tampered with.
 *
 * Architecture:
 *   MerkleAuditTrail (in-memory)
 *     → checkpoint() produces a root hash
 *     → MerkleAnchor writes it to a Solana PDA via memo program
 *     → Anyone can verify the root against the on-chain record
 *
 * Uses Solana Memo Program (no custom program needed) for
 * lightweight, low-cost anchoring (~0.000005 SOL per anchor).
 */

// @ts-ignore — @solana/web3.js is an optional peer dependency
import {
  Connection,
  PublicKey,
  Keypair,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from '@solana/web3.js';
import type { MerkleAuditTrail, AuditCheckpoint } from './merkle-audit';

// ─── Constants ─────────────────────────────────────────────────

/** Solana Memo Program v2 */
const MEMO_PROGRAM_ID = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');

const DEFAULT_RPC = 'https://api.devnet.solana.com';
const ANCHOR_PREFIX = 'AGENTSHIELD_MERKLE_V1';

// ─── Types ─────────────────────────────────────────────────────

export interface AnchorRecord {
  /** Merkle root hash */
  merkleRoot: string;
  /** Number of events at time of anchoring */
  eventCount: number;
  /** Unix timestamp (ms) when anchored */
  anchoredAt: number;
  /** Solana transaction signature */
  signature: string;
  /** Slot number for verification */
  slot: number;
  /** Cost in lamports */
  cost: number;
}

export interface MerkleAnchorConfig {
  /** Solana RPC endpoint */
  rpcEndpoint: string;
  /** Keypair for signing anchor transactions (operator wallet) */
  signerKeypair: Keypair;
  /** Auto-anchor interval in ms (0 = disabled) */
  autoAnchorIntervalMs: number;
  /** Minimum events between anchors (prevents spam) */
  minEventsBetweenAnchors: number;
  /** Enable/disable anchoring */
  enabled: boolean;
}

const DEFAULT_CONFIG: MerkleAnchorConfig = {
  rpcEndpoint: DEFAULT_RPC,
  signerKeypair: Keypair.generate(), // placeholder
  autoAnchorIntervalMs: 0,
  minEventsBetweenAnchors: 50,
  enabled: false,
};

// ─── Merkle Anchor Service ─────────────────────────────────────

export class MerkleAnchor {
  private config: MerkleAnchorConfig;
  private connection: Connection;
  private auditTrail: MerkleAuditTrail;
  private anchorHistory: AnchorRecord[] = [];
  private lastAnchoredEventCount = 0;
  private intervalHandle: ReturnType<typeof setInterval> | null = null;

  constructor(auditTrail: MerkleAuditTrail, config?: Partial<MerkleAnchorConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.connection = new Connection(this.config.rpcEndpoint, 'confirmed');
    this.auditTrail = auditTrail;

    if (this.config.enabled && this.config.autoAnchorIntervalMs > 0) {
      this.startAutoAnchor();
    }
  }

  /**
   * Anchor the current Merkle root to Solana.
   * Writes a memo transaction with the root hash, event count, and timestamp.
   * Returns the anchor record or null if anchoring conditions aren't met.
   */
  async anchor(): Promise<AnchorRecord | null> {
    if (!this.config.enabled) return null;

    const currentCount = this.auditTrail.getEventCount();
    const delta = currentCount - this.lastAnchoredEventCount;

    if (delta < this.config.minEventsBetweenAnchors) {
      return null; // Not enough new events
    }

    // Create checkpoint and get root
    const checkpoint = this.auditTrail.createCheckpoint();
    const memoData = this.encodeMemo(checkpoint);

    try {
      const { signature, slot, cost } = await this.sendMemoTransaction(memoData);

      const record: AnchorRecord = {
        merkleRoot: checkpoint.merkleRoot,
        eventCount: checkpoint.eventCount,
        anchoredAt: Date.now(),
        signature,
        slot,
        cost,
      };

      this.anchorHistory.push(record);
      this.lastAnchoredEventCount = currentCount;

      return record;
    } catch (err) {
      console.error('[MerkleAnchor] Failed to anchor:', err);
      return null;
    }
  }

  /**
   * Verify a previously anchored root against on-chain data.
   * Fetches the transaction memo and compares with the stored record.
   */
  async verify(record: AnchorRecord): Promise<{
    valid: boolean;
    onChainMemo: string | null;
    reason: string;
  }> {
    try {
      const tx = await this.connection.getTransaction(record.signature, {
        maxSupportedTransactionVersion: 0,
      });

      if (!tx) {
        return { valid: false, onChainMemo: null, reason: 'Transaction not found on-chain' };
      }

      // Extract memo from transaction log messages
      const memoLog = tx.meta?.logMessages?.find((m: string) => m.includes(ANCHOR_PREFIX));
      if (!memoLog) {
        return { valid: false, onChainMemo: null, reason: 'No AgentShield memo found in transaction' };
      }

      // Parse the memo data from the log
      const memoMatch = memoLog.match(/Program log: Memo \(len \d+\): "(.*?)"/);
      const onChainMemo = memoMatch ? memoMatch[1] : memoLog;

      const valid = onChainMemo.includes(record.merkleRoot);
      return {
        valid,
        onChainMemo,
        reason: valid ? 'Merkle root matches on-chain record' : 'Merkle root mismatch — possible tampering',
      };
    } catch (err) {
      return { valid: false, onChainMemo: null, reason: `Verification error: ${err}` };
    }
  }

  /** Start automatic periodic anchoring. */
  startAutoAnchor(): void {
    if (this.intervalHandle) return;
    this.intervalHandle = setInterval(async () => {
      const record = await this.anchor();
      if (record) {
        console.log(`[MerkleAnchor] Anchored root ${record.merkleRoot.slice(0, 16)}... (${record.eventCount} events) → tx: ${record.signature.slice(0, 16)}...`);
      }
    }, this.config.autoAnchorIntervalMs);
  }

  /** Stop automatic anchoring. */
  stopAutoAnchor(): void {
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
  }

  /** Get all anchor records. */
  getHistory(): AnchorRecord[] {
    return [...this.anchorHistory];
  }

  /** Get the latest anchor record. */
  getLatest(): AnchorRecord | null {
    return this.anchorHistory.length > 0
      ? this.anchorHistory[this.anchorHistory.length - 1]
      : null;
  }

  /** Get total anchoring cost in SOL. */
  getTotalCostSol(): number {
    return this.anchorHistory.reduce((sum, r) => sum + r.cost, 0) / LAMPORTS_PER_SOL;
  }

  /** Get stats for the dashboard. */
  getStats(): {
    totalAnchors: number;
    lastAnchorTime: number | null;
    lastMerkleRoot: string | null;
    lastSignature: string | null;
    totalCostSol: number;
    eventsSinceLastAnchor: number;
  } {
    const latest = this.getLatest();
    return {
      totalAnchors: this.anchorHistory.length,
      lastAnchorTime: latest?.anchoredAt ?? null,
      lastMerkleRoot: latest?.merkleRoot ?? null,
      lastSignature: latest?.signature ?? null,
      totalCostSol: this.getTotalCostSol(),
      eventsSinceLastAnchor: this.auditTrail.getEventCount() - this.lastAnchoredEventCount,
    };
  }

  // ─── Internal ──────────────────────────────────────────────────

  private encodeMemo(checkpoint: AuditCheckpoint): string {
    return `${ANCHOR_PREFIX}|${checkpoint.merkleRoot}|${checkpoint.eventCount}|${checkpoint.timestamp}`;
  }

  private async sendMemoTransaction(memo: string): Promise<{
    signature: string;
    slot: number;
    cost: number;
  }> {
    const instruction = new TransactionInstruction({
      keys: [{ pubkey: this.config.signerKeypair.publicKey, isSigner: true, isWritable: false }],
      programId: MEMO_PROGRAM_ID,
      data: Buffer.from(memo, 'utf-8'),
    });

    const tx = new Transaction().add(instruction);
    const balanceBefore = await this.connection.getBalance(this.config.signerKeypair.publicKey);

    const signature = await sendAndConfirmTransaction(this.connection, tx, [this.config.signerKeypair]);

    const balanceAfter = await this.connection.getBalance(this.config.signerKeypair.publicKey);
    const txInfo = await this.connection.getTransaction(signature, { maxSupportedTransactionVersion: 0 });

    return {
      signature,
      slot: txInfo?.slot ?? 0,
      cost: balanceBefore - balanceAfter,
    };
  }
}
