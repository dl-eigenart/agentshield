/**
 * AgentShield — Merkle Audit Trail Tests
 * Tests Layer 5: tamper-proof event hashing, integrity verification.
 */

import { describe, it, expect } from 'vitest';
import { MerkleAuditTrail } from '../src/logging/merkle-audit.js';

describe('MerkleAuditTrail', () => {
  describe('Event tracking', () => {
    it('adds events and returns hashes', () => {
      const trail = new MerkleAuditTrail();
      const hash1 = trail.addEvent('event-1');
      const hash2 = trail.addEvent('event-2');
      expect(hash1).toHaveLength(64); // SHA-256 hex
      expect(hash2).toHaveLength(64);
      expect(hash1).not.toBe(hash2);
      expect(trail.getEventCount()).toBe(2);
    });

    it('verifies existing events', () => {
      const trail = new MerkleAuditTrail();
      trail.addEvent('event-1');
      trail.addEvent('event-2');
      expect(trail.verifyEvent('event-1')).toBe(true);
      expect(trail.verifyEvent('event-3')).toBe(false);
    });
  });

  describe('Merkle root computation', () => {
    it('computes deterministic root', () => {
      const t1 = new MerkleAuditTrail();
      const t2 = new MerkleAuditTrail();
      t1.addEvent('a'); t1.addEvent('b'); t1.addEvent('c');
      t2.addEvent('a'); t2.addEvent('b'); t2.addEvent('c');
      expect(t1.computeRoot()).toBe(t2.computeRoot());
    });

    it('different events produce different roots', () => {
      const t1 = new MerkleAuditTrail();
      const t2 = new MerkleAuditTrail();
      t1.addEvent('a'); t1.addEvent('b');
      t2.addEvent('a'); t2.addEvent('c');
      expect(t1.computeRoot()).not.toBe(t2.computeRoot());
    });

    it('single event has a valid root', () => {
      const trail = new MerkleAuditTrail();
      trail.addEvent('only-one');
      const root = trail.computeRoot();
      expect(root).toHaveLength(64);
    });
  });

  describe('Checkpoints & integrity', () => {
    it('creates checkpoint with correct count', () => {
      const trail = new MerkleAuditTrail();
      trail.addEvent('a'); trail.addEvent('b'); trail.addEvent('c');
      const cp = trail.createCheckpoint();
      expect(cp.eventCount).toBe(3);
      expect(cp.merkleRoot).toHaveLength(64);
    });

    it('verifies integrity against checkpoint', () => {
      const trail = new MerkleAuditTrail();
      trail.addEvent('a'); trail.addEvent('b');
      const cp = trail.createCheckpoint();
      // Add more events after checkpoint
      trail.addEvent('c');
      // Integrity check against the checkpoint should still pass
      expect(trail.verifyIntegrity(cp)).toBe(true);
    });

    it('auto-checkpoints at interval', () => {
      const trail = new MerkleAuditTrail({ checkpointInterval: 3 });
      trail.addEvent('a'); trail.addEvent('b'); trail.addEvent('c');
      expect(trail.getCheckpoints().length).toBe(1);
      trail.addEvent('d'); trail.addEvent('e'); trail.addEvent('f');
      expect(trail.getCheckpoints().length).toBe(2);
    });
  });
});
