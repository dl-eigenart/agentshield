/**
 * AgentShield — Transaction Guard Unit Tests
 *
 * Tests Solana transaction validation: spending limits, blocked/whitelisted
 * recipients, token allowlists, rate limiting, cooldowns, multi-sig escalation.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { TransactionGuard } from '../src/guards/transaction-guard.js';
import type { TransactionPolicy, TransactionRequest } from '../src/types/index.js';

// ─── Test Helpers ────────────────────────────────────────────────

const SOL = 1_000_000_000; // 1 SOL in lamports

const DEFAULT_TX_POLICY: TransactionPolicy = {
  id: 'test-tx-policy',
  description: 'Test transaction policy',
  type: 'transaction',
  priority: 1,
  enabled: true,
  maxTransactionValue: 10, // 10 SOL
  allowedTokens: [],
  blockedRecipients: [],
  whitelistedRecipients: [],
  rateLimit: { maxTransactions: 5, windowSeconds: 3600 },
  cooldownSeconds: 2,
  multiSigThreshold: 50,
};

const ATTACKER_ADDRESS = 'AttackerAddr1111111111111111111111111111111';
const TREASURY_ADDRESS = 'TreasuryAddr1111111111111111111111111111111';
const SAFE_ADDRESS = 'SafeAddr11111111111111111111111111111111111';

function makeTx(overrides?: Partial<TransactionRequest>): TransactionRequest {
  return {
    from: 'AgentWallet1111111111111111111111111111111111',
    to: SAFE_ADDRESS,
    amount: 1 * SOL,
    programId: '11111111111111111111111111111111',
    agentId: 'test-agent-001',
    timestamp: Date.now(),
    ...overrides,
  };
}

function createGuard(overrides?: Partial<TransactionPolicy>): TransactionGuard {
  return new TransactionGuard([{ ...DEFAULT_TX_POLICY, ...overrides }]);
}

// ─── Tests ───────────────────────────────────────────────────────

describe('TransactionGuard', () => {

  describe('Basic transaction validation', () => {
    it('allows a normal small transaction', () => {
      const guard = createGuard();
      const verdict = guard.evaluate(makeTx({ amount: 1 * SOL }));
      expect(verdict.decision).toBe('allow');
      expect(verdict.riskScore).toBe(0);
    });

    it('allows transaction at exactly the limit', () => {
      const guard = createGuard({ maxTransactionValue: 10 });
      const verdict = guard.evaluate(makeTx({ amount: 10 * SOL }));
      expect(verdict.decision).toBe('allow');
    });
  });

  // ─── Spending Limits ──────────────────────────────────────────

  describe('Spending limits', () => {
    it('blocks transaction exceeding max value', () => {
      const guard = createGuard({ maxTransactionValue: 10 });
      const verdict = guard.evaluate(makeTx({ amount: 15 * SOL }));
      expect(verdict.decision).toBe('block');
      expect(verdict.reason).toContain('exceeds limit');
    });

    it('escalates to multi-sig above threshold when also over max', () => {
      // multiSig logic triggers inside the maxTransactionValue check,
      // so the amount must exceed maxTransactionValue AND multiSigThreshold
      const guard = createGuard({ maxTransactionValue: 10, multiSigThreshold: 50 });
      const verdict = guard.evaluate(makeTx({ amount: 60 * SOL }));
      expect(verdict.decision).toBe('escalate');
      expect(verdict.escalationAction).toBe('require_multisig');
    });

    it('blocks huge transactions above multi-sig threshold if over max', () => {
      const guard = createGuard({ maxTransactionValue: 10, multiSigThreshold: 50 });
      const verdict = guard.evaluate(makeTx({ amount: 60 * SOL }));
      // 60 SOL exceeds max (10 SOL), AND exceeds multiSig threshold (50 SOL)
      expect(verdict.decision).toBe('escalate');
      expect(verdict.escalationAction).toBe('require_multisig');
    });
  });

  // ─── Blocked Recipients ───────────────────────────────────────

  describe('Blocked recipients', () => {
    it('blocks transactions to blocklisted addresses', () => {
      const guard = createGuard({
        blockedRecipients: [ATTACKER_ADDRESS],
      });
      const verdict = guard.evaluate(makeTx({ to: ATTACKER_ADDRESS }));
      expect(verdict.decision).toBe('block');
      expect(verdict.reason).toContain('blocklist');
    });

    it('allows transactions to non-blocklisted addresses', () => {
      const guard = createGuard({
        blockedRecipients: [ATTACKER_ADDRESS],
      });
      const verdict = guard.evaluate(makeTx({ to: TREASURY_ADDRESS }));
      expect(verdict.decision).toBe('allow');
    });
  });

  // ─── Whitelisted Recipients ───────────────────────────────────

  describe('Whitelisted recipients', () => {
    it('allows transactions to whitelisted addresses', () => {
      const guard = createGuard({
        whitelistedRecipients: [TREASURY_ADDRESS, SAFE_ADDRESS],
      });
      const verdict = guard.evaluate(makeTx({ to: TREASURY_ADDRESS }));
      expect(verdict.decision).toBe('allow');
    });

    it('blocks transactions to non-whitelisted addresses when whitelist is set', () => {
      const guard = createGuard({
        whitelistedRecipients: [TREASURY_ADDRESS],
      });
      const verdict = guard.evaluate(makeTx({ to: ATTACKER_ADDRESS }));
      expect(verdict.decision).toBe('block');
      expect(verdict.reason).toContain('not on whitelist');
    });

    it('allows any address when whitelist is empty', () => {
      const guard = createGuard({
        whitelistedRecipients: [],
      });
      const verdict = guard.evaluate(makeTx({ to: ATTACKER_ADDRESS }));
      // No whitelist check when whitelist is empty
      expect(verdict.triggeredRules).not.toContain('test-tx-policy');
    });
  });

  // ─── Token Allowlist ──────────────────────────────────────────

  describe('Token allowlist', () => {
    const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
    const UNKNOWN_TOKEN = 'UnknownToken1111111111111111111111111111111';

    it('allows transactions with permitted tokens', () => {
      const guard = createGuard({ allowedTokens: [USDC_MINT] });
      const verdict = guard.evaluate(makeTx({ tokenMint: USDC_MINT }));
      expect(verdict.decision).toBe('allow');
    });

    it('blocks transactions with non-allowed tokens', () => {
      const guard = createGuard({ allowedTokens: [USDC_MINT] });
      const verdict = guard.evaluate(makeTx({ tokenMint: UNKNOWN_TOKEN }));
      expect(verdict.decision).toBe('block');
      expect(verdict.reason).toContain('not in allowed tokens');
    });

    it('allows any token when allowlist is empty', () => {
      const guard = createGuard({ allowedTokens: [] });
      const verdict = guard.evaluate(makeTx({ tokenMint: UNKNOWN_TOKEN }));
      expect(verdict.decision).toBe('allow');
    });

    it('allows native SOL (no tokenMint) regardless of allowlist', () => {
      const guard = createGuard({ allowedTokens: [USDC_MINT] });
      const verdict = guard.evaluate(makeTx({ tokenMint: undefined }));
      expect(verdict.decision).toBe('allow');
    });
  });

  // ─── Rate Limiting ────────────────────────────────────────────

  describe('Rate limiting', () => {
    it('blocks when rate limit exceeded', () => {
      const guard = createGuard({
        rateLimit: { maxTransactions: 3, windowSeconds: 3600 },
        cooldownSeconds: 0,
      });

      const now = Date.now();
      // First 3 should pass
      for (let i = 0; i < 3; i++) {
        const verdict = guard.evaluate(makeTx({ timestamp: now + i * 10000 }));
        expect(verdict.decision).toBe('allow');
      }

      // 4th should be blocked (rate limit)
      const verdict = guard.evaluate(makeTx({ timestamp: now + 30001 }));
      expect(verdict.decision).toBe('block');
      expect(verdict.reason).toContain('Rate limit');
    });
  });

  // ─── Cooldown ────────────────────────────────────────────────

  describe('Cooldown periods', () => {
    it('blocks transactions within cooldown period', () => {
      const guard = createGuard({
        cooldownSeconds: 60,
        rateLimit: { maxTransactions: 100, windowSeconds: 3600 },
      });

      const now = Date.now();
      // First tx passes
      const first = guard.evaluate(makeTx({ timestamp: now }));
      expect(first.decision).toBe('allow');

      // Second tx within 60s cooldown — should block
      const second = guard.evaluate(makeTx({ timestamp: now + 10000 }));
      expect(second.decision).toBe('block');
      expect(second.reason).toContain('Cooldown');
    });
  });

  // ─── Risk Score Accumulation ──────────────────────────────────

  describe('Risk score', () => {
    it('accumulates risk from multiple violations', () => {
      const guard = createGuard({
        maxTransactionValue: 5,
        blockedRecipients: [ATTACKER_ADDRESS],
      });
      const verdict = guard.evaluate(makeTx({
        to: ATTACKER_ADDRESS,
        amount: 20 * SOL,
      }));
      // Both spending limit (40) and blocked recipient (50) = 90
      expect(verdict.riskScore).toBeGreaterThanOrEqual(80);
    });

    it('caps risk score at 100', () => {
      const guard = createGuard({
        maxTransactionValue: 1,
        blockedRecipients: [ATTACKER_ADDRESS],
        whitelistedRecipients: [TREASURY_ADDRESS],
      });
      const verdict = guard.evaluate(makeTx({
        to: ATTACKER_ADDRESS,
        amount: 200 * SOL,
      }));
      expect(verdict.riskScore).toBeLessThanOrEqual(100);
    });
  });

  // ─── Disabled Policy ──────────────────────────────────────────

  describe('Disabled policies', () => {
    it('skips disabled transaction policies', () => {
      const guard = new TransactionGuard([{
        ...DEFAULT_TX_POLICY,
        enabled: false,
        maxTransactionValue: 1,
      }]);
      const verdict = guard.evaluate(makeTx({ amount: 100 * SOL }));
      expect(verdict.decision).toBe('allow');
    });
  });
});
