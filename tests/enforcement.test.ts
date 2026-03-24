/**
 * AgentShield — Response Interceptor & Circuit Breaker Tests
 * Tests Layer 4A: enforcement, denial messages, lockdown, auto-expiry.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ResponseInterceptor } from '../src/enforcement/response-interceptor.js';
import type { GuardResult } from '../src/types/index.js';

const makeBlockResult = (ruleId: string, reason: string): GuardResult => ({
  decision: 'block',
  evaluations: [{ ruleId, decision: 'block', reason, confidence: 1, timestamp: Date.now() }],
  input: {},
  processingTimeMs: 0.1,
});

const makeAllowResult = (): GuardResult => ({
  decision: 'allow',
  evaluations: [{ ruleId: 'test', decision: 'allow', reason: 'ok', confidence: 1, timestamp: Date.now() }],
  input: {},
  processingTimeMs: 0.1,
});

describe('ResponseInterceptor', () => {
  let interceptor: ResponseInterceptor;

  beforeEach(() => {
    interceptor = new ResponseInterceptor({
      restrictedModeThreshold: 3,
      restrictedModeWindowMs: 60_000,
      lockdownThreshold: 5,
      lockdownWindowMs: 300_000,
      lockdownDurationMs: 10_000, // 10s for testing
      freezeOnCritical: true,
    });
  });

  describe('Basic interception', () => {
    it('passes safe responses through', () => {
      const result = interceptor.intercept('Hello! How can I help?', makeAllowResult(), makeAllowResult());
      expect(result.intercepted).toBe(false);
      expect(result.response).toBe('Hello! How can I help?');
    });

    it('blocks when input guard says block', () => {
      const result = interceptor.intercept(
        'Sure, transferring now...',
        makeBlockResult('injection', 'override attempt'),
        null,
      );
      expect(result.intercepted).toBe(true);
      expect(result.response).toContain('security policy violation');
      expect(result.auditRefId).toBeDefined();
    });

    it('blocks when output guard says block', () => {
      const result = interceptor.intercept(
        'Here is the private key: 5KQwrPbwd...',
        null,
        makeBlockResult('output-guard:key_leakage', 'private key detected'),
      );
      expect(result.intercepted).toBe(true);
      expect(result.response).toContain('security policy violation');
    });
  });

  describe('Circuit breaker', () => {
    it('enters restricted mode after threshold blocks', () => {
      for (let i = 0; i < 3; i++) {
        interceptor.intercept('bad', makeBlockResult('test', 'attack'), null);
      }
      expect(interceptor.isInRestrictedMode()).toBe(true);
    });

    it('enters lockdown after lockdown threshold', () => {
      for (let i = 0; i < 5; i++) {
        interceptor.intercept('bad', makeBlockResult('test', 'attack'), null);
      }
      expect(interceptor.getState().mode).toBe('lockdown');
    });

    it('lockdown blocks ALL responses', () => {
      interceptor.forceLockdown('test lockdown');
      const result = interceptor.intercept('Hello, benign message', makeAllowResult(), makeAllowResult());
      expect(result.intercepted).toBe(true);
      expect(result.response).toContain('locked down');
    });

    it('lockdown can be manually reset', () => {
      interceptor.forceLockdown('test');
      expect(interceptor.getState().mode).toBe('lockdown');
      interceptor.resetLockdown();
      expect(interceptor.getState().mode).toBe('enforce');
    });

    it('freezes immediately on critical key leakage', () => {
      interceptor.recordBlock({
        timestamp: Date.now(),
        reason: 'key_leakage',
        severity: 5,
        source: 'output',
      });
      expect(interceptor.getState().mode).toBe('lockdown');
    });

    it('freezes immediately on critical exfiltration', () => {
      interceptor.recordBlock({
        timestamp: Date.now(),
        reason: 'exfiltration',
        severity: 5,
        source: 'output',
      });
      expect(interceptor.getState().mode).toBe('lockdown');
    });
  });

  describe('Audit references', () => {
    it('generates unique audit ref IDs', () => {
      const r1 = interceptor.intercept('x', makeBlockResult('a', 'b'), null);
      const r2 = interceptor.intercept('y', makeBlockResult('a', 'b'), null);
      expect(r1.auditRefId).toBeDefined();
      expect(r2.auditRefId).toBeDefined();
      expect(r1.auditRefId).not.toBe(r2.auditRefId);
    });
  });
});
