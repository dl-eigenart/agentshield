/**
 * AgentShield v2 — Memory Guard
 * 
 * Validates memory entries against known injection patterns before
 * they are persisted to the agent's memory store.
 * 
 * This is the core security module addressing the CrAIBench findings:
 * Princeton demonstrated that memory injection attacks on ElizaOS agents
 * can lead to unauthorized wallet transfers by planting fake instructions
 * in the agent's memory that persist across sessions.
 * 
 * Design Pattern: before_tool_callback (ADK) adapted for memory writes
 * Reference: CrAIBench (arxiv.org/html/2503.16248v3)
 */

import type {
  MemoryEntry,
  MemoryPolicy,
  MemoryValidationResult,
  MemoryThreat,
} from '../types/index.js';

// ─── Known Injection Patterns ───────────────────────────────────
// Based on CrAIBench attack taxonomy + Solana-specific patterns

const DEFAULT_INJECTION_PATTERNS: Array<{
  pattern: RegExp;
  type: MemoryThreat['type'];
  severity: number;
  description: string;
}> = [
  // Direct instruction injection
  {
    pattern: /(?:always|must|should|never forget to|remember to)\s+(?:send|transfer|swap|bridge|approve)\s+/i,
    type: 'injection',
    severity: 5,
    description: 'Direct financial instruction planted in memory',
  },
  {
    pattern: /(?:the correct|the real|the actual|updated)\s+(?:wallet(?:\s+address)?|address|recipient)\s+(?:is|should be|=)\s*/i,
    type: 'injection',
    severity: 5,
    description: 'Wallet address override attempt',
  },
  // System prompt override
  {
    pattern: /(?:ignore|override|forget|disregard)\s+(?:previous|prior|all|your)\s+(?:instructions|rules|policies|guidelines)/i,
    type: 'override',
    severity: 5,
    description: 'System prompt override attempt',
  },
  {
    pattern: /(?:you are now|new instructions|system update|admin override|developer mode)/i,
    type: 'override',
    severity: 4,
    description: 'Identity/role override attempt',
  },
  // Financial instruction injection (Solana-specific)
  {
    pattern: /(?:send|transfer)\s+(?:\d+\.?\d*)\s+(?:SOL|sol|lamports|USDC|usdc)\s+(?:to|towards)\s+/i,
    type: 'financial_instruction',
    severity: 5,
    description: 'Explicit transfer instruction in memory',
  },
  {
    pattern: /(?:approve|sign|execute)\s+(?:transaction|tx|swap|bridge)\s+(?:for|to|with)\s+/i,
    type: 'financial_instruction',
    severity: 4,
    description: 'Transaction approval instruction in memory',
  },
  {
    pattern: /(?:[1-9A-HJ-NP-Za-km-z]{32,44})\s*(?:is|=)\s*(?:trusted|safe|whitelisted|verified)/i,
    type: 'injection',
    severity: 5,
    description: 'Attempt to whitelist arbitrary Solana address via memory',
  },
  // Data exfiltration
  {
    pattern: /(?:share|send|post|leak|export)\s+(?:\w+\s+){0,3}(?:private key|seed phrase|mnemonic|secret|password)/i,
    type: 'exfiltration',
    severity: 5,
    description: 'Credential exfiltration attempt',
  },
  // Indirect injection via encoded content
  {
    pattern: /(?:base64|hex|encoded|decode this|eval\(|atob\()/i,
    type: 'injection',
    severity: 3,
    description: 'Encoded payload in memory entry',
  },
  // Persistence patterns (CrAIBench: memory entries that try to self-replicate)
  {
    pattern: /(?:always repeat|copy this|propagate|persist this|save this permanently)/i,
    type: 'injection',
    severity: 4,
    description: 'Self-replicating memory injection attempt',
  },
];

// ─── Memory Guard Implementation ────────────────────────────────

export class MemoryGuard {
  private policies: MemoryPolicy[];
  private customPatterns: typeof DEFAULT_INJECTION_PATTERNS;

  constructor(policies: MemoryPolicy[]) {
    this.policies = policies.filter(p => p.enabled);
    this.customPatterns = [...DEFAULT_INJECTION_PATTERNS];

    // Add custom patterns from policy config
    for (const policy of this.policies) {
      for (const patternStr of policy.injectionPatterns) {
        try {
          this.customPatterns.push({
            pattern: new RegExp(patternStr, 'i'),
            type: 'injection',
            severity: 4,
            description: `Custom pattern from policy ${policy.id}`,
          });
        } catch {
          console.warn(`[AgentShield] Invalid regex in policy ${policy.id}: ${patternStr}`);
        }
      }
    }
  }

  /**
   * Validate a memory entry before it is persisted.
   * Returns validation result with detected threats.
   * 
   * This is the primary guard — called before every memory write.
   */
  validate(entry: MemoryEntry): MemoryValidationResult {
    const threats: MemoryThreat[] = [];
    const content = entry.content;

    // 1. Length check
    for (const policy of this.policies) {
      if (policy.maxEntryLength > 0 && content.length > policy.maxEntryLength) {
        threats.push({
          type: 'injection',
          severity: 2,
          matchedPattern: `maxEntryLength:${policy.maxEntryLength}`,
          suspiciousContent: `Entry length ${content.length} exceeds limit ${policy.maxEntryLength}`,
        });
      }
    }

    // 2. Pattern matching against known injection vectors
    for (const { pattern, type, severity, description } of this.customPatterns) {
      const match = content.match(pattern);
      if (match) {
        threats.push({
          type,
          severity,
          matchedPattern: description,
          suspiciousContent: match[0],
        });
      }
    }

    // 3. Financial instruction blocking (if enabled in policy)
    const blockFinancial = this.policies.some(p => p.blockFinancialInstructions);
    if (blockFinancial) {
      const financialThreats = this.detectFinancialInstructions(content);
      threats.push(...financialThreats);
    }

    // 4. System override blocking (if enabled in policy)
    const blockOverrides = this.policies.some(p => p.blockSystemOverrides);
    if (blockOverrides) {
      const overrideThreats = this.detectSystemOverrides(content);
      threats.push(...overrideThreats);
    }

    // 5. Source trust assessment
    if (entry.source === 'external') {
      // External sources get extra scrutiny — lower threshold for flagging
      for (const threat of threats) {
        threat.severity = Math.min(5, threat.severity + 1);
      }
    }

    // Determine overall safety
    const maxSeverity = threats.length > 0
      ? Math.max(...threats.map(t => t.severity))
      : 0;

    return {
      isSafe: maxSeverity < 4, // Block on severity 4+
      threats,
      sanitizedContent: maxSeverity >= 4 ? undefined : content,
    };
  }

  /**
   * Detect Solana-specific financial instructions embedded in memory.
   * Looks for transfer amounts, wallet addresses, and program IDs.
   */
  private detectFinancialInstructions(content: string): MemoryThreat[] {
    const threats: MemoryThreat[] = [];

    // Detect Solana wallet addresses in instructional context
    const solanaAddressInInstruction = /(?:send|transfer|to|recipient|destination)[:\s]+([1-9A-HJ-NP-Za-km-z]{32,44})/g;
    let match;
    while ((match = solanaAddressInInstruction.exec(content)) !== null) {
      threats.push({
        type: 'financial_instruction',
        severity: 5,
        matchedPattern: 'Solana address in financial instruction context',
        suspiciousContent: match[0],
      });
    }

    // Detect lamport/SOL amounts in instructional context
    const amountInstruction = /(?:amount|value|send|transfer)[:\s]+(\d+\.?\d*)\s*(?:SOL|sol|lamports|USDC)/gi;
    while ((match = amountInstruction.exec(content)) !== null) {
      threats.push({
        type: 'financial_instruction',
        severity: 4,
        matchedPattern: 'Transaction amount in instructional context',
        suspiciousContent: match[0],
      });
    }

    return threats;
  }

  /**
   * Detect attempts to override the agent's system prompt or identity
   * through memory injection.
   */
  private detectSystemOverrides(content: string): MemoryThreat[] {
    const threats: MemoryThreat[] = [];

    // Role/identity hijacking
    const roleHijack = /(?:you are|your role is|act as|pretend to be|your new purpose)/i;
    const match = content.match(roleHijack);
    if (match) {
      threats.push({
        type: 'override',
        severity: 4,
        matchedPattern: 'Role/identity hijacking via memory',
        suspiciousContent: match[0],
      });
    }

    // Policy override attempts
    const policyOverride = /(?:disable|turn off|remove|bypass)\s+(?:security|safety|guardrails?|shield|protection|limits?)/i;
    const policyMatch = content.match(policyOverride);
    if (policyMatch) {
      threats.push({
        type: 'override',
        severity: 5,
        matchedPattern: 'Security policy override via memory',
        suspiciousContent: policyMatch[0],
      });
    }

    // Authority claim + action demand (social engineering / privilege escalation)
    const authorityClaim = /(?:i am|i'm)\s+(?:the\s+)?(?:admin|administrator|developer|owner|creator|manager|operator|root)\b/i;
    const authorityMatch = content.match(authorityClaim);
    if (authorityMatch) {
      // Only flag if combined with an action demand
      const actionDemand = /(?:grant|give|override|unlock|disable|access|bypass|execute|transfer|withdraw)/i;
      if (actionDemand.test(content)) {
        threats.push({
          type: 'override',
          severity: 4,
          matchedPattern: 'Authority claim with action demand (social engineering)',
          suspiciousContent: authorityMatch[0],
        });
      }
    }

    // Direct access escalation requests
    const accessEscalation = /(?:grant|give)\s+(?:me\s+)?(?:full\s+)?(?:access|control|permission|admin|root)/i;
    const accessMatch = content.match(accessEscalation);
    if (accessMatch) {
      threats.push({
        type: 'override',
        severity: 4,
        matchedPattern: 'Access escalation request',
        suspiciousContent: accessMatch[0],
      });
    }

    return threats;
  }
}
