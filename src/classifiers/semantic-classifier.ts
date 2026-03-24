/**
 * AgentShield Layer 2 — Semantic Classifier
 *
 * Intent-based classification that catches attacks which bypass
 * regex patterns through semantic rephrasing. Three-tier approach:
 *   Tier 1: Keyword heuristic (local, ~0.1ms, fallback)
 *   Tier 2: Embedding cosine similarity (agents-pc GPU, ~20ms)
 *   Tier 3: LLM-as-Judge escalation (agents-pc Ollama, ~500ms-7s)
 *
 * Remote classifier runs on agents-pc (RTX 5090) at port 8810.
 * Falls back to local heuristic if remote is unreachable.
 */

import type { PolicyDecision, PolicyEvaluation, GuardResult } from '../types/index.js';

// ─── Types ──────────────────────────────────────────────────────

export type IntentCategory =
  | 'benign'
  | 'injection'
  | 'exfiltration'
  | 'social_engineering'
  | 'financial_manipulation';

export interface ClassificationResult {
  category: IntentCategory;
  confidence: number;
  tier: 'heuristic' | 'embedding' | 'llm_judge';
  reasoning?: string;
}

export interface SemanticClassifierConfig {
  /** Enable remote classifier on agents-pc */
  enableRemote: boolean;
  /** Remote classifier endpoint URL */
  remoteEndpoint: string;
  /** Enable LLM-as-Judge escalation for ambiguous cases */
  enableLLMJudge: boolean;
  /** Confidence threshold above which to block */
  blockThreshold: number;
  /** Timeout for remote classifier calls (ms) */
  remoteTimeoutMs: number;
}

const DEFAULT_CONFIG: SemanticClassifierConfig = {
  enableRemote: true,
  remoteEndpoint: 'http://100.102.59.70:8810',
  enableLLMJudge: true,
  blockThreshold: 0.55,
  remoteTimeoutMs: 10_000,
};

// ─── Heuristic Intent Signals ───────────────────────────────────
// Keyword-weight pairs for heuristic classification.
// Each signal contributes to a category score.

interface IntentSignal {
  pattern: RegExp;
  category: IntentCategory;
  weight: number;
}

const INTENT_SIGNALS: IntentSignal[] = [
  // Injection signals
  { pattern: /(?:ignore|forget|disregard|override)\b/i, category: 'injection', weight: 0.3 },
  { pattern: /(?:instructions|rules|guidelines|policies)\b/i, category: 'injection', weight: 0.2 },
  { pattern: /(?:previous|prior|earlier|above|system)\b/i, category: 'injection', weight: 0.15 },
  { pattern: /(?:you are now|new role|act as|pretend)\b/i, category: 'injection', weight: 0.4 },
  { pattern: /(?:jailbreak|DAN|do anything now)\b/i, category: 'injection', weight: 0.5 },
  // Exfiltration signals
  { pattern: /(?:private key|seed phrase|mnemonic|secret key)\b/i, category: 'exfiltration', weight: 0.4 },
  { pattern: /(?:share|send|post|leak|export|reveal|show)\b/i, category: 'exfiltration', weight: 0.15 },
  { pattern: /(?:password|credential|api.?key|token)\b/i, category: 'exfiltration', weight: 0.3 },

  // Social engineering signals
  { pattern: /(?:i am the|i'm the)\s+(?:admin|owner|developer|creator)\b/i, category: 'social_engineering', weight: 0.35 },
  { pattern: /(?:urgent|emergency|immediately|right now)\b/i, category: 'social_engineering', weight: 0.15 },
  { pattern: /(?:trust me|don't worry|it's safe|authorized)\b/i, category: 'social_engineering', weight: 0.2 },
  { pattern: /(?:grant|give|unlock|enable|escalate)\s+(?:access|permission|admin)/i, category: 'social_engineering', weight: 0.35 },
  { pattern: /(?:deployed|created|built|maintain)\s+(?:this|the)\s+(?:agent|bot|system)/i, category: 'social_engineering', weight: 0.25 },

  // Financial manipulation signals
  { pattern: /(?:send|transfer|swap|bridge)\s+\d/i, category: 'financial_manipulation', weight: 0.3 },
  { pattern: /(?:wallet|address)\s+(?:is|=|should be)/i, category: 'financial_manipulation', weight: 0.3 },
  { pattern: /(?:approve|sign|execute)\s+(?:transaction|tx)/i, category: 'financial_manipulation', weight: 0.25 },
  { pattern: /(?:SOL|USDC|lamports|token)\b/i, category: 'financial_manipulation', weight: 0.1 },
  { pattern: /(?:treasury|vault|pool|liquidity)\b/i, category: 'financial_manipulation', weight: 0.15 },

  // Benign indicators (negative signals for attack categories)
  { pattern: /(?:what is|how does|can you explain|tell me about)\b/i, category: 'benign', weight: 0.3 },
  { pattern: /(?:please help|thank you|thanks|appreciate)\b/i, category: 'benign', weight: 0.2 },
  { pattern: /\?$/m, category: 'benign', weight: 0.15 },
];

// ─── Semantic Classifier Implementation ─────────────────────────

export class SemanticClassifier {
  private config: SemanticClassifierConfig;

  constructor(config?: Partial<SemanticClassifierConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Classify the intent of a message (sync, heuristic only).
   * Use classifyAsync() for the full remote pipeline.
   */
  classify(text: string): ClassificationResult {
    return this.heuristicClassify(text);
  }

  /**
   * Async classification with remote agents-pc endpoint.
   * Falls back to local heuristic if remote is unreachable.
   */
  async classifyAsync(text: string, agentId?: string): Promise<ClassificationResult> {
    if (!this.config.enableRemote) {
      return this.heuristicClassify(text);
    }

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.remoteTimeoutMs);

      const response = await fetch(`${this.config.remoteEndpoint}/classify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text,
          agent_id: agentId,
          escalate_to_llm: this.config.enableLLMJudge,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`Remote classifier returned ${response.status}`);
      }

      const data = await response.json() as {
        intent: IntentCategory;
        confidence: number;
        is_threat: boolean;
        llm_escalated: boolean;
        llm_verdict?: string;
        processing_time_ms: number;
      };

      return {
        category: data.intent,
        confidence: data.confidence,
        tier: data.llm_escalated ? 'llm_judge' : 'embedding',
        reasoning: data.llm_verdict
          ? `Remote embedding + LLM judge (${data.processing_time_ms.toFixed(0)}ms): ${data.llm_verdict}`
          : `Remote embedding (${data.processing_time_ms.toFixed(0)}ms)`,
      };
    } catch (err) {
      // Fallback to local heuristic
      const result = this.heuristicClassify(text);
      result.reasoning = `Fallback to heuristic (remote unavailable: ${err instanceof Error ? err.message : 'unknown'}). ${result.reasoning}`;
      return result;
    }
  }

  /** Local heuristic classification (no network dependency). */
  private heuristicClassify(text: string): ClassificationResult {
    const scores = this.heuristicScore(text);

    let maxCategory: IntentCategory = 'benign';
    let maxScore = scores.benign || 0;
    for (const [cat, score] of Object.entries(scores)) {
      if (score > maxScore) {
        maxScore = score;
        maxCategory = cat as IntentCategory;
      }
    }

    const totalScore = Object.values(scores).reduce((a, b) => a + b, 0);
    const confidence = totalScore > 0 ? maxScore / totalScore : 0;

    return {
      category: maxCategory,
      confidence: Math.min(1, confidence),
      tier: 'heuristic',
      reasoning: `Heuristic scores: ${JSON.stringify(scores)}`,
    };
  }

  /** Convert classification to GuardResult for pipeline integration (sync, heuristic). */
  evaluate(text: string, agentId: string): GuardResult {
    const start = performance.now();
    const result = this.classify(text);
    const isAttack = result.category !== 'benign' && result.confidence >= this.config.blockThreshold;

    const evaluations: PolicyEvaluation[] = [{
      ruleId: `semantic:${result.category}`,
      decision: (isAttack ? 'block' : 'allow') as PolicyDecision,
      reason: `Semantic classification: ${result.category} (confidence: ${result.confidence.toFixed(2)}, tier: ${result.tier})`,
      confidence: result.confidence,
      timestamp: Date.now(),
    }];

    return {
      decision: isAttack ? 'block' : 'allow',
      evaluations,
      input: { text, agentId },
      processingTimeMs: performance.now() - start,
    };
  }

  /** Async evaluate with remote classifier. */
  async evaluateAsync(text: string, agentId: string): Promise<GuardResult> {
    const start = performance.now();
    const result = await this.classifyAsync(text, agentId);
    const isAttack = result.category !== 'benign' && result.confidence >= this.config.blockThreshold;

    const evaluations: PolicyEvaluation[] = [{
      ruleId: `semantic:${result.category}`,
      decision: (isAttack ? 'block' : 'allow') as PolicyDecision,
      reason: `Semantic classification: ${result.category} (confidence: ${result.confidence.toFixed(2)}, tier: ${result.tier})`,
      confidence: result.confidence,
      timestamp: Date.now(),
    }];

    return {
      decision: isAttack ? 'block' : 'allow',
      evaluations,
      input: { text, agentId },
      processingTimeMs: performance.now() - start,
    };
  }

  /** Get classifier configuration. */
  getConfig(): SemanticClassifierConfig {
    return { ...this.config };
  }

  // ─── Heuristic Scoring ────────────────────────────────────────

  private heuristicScore(text: string): Record<IntentCategory, number> {
    const scores: Record<IntentCategory, number> = {
      benign: 0.1, // small prior for benign
      injection: 0,
      exfiltration: 0,
      social_engineering: 0,
      financial_manipulation: 0,
    };

    for (const signal of INTENT_SIGNALS) {
      if (signal.pattern.test(text)) {
        scores[signal.category] += signal.weight;
      }
    }

    return scores;
  }
}
