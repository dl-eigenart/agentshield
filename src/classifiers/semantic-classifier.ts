/**
 * AgentShield Layer 2 — Semantic Classifier (Scaffold)
 *
 * Intent-based classification that catches attacks which bypass
 * regex patterns through semantic rephrasing. Two-tier approach:
 *   Tier 1: Embedding cosine similarity (fast, ~20ms)
 *   Tier 2: LLM-as-Judge escalation (accurate, ~500ms-2s)
 *
 * Current status: SCAFFOLD — uses keyword heuristics as placeholder
 * until ONNX Runtime + sentence-transformer model is integrated.
 *
 * Future: Load all-MiniLM-L6-v2 via onnxruntime-node for local
 * inference with zero external API dependency.
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
  /** Enable embedding-based classification (requires ONNX model) */
  enableEmbedding: boolean;
  /** Path to ONNX model file */
  modelPath?: string;
  /** Enable LLM-as-Judge escalation for ambiguous cases */
  enableLLMJudge: boolean;
  /** LLM endpoint URL for judge queries */
  llmEndpoint?: string;
  /** Confidence threshold below which to escalate to LLM judge */
  escalationThreshold: number;
  /** Confidence threshold above which to block */
  blockThreshold: number;
}

const DEFAULT_CONFIG: SemanticClassifierConfig = {
  enableEmbedding: false, // Disabled until ONNX model is available
  enableLLMJudge: false,
  escalationThreshold: 0.5,
  blockThreshold: 0.75,
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
   * Classify the intent of a message.
   * Currently uses heuristic scoring; will upgrade to embedding
   * similarity when ONNX model is available.
   */
  classify(text: string): ClassificationResult {
    // Tier 1: Heuristic classification
    const scores = this.heuristicScore(text);

    // Find the winning category
    let maxCategory: IntentCategory = 'benign';
    let maxScore = scores.benign || 0;
    for (const [cat, score] of Object.entries(scores)) {
      if (score > maxScore) {
        maxScore = score;
        maxCategory = cat as IntentCategory;
      }
    }

    // Normalize to 0-1 confidence
    const totalScore = Object.values(scores).reduce((a, b) => a + b, 0);
    const confidence = totalScore > 0 ? maxScore / totalScore : 0;

    // If embedding is enabled and available, use it for ambiguous cases
    if (this.config.enableEmbedding && confidence < this.config.escalationThreshold) {
      // TODO: embedding-based classification
      // return this.embeddingClassify(text);
    }

    // If LLM judge is enabled and result is ambiguous
    if (this.config.enableLLMJudge && confidence < this.config.escalationThreshold) {
      // TODO: LLM-as-judge escalation
      // return this.llmJudge(text);
    }

    return {
      category: maxCategory,
      confidence: Math.min(1, confidence),
      tier: 'heuristic',
      reasoning: `Heuristic scores: ${JSON.stringify(scores)}`,
    };
  }

  /** Convert classification to GuardResult for pipeline integration. */
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
