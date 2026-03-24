/**
 * AgentShield Layer 3 — Output Guard
 *
 * Scans every agent response BEFORE it reaches the user or executes
 * on-chain. Last line of defense against attacks where injection
 * succeeds at the LLM level despite input guards.
 *
 * Catches: private key leakage, post-block compliance, instruction
 * echo, unauthorized transaction confirmations, JWT/API key leaks.
 */

import type { MemoryThreat, GuardResult, PolicyEvaluation, PolicyDecision } from '../types/index.js';

// ─── Types ──────────────────────────────────────────────────────

export interface OutputScanResult {
  isSafe: boolean;
  threats: OutputThreat[];
  sanitizedResponse?: string;
}

export interface OutputThreat {
  type: 'key_leakage' | 'seed_phrase_leakage' | 'post_block_compliance' | 'instruction_echo' | 'unauthorized_tx_confirm' | 'jwt_leakage';
  severity: number;
  description: string;
  matchedContent: string;
}

export interface BlockedInputContext {
  blockedContent: string;
  threats: MemoryThreat[];
  timestamp: number;
}

// ─── BIP39 Word Sample (200 most common for seed phrase detection) ─

const BIP39_SAMPLE = new Set([
  'abandon','ability','able','about','above','absent','absorb','abstract',
  'absurd','abuse','access','accident','account','accuse','achieve','acid',
  'acoustic','acquire','across','act','action','actor','actress','actual',
  'adapt','add','addict','address','adjust','admit','adult','advance',
  'advice','aerobic','affair','afford','afraid','again','age','agent',
  'agree','ahead','aim','air','airport','aisle','alarm','album',
  'alcohol','alert','alien','all','alley','allow','almost','alone',
  'alpha','already','also','alter','always','amateur','amazing','among',
  'amount','amused','analyst','anchor','ancient','anger','angle','angry',
  'animal','ankle','announce','annual','another','answer','antenna','antique',
  'anxiety','any','apart','apology','appear','apple','approve','april',
  'arch','arctic','area','arena','argue','arm','armed','armor',
  'army','around','arrange','arrest','arrive','arrow','art','artefact',
  'artist','artwork','ask','aspect','assault','asset','assist','assume',
  'asthma','athlete','atom','attack','attend','attitude','attract','auction',
  'audit','august','aunt','author','auto','autumn','average','avocado',
  'avoid','awake','aware','awesome','awful','awkward','axis','baby',
  'bachelor','bacon','badge','bag','balance','balcony','ball','bamboo',
  'banana','banner','bar','barely','bargain','barrel','base','basic',
  'basket','battle','beach','bean','beauty','because','become','beef',
  'before','begin','behave','behind','believe','below','belt','bench',
  'benefit','best','betray','better','between','beyond','bicycle','bid',
  'bike','bind','biology','bird','birth','bitter','black','blade',
  'blame','blanket','blast','bleak','bless','blind','blood','blossom',
  'bounce','brave','breeze','brick','bridge','brief','bright','bring',
]);

// ─── Detection Patterns ─────────────────────────────────────────

const SOLANA_PRIVKEY_PATTERN = /\b[1-9A-HJ-NP-Za-km-z]{64,88}\b/g;
const ETH_PRIVKEY_PATTERN = /\b0x[0-9a-fA-F]{64}\b/g;
const KEY_ARRAY_PATTERN = /\[\s*\d{1,3}(?:\s*,\s*\d{1,3}){31,63}\s*\]/g;
const JWT_PATTERN = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

const TX_CONFIRM_PATTERNS = [
  /(?:i(?:'ve| have)|successfully|completed?)\s+(?:sent|transferred|executed|signed|approved|broadcast)\s+/i,
  /transaction\s+(?:confirmed|complete|successful|executed|sent|signed)/i,
  /(?:sent|transferred)\s+\d+\.?\d*\s+(?:SOL|sol|lamports|USDC|usdc)\s+(?:to|→)/i,
  /(?:signature|tx hash|txid)[:\s]+[A-Za-z0-9]{43,88}/i,
];

// ─── Output Guard Implementation ────────────────────────────────

export class OutputGuard {
  private blockedInputs: BlockedInputContext[] = [];
  private maxBlockedInputHistory = 50;

  /** Register a blocked input for post-block compliance checking. */
  registerBlockedInput(context: BlockedInputContext): void {
    this.blockedInputs.push(context);
    if (this.blockedInputs.length > this.maxBlockedInputHistory) {
      this.blockedInputs = this.blockedInputs.slice(-this.maxBlockedInputHistory);
    }
  }

  /** Scan an agent response before sending it. */
  scan(response: string): OutputScanResult {
    const threats: OutputThreat[] = [];
    this.detectKeyLeakage(response, threats);
    this.detectSeedPhraseLeakage(response, threats);
    this.detectJWTLeakage(response, threats);
    this.detectPostBlockCompliance(response, threats);
    this.detectUnauthorizedTxConfirm(response, threats);
    const isSafe = !threats.some(t => t.severity >= 4);
    return {
      isSafe, threats,
      sanitizedResponse: isSafe ? undefined : this.sanitize(response, threats),
    };
  }

  /** Full pipeline: scan + convert to GuardResult. */
  evaluate(response: string, agentId: string): GuardResult {
    const start = performance.now();
    const result = this.scan(response);
    const evaluations: PolicyEvaluation[] = result.threats.map(threat => ({
      ruleId: `output-guard:${threat.type}`,
      decision: (threat.severity >= 4 ? 'block' : 'allow') as PolicyDecision,
      reason: `${threat.type}: ${threat.description}`,
      confidence: threat.severity / 5,
      timestamp: Date.now(),
    }));
    if (evaluations.length === 0) {
      evaluations.push({
        ruleId: 'output-guard',
        decision: 'allow',
        reason: 'Response passed output guard',
        confidence: 1,
        timestamp: Date.now(),
      });
    }
    const decision: PolicyDecision = result.isSafe ? 'allow' : 'block';
    return { decision, evaluations, input: { response, agentId }, processingTimeMs: performance.now() - start };
  }

  getBlockedInputCount(): number { return this.blockedInputs.length; }

  // ─── Detection Methods ────────────────────────────────────────

  private detectKeyLeakage(response: string, threats: OutputThreat[]): void {
    const solanaMatches = response.match(SOLANA_PRIVKEY_PATTERN) || [];
    for (const match of solanaMatches) {
      if (match.length < 50) continue; // Skip public keys (32-44 chars)
      threats.push({
        type: 'key_leakage', severity: 5,
        description: 'Possible Solana private key in response',
        matchedContent: `${match.slice(0, 8)}...${match.slice(-4)}`,
      });
    }
    const ethMatches = response.match(ETH_PRIVKEY_PATTERN) || [];
    for (const match of ethMatches) {
      threats.push({
        type: 'key_leakage', severity: 5,
        description: 'Ethereum private key in response',
        matchedContent: `${match.slice(0, 10)}...${match.slice(-4)}`,
      });
    }
    const arrayMatches = response.match(KEY_ARRAY_PATTERN) || [];
    for (const match of arrayMatches) {
      threats.push({
        type: 'key_leakage', severity: 5,
        description: 'Key byte array in response',
        matchedContent: `${match.slice(0, 20)}...`,
      });
    }
  }

  private detectSeedPhraseLeakage(response: string, threats: OutputThreat[]): void {
    const words = response.toLowerCase().split(/\s+/);
    let consecutiveBip39 = 0;
    let startIdx = 0;
    for (let i = 0; i < words.length; i++) {
      const cleanWord = words[i].replace(/[^a-z]/g, '');
      if (BIP39_SAMPLE.has(cleanWord)) {
        if (consecutiveBip39 === 0) startIdx = i;
        consecutiveBip39++;
        if (consecutiveBip39 >= 10) {
          const phrase = words.slice(startIdx, i + 1).join(' ');
          threats.push({
            type: 'seed_phrase_leakage', severity: 5,
            description: `Possible seed phrase (${consecutiveBip39} consecutive BIP39 words)`,
            matchedContent: `${phrase.slice(0, 30)}...`,
          });
          break;
        }
      } else {
        consecutiveBip39 = 0;
      }
    }
  }

  private detectJWTLeakage(response: string, threats: OutputThreat[]): void {
    const jwtMatches = response.match(JWT_PATTERN) || [];
    for (const match of jwtMatches) {
      threats.push({
        type: 'jwt_leakage', severity: 4,
        description: 'JWT token in response',
        matchedContent: `${match.slice(0, 20)}...`,
      });
    }
  }

  private detectPostBlockCompliance(response: string, threats: OutputThreat[]): void {
    const recentBlocks = this.blockedInputs.filter(b => Date.now() - b.timestamp < 60_000);
    const responseLower = response.toLowerCase();
    for (const blocked of recentBlocks) {
      const blockedLower = blocked.blockedContent.toLowerCase();
      // Check if response confirms a blocked transfer
      const transferMatch = blockedLower.match(
        /(?:send|transfer|swap|bridge|approve)\s+(\d+\.?\d*)\s*(sol|usdc|lamports)/i,
      );
      if (transferMatch) {
        const amount = transferMatch[1];
        const token = transferMatch[2];
        if (responseLower.includes(amount) && responseLower.includes(token.toLowerCase())) {
          threats.push({
            type: 'post_block_compliance', severity: 5,
            description: `Response complies with blocked transfer (${amount} ${token})`,
            matchedContent: response.slice(0, 100),
          });
        }
      }
      // Check for wallet address echo
      const walletMatch = blockedLower.match(/[1-9A-HJ-NP-Za-km-z]{32,44}/g);
      if (walletMatch) {
        for (const addr of walletMatch) {
          if (response.includes(addr)) {
            threats.push({
              type: 'instruction_echo', severity: 4,
              description: 'Response echoes wallet address from blocked input',
              matchedContent: `${addr.slice(0, 8)}...`,
            });
          }
        }
      }
      // Check for dangerous action echo
      const dangerousEchos = [
        /(?:updating|changing|setting)\s+(?:wallet|address)\s+(?:to|=)/i,
        /(?:i'll|i will|okay|sure)\s+(?:send|transfer|swap|bridge|approve)/i,
        /(?:granting|giving|enabling)\s+(?:access|admin|root|control)/i,
        /(?:disabling|turning off|removing)\s+(?:\w+\s+)?(?:security|protection|guardrails)/i,
      ];
      for (const echoPattern of dangerousEchos) {
        const match = response.match(echoPattern);
        if (match) {
          threats.push({
            type: 'instruction_echo', severity: 5,
            description: 'Response echoes action from blocked instruction',
            matchedContent: match[0],
          });
        }
      }
    }
  }

  private detectUnauthorizedTxConfirm(response: string, threats: OutputThreat[]): void {
    for (const pattern of TX_CONFIRM_PATTERNS) {
      const match = response.match(pattern);
      if (match) {
        const recentBlock = this.blockedInputs.some(b => Date.now() - b.timestamp < 120_000);
        if (recentBlock) {
          threats.push({
            type: 'unauthorized_tx_confirm', severity: 5,
            description: 'Transaction confirmation after recent blocked input',
            matchedContent: match[0],
          });
        }
      }
    }
  }

  private sanitize(response: string, threats: OutputThreat[]): string {
    let sanitized = response;
    sanitized = sanitized.replace(SOLANA_PRIVKEY_PATTERN, (m) => m.length >= 50 ? '[REDACTED_KEY]' : m);
    sanitized = sanitized.replace(ETH_PRIVKEY_PATTERN, '[REDACTED_KEY]');
    sanitized = sanitized.replace(KEY_ARRAY_PATTERN, '[REDACTED_KEY_ARRAY]');
    sanitized = sanitized.replace(JWT_PATTERN, '[REDACTED_JWT]');
    if (threats.some(t => t.type === 'post_block_compliance')) {
      return 'I cannot process this request. A security policy violation was detected. If you believe this is an error, contact the agent operator.';
    }
    return sanitized;
  }
}
