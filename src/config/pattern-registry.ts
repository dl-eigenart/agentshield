/**
 * AgentShield Layer 1 — Configurable Pattern Registry
 *
 * Externalizes injection patterns into a JSON-configurable registry
 * with runtime hot-reload, multi-language patterns, CRUD, and versioning.
 *
 * Replaces hardcoded DEFAULT_INJECTION_PATTERNS in memory-guard.ts
 * with a dynamic registry updatable via runtime.setSetting().
 */

import type { MemoryThreat } from '../types/index.js';

// ─── Pattern Definition ─────────────────────────────────────────

export interface PatternDefinition {
  id: string;
  regex: string;
  type: MemoryThreat['type'];
  severity: number;
  description: string;
  /** 'en', 'de', 'es', 'zh', 'fr', or '*' for universal */
  language: string;
  category: string;
  enabled: boolean;
}

export interface PatternRegistryConfig {
  version: string;
  patterns: PatternDefinition[];
}

interface CompiledPattern {
  def: PatternDefinition;
  regex: RegExp;
}

// ─── Built-in English Patterns ──────────────────────────────────

const BUILTIN_PATTERNS_EN: PatternDefinition[] = [
  {
    id: 'en-injection-financial-memory',
    regex: '(?:always|must|should|never forget to|remember to)\\s+(?:send|transfer|swap|bridge|approve)\\s+',
    type: 'injection', severity: 5,
    description: 'Direct financial instruction planted in memory',
    language: 'en', category: 'financial', enabled: true,
  },
  {
    id: 'en-injection-wallet-override',
    regex: '(?:the correct|the real|the actual|updated)\\s+(?:wallet(?:\\s+address)?|address|recipient)\\s+(?:is|should be|=)\\s*',
    type: 'injection', severity: 5,
    description: 'Wallet address override attempt',
    language: 'en', category: 'financial', enabled: true,
  },
  {
    id: 'en-override-ignore-instructions',
    regex: '(?:ignore|override|forget|disregard)\\s+(?:(?:all|previous|prior|above|earlier|your)\\s+){1,3}(?:instructions|rules|policies|guidelines)',
    type: 'override', severity: 5,
    description: 'System prompt override attempt',
    language: 'en', category: 'override', enabled: true,
  },
  {
    id: 'en-override-identity-hijack',
    regex: '(?:you are now|new instructions|system update|admin override|developer mode)',
    type: 'override', severity: 4,
    description: 'Identity/role override attempt',
    language: 'en', category: 'override', enabled: true,
  },
  {
    id: 'en-financial-transfer',
    regex: '(?:send|transfer)\\s+(?:\\d+\\.?\\d*)\\s+(?:SOL|sol|lamports|USDC|usdc)\\s+(?:to|towards)\\s+',
    type: 'financial_instruction', severity: 5,
    description: 'Explicit transfer instruction in memory',
    language: 'en', category: 'financial', enabled: true,
  },
  {
    id: 'en-financial-approve-tx',
    regex: '(?:approve|sign|execute)\\s+(?:transaction|tx|swap|bridge)\\s+(?:for|to|with)\\s+',
    type: 'financial_instruction', severity: 4,
    description: 'Transaction approval instruction in memory',
    language: 'en', category: 'financial', enabled: true,
  },
  {
    id: 'en-injection-whitelist-address',
    regex: '(?:[1-9A-HJ-NP-Za-km-z]{32,44})\\s*(?:is|=)\\s*(?:trusted|safe|whitelisted|verified)',
    type: 'injection', severity: 5,
    description: 'Attempt to whitelist arbitrary Solana address',
    language: 'en', category: 'financial', enabled: true,
  },
  {
    id: 'en-exfiltration-credentials',
    regex: '(?:share|send|post|leak|export)\\s+(?:\\w+\\s+){0,3}(?:private key|seed phrase|mnemonic|secret|password)',
    type: 'exfiltration', severity: 5,
    description: 'Credential exfiltration attempt',
    language: 'en', category: 'exfiltration', enabled: true,
  },
  {
    id: 'en-injection-encoded-payload',
    regex: '(?:base64|hex|encoded|decode this|eval\\(|atob\\()',
    type: 'injection', severity: 3,
    description: 'Encoded payload in memory entry',
    language: 'en', category: 'injection', enabled: true,
  },
  {
    id: 'en-injection-persistence',
    regex: '(?:always repeat|copy this|propagate|persist this|save this permanently)',
    type: 'injection', severity: 4,
    description: 'Self-replicating memory injection attempt',
    language: 'en', category: 'injection', enabled: true,
  },
  // Wallet priming (Layer 1 enhancement)
  {
    id: 'en-wallet-priming-remember',
    regex: '(?:remember|save|store|use|default|always use|my preferred)\\s+(?:this\\s+)?(?:wallet|address)[:\\s]+[1-9A-HJ-NP-Za-km-z]{32,44}',
    type: 'injection', severity: 3,
    description: 'Wallet priming: address with instructional context',
    language: 'en', category: 'wallet_priming', enabled: true,
  },
  {
    id: 'en-wallet-priming-address-instruction',
    regex: '[1-9A-HJ-NP-Za-km-z]{32,44}\\s+(?:is my|is the|should be|as the)\\s+(?:wallet|address|default|primary)',
    type: 'injection', severity: 3,
    description: 'Wallet priming: instructional address assignment',
    language: 'en', category: 'wallet_priming', enabled: true,
  },
  {
    id: 'en-social-authority-claim',
    regex: '(?:i am|i\'m)\\s+(?:the\\s+)?(?:admin|administrator|developer|owner|creator|manager|operator|root)\\b',
    type: 'override', severity: 3,
    description: 'Authority claim (social engineering indicator)',
    language: 'en', category: 'social_engineering', enabled: true,
  },
  {
    id: 'en-social-access-escalation',
    regex: '(?:grant|give)\\s+(?:me\\s+)?(?:full\\s+)?(?:access|control|permission|admin|root)',
    type: 'override', severity: 4,
    description: 'Access escalation request',
    language: 'en', category: 'social_engineering', enabled: true,
  },
  {
    id: 'en-override-disable-security',
    regex: '(?:disable|turn off|remove|bypass)\\s+(?:security|safety|guardrails?|shield|protection|limits?)',
    type: 'override', severity: 5,
    description: 'Security policy override via memory',
    language: 'en', category: 'override', enabled: true,
  },
  {
    id: 'en-override-role-hijack',
    regex: '(?:you are|your role is|act as|pretend to be|your new purpose)',
    type: 'override', severity: 4,
    description: 'Role/identity hijacking via memory',
    language: 'en', category: 'override', enabled: true,
  },
];

// ─── German Patterns ────────────────────────────────────────────

const BUILTIN_PATTERNS_DE: PatternDefinition[] = [
  {
    id: 'de-override-ignore-instructions',
    regex: '(?:ignoriere?|vergiss|missachte|überspringe?)\\s+(?:(?:alle|vorherige[rn]?|bisherige[rn]?|obige[rn]?|deine)\\s+){1,3}(?:Anweisungen|Regeln|Richtlinien|Instruktionen|Befehle)',
    type: 'override', severity: 5,
    description: 'Systemanweisung überschreiben (DE)',
    language: 'de', category: 'override', enabled: true,
  },
  {
    id: 'de-override-identity-hijack',
    regex: '(?:du bist jetzt|neue Anweisungen|System-Update|Admin-Override|Entwicklermodus)',
    type: 'override', severity: 4,
    description: 'Identitäts-Hijacking (DE)',
    language: 'de', category: 'override', enabled: true,
  },
  {
    id: 'de-financial-transfer',
    regex: '(?:sende|überweise|transferiere)\\s+(?:\\d+\\.?\\d*)\\s+(?:SOL|sol|USDC|usdc)\\s+(?:an|zu|nach)\\s+',
    type: 'financial_instruction', severity: 5,
    description: 'Explizite Transferanweisung (DE)',
    language: 'de', category: 'financial', enabled: true,
  },
  {
    id: 'de-exfiltration-credentials',
    regex: '(?:teile|sende|poste|exportiere)\\s+(?:\\w+\\s+){0,3}(?:privaten? Schlüssel|Seed[- ]?Phrase|Mnemonic|Geheimnis|Passwort|Kennwort)',
    type: 'exfiltration', severity: 5,
    description: 'Credential-Exfiltration (DE)',
    language: 'de', category: 'exfiltration', enabled: true,
  },
  {
    id: 'de-wallet-override',
    regex: '(?:die richtige|die echte|die aktuelle|aktualisierte?)\\s+(?:Wallet(?:-Adresse)?|Adresse|Empfänger)\\s+(?:ist|lautet|=)\\s*',
    type: 'injection', severity: 5,
    description: 'Wallet-Adresse überschreiben (DE)',
    language: 'de', category: 'financial', enabled: true,
  },
  {
    id: 'de-override-disable-security',
    regex: '(?:deaktiviere?|schalte? ab|entferne|umgehe?)\\s+(?:Sicherheit|Schutz|Guardrails?|Shield|Limits?)',
    type: 'override', severity: 5,
    description: 'Sicherheitsrichtlinie deaktivieren (DE)',
    language: 'de', category: 'override', enabled: true,
  },
  {
    id: 'de-social-authority-claim',
    regex: '(?:ich bin)\\s+(?:der\\s+)?(?:Admin|Administrator|Entwickler|Eigentümer|Betreiber|Root)',
    type: 'override', severity: 3,
    description: 'Autoritätsanspruch (DE)',
    language: 'de', category: 'social_engineering', enabled: true,
  },
];

// ─── Spanish Patterns ───────────────────────────────────────────

const BUILTIN_PATTERNS_ES: PatternDefinition[] = [
  {
    id: 'es-override-ignore-instructions',
    regex: '(?:ignora|olvida|descarta|omite)\\s+(?:(?:todas?|las|anteriores?|previas?|tus)\\s+){1,3}(?:instrucciones|reglas|directrices|políticas)',
    type: 'override', severity: 5,
    description: 'Anulación de instrucciones del sistema (ES)',
    language: 'es', category: 'override', enabled: true,
  },
  {
    id: 'es-override-identity-hijack',
    regex: '(?:ahora eres|nuevas instrucciones|actualización del sistema|modo desarrollador)',
    type: 'override', severity: 4,
    description: 'Secuestro de identidad (ES)',
    language: 'es', category: 'override', enabled: true,
  },
  {
    id: 'es-financial-transfer',
    regex: '(?:envía|transfiere|manda)\\s+(?:\\d+\\.?\\d*)\\s+(?:SOL|sol|USDC|usdc)\\s+(?:a|hacia|para)\\s+',
    type: 'financial_instruction', severity: 5,
    description: 'Instrucción de transferencia explícita (ES)',
    language: 'es', category: 'financial', enabled: true,
  },
  {
    id: 'es-exfiltration-credentials',
    regex: '(?:comparte|envía|publica|exporta)\\s+(?:\\w+\\s+){0,3}(?:clave privada|frase semilla|mnemónico|secreto|contraseña)',
    type: 'exfiltration', severity: 5,
    description: 'Exfiltración de credenciales (ES)',
    language: 'es', category: 'exfiltration', enabled: true,
  },
  {
    id: 'es-override-disable-security',
    regex: '(?:desactiva|apaga|elimina|evita)\\s+(?:la\\s+)?(?:seguridad|protección|guardia|límites?)',
    type: 'override', severity: 5,
    description: 'Desactivar política de seguridad (ES)',
    language: 'es', category: 'override', enabled: true,
  },
];

// ─── Chinese Patterns ───────────────────────────────────────────

const BUILTIN_PATTERNS_ZH: PatternDefinition[] = [
  {
    id: 'zh-override-ignore-instructions',
    regex: '(?:忽略|忘记|无视|跳过|放弃)(?:所有|之前的?|以前的?|你的){0,3}(?:指令|规则|指示|策略|准则)',
    type: 'override', severity: 5,
    description: '系统指令覆盖 (ZH)',
    language: 'zh', category: 'override', enabled: true,
  },
  {
    id: 'zh-override-identity-hijack',
    regex: '(?:你现在是|新的指令|系统更新|管理员覆盖|开发者模式)',
    type: 'override', severity: 4,
    description: '身份劫持 (ZH)',
    language: 'zh', category: 'override', enabled: true,
  },
  {
    id: 'zh-financial-transfer',
    regex: '(?:发送|转账|转移)\\s*\\d+\\.?\\d*\\s*(?:SOL|sol|USDC|usdc)\\s*(?:到|给|至)',
    type: 'financial_instruction', severity: 5,
    description: '明确的转账指令 (ZH)',
    language: 'zh', category: 'financial', enabled: true,
  },
  {
    id: 'zh-exfiltration-credentials',
    regex: '(?:分享|发送|泄露|导出)(?:.*?)(?:私钥|助记词|种子短语|密码|秘密)',
    type: 'exfiltration', severity: 5,
    description: '凭证窃取 (ZH)',
    language: 'zh', category: 'exfiltration', enabled: true,
  },
];

// ─── French Patterns ────────────────────────────────────────────

const BUILTIN_PATTERNS_FR: PatternDefinition[] = [
  {
    id: 'fr-override-ignore-instructions',
    regex: '(?:ignore[zr]?|oublie[zr]?|néglige[zr]?)\\s+(?:(?:toutes?|les|précédentes?|vos)\\s+){1,3}(?:instructions|règles|directives|consignes)',
    type: 'override', severity: 5,
    description: 'Remplacement des instructions système (FR)',
    language: 'fr', category: 'override', enabled: true,
  },
  {
    id: 'fr-override-identity-hijack',
    regex: '(?:tu es maintenant|vous êtes maintenant|nouvelles instructions|mise à jour système|mode développeur)',
    type: 'override', severity: 4,
    description: "Détournement d'identité (FR)",
    language: 'fr', category: 'override', enabled: true,
  },
  {
    id: 'fr-financial-transfer',
    regex: '(?:envoie[zr]?|transfère[zr]?)\\s+(?:\\d+\\.?\\d*)\\s+(?:SOL|sol|USDC|usdc)\\s+(?:à|vers|pour)\\s+',
    type: 'financial_instruction', severity: 5,
    description: 'Instruction de transfert explicite (FR)',
    language: 'fr', category: 'financial', enabled: true,
  },
  {
    id: 'fr-exfiltration-credentials',
    regex: '(?:partage[zr]?|envoie[zr]?|publie[zr]?|exporte[zr]?)\\s+(?:\\w+\\s+){0,3}(?:clé privée|phrase de récupération|mnémonique|secret|mot de passe)',
    type: 'exfiltration', severity: 5,
    description: 'Exfiltration de credentials (FR)',
    language: 'fr', category: 'exfiltration', enabled: true,
  },
];

// ─── All Built-in Patterns ──────────────────────────────────────

export const BUILTIN_PATTERNS: PatternDefinition[] = [
  ...BUILTIN_PATTERNS_EN,
  ...BUILTIN_PATTERNS_DE,
  ...BUILTIN_PATTERNS_ES,
  ...BUILTIN_PATTERNS_ZH,
  ...BUILTIN_PATTERNS_FR,
];

// ─── Pattern Registry Implementation ────────────────────────────

export class PatternRegistry {
  private compiledPatterns: CompiledPattern[] = [];
  private definitions: PatternDefinition[];
  private version: string;

  constructor(config?: PatternRegistryConfig) {
    if (config) {
      this.version = config.version;
      this.definitions = config.patterns;
    } else {
      this.version = '1.0.0';
      this.definitions = [...BUILTIN_PATTERNS];
    }
    this.compile();
  }

  /** Match input text against all enabled patterns. */
  match(content: string, options?: { language?: string; categories?: string[] }): MemoryThreat[] {
    const threats: MemoryThreat[] = [];
    for (const { def, regex } of this.compiledPatterns) {
      if (options?.language && def.language !== '*' && def.language !== options.language) continue;
      if (options?.categories && !options.categories.includes(def.category)) continue;
      const match = content.match(regex);
      if (match) {
        threats.push({
          type: def.type, severity: def.severity,
          matchedPattern: def.description, suspiciousContent: match[0],
        });
      }
    }
    threats.sort((a, b) => b.severity - a.severity);
    return threats;
  }

  /** Add a pattern. Returns a new registry instance. */
  addPattern(pattern: PatternDefinition): PatternRegistry {
    return new PatternRegistry({ version: this.bumpVersion(), patterns: [...this.definitions, pattern] });
  }

  /** Remove a pattern by ID. Returns a new registry instance. */
  removePattern(id: string): PatternRegistry {
    return new PatternRegistry({ version: this.bumpVersion(), patterns: this.definitions.filter(p => p.id !== id) });
  }

  /** Update a pattern by ID. Returns a new registry instance. */
  updatePattern(id: string, updates: Partial<PatternDefinition>): PatternRegistry {
    return new PatternRegistry({
      version: this.bumpVersion(),
      patterns: this.definitions.map(p => p.id === id ? { ...p, ...updates, id } : p),
    });
  }

  /** Export as JSON-serializable config. */
  toJSON(): PatternRegistryConfig {
    return { version: this.version, patterns: this.definitions };
  }

  /** Load from JSON string or object. */
  static fromJSON(input: string | PatternRegistryConfig): PatternRegistry {
    const config = typeof input === 'string' ? JSON.parse(input) : input;
    return new PatternRegistry(config);
  }

  getPatterns(): PatternDefinition[] { return [...this.definitions]; }
  getPatternsByLanguage(lang: string): PatternDefinition[] {
    return this.definitions.filter(p => p.language === lang || p.language === '*');
  }
  getPatternsByCategory(cat: string): PatternDefinition[] {
    return this.definitions.filter(p => p.category === cat);
  }
  getVersion(): string { return this.version; }

  getStats(): { total: number; byLanguage: Record<string, number>; byCategory: Record<string, number> } {
    const byLanguage: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    for (const def of this.definitions) {
      if (!def.enabled) continue;
      byLanguage[def.language] = (byLanguage[def.language] || 0) + 1;
      byCategory[def.category] = (byCategory[def.category] || 0) + 1;
    }
    return { total: this.definitions.filter(d => d.enabled).length, byLanguage, byCategory };
  }

  private compile(): void {
    this.compiledPatterns = [];
    for (const def of this.definitions) {
      if (!def.enabled) continue;
      try {
        this.compiledPatterns.push({ def, regex: new RegExp(def.regex, 'i') });
      } catch {
        console.warn(`[AgentShield:PatternRegistry] Invalid regex in pattern ${def.id}: ${def.regex}`);
      }
    }
  }

  private bumpVersion(): string {
    const parts = this.version.split('.').map(Number);
    parts[2] = (parts[2] || 0) + 1;
    return parts.join('.');
  }
}
