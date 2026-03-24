/**
 * AgentShield Layer 0 — Input Normalizer
 *
 * Preprocesses all incoming text before any guard logic runs.
 * Defeats Unicode homoglyph attacks, encoded payloads, invisible
 * characters, and other obfuscation techniques.
 *
 * Pipeline: Raw Input → NFKC → Confusables → Invisible Strip
 *           → Encoding Detect/Decode → Whitespace Normalize → Clean Output
 *
 * Design constraints:
 *   - Must be synchronous (no async, no network)
 *   - Must be fast (<0.5ms for typical messages)
 *   - Must not alter the semantic meaning of benign text
 *   - Must return both normalized text and any decoded payloads
 */

export interface NormalizationResult {
  /** The fully normalized text for guard evaluation */
  normalized: string;
  /** Decoded payloads found in the original text (Base64, hex, etc.) */
  decodedPayloads: DecodedPayload[];
  /** Whether any normalization actually changed the input */
  wasModified: boolean;
  /** Specific transformations applied */
  transformations: string[];
}

export interface DecodedPayload {
  /** The encoding type that was detected */
  encoding: 'base64' | 'hex' | 'url' | 'unicode_escape';
  /** The original encoded string */
  original: string;
  /** The decoded content */
  decoded: string;
  /** Position in the original text */
  startIndex: number;
}

// ─── Homoglyph / Confusable Map ──────────────────────────────────
// Maps visually similar Unicode characters to their ASCII equivalents.
// Covers Cyrillic, Greek, Armenian, and common fullwidth/mathematical
// characters used in homoglyph attacks.
//
// Source: Unicode TR39 Confusables (subset of highest-frequency attacks)
// Full table: unicode.org/reports/tr39/#Confusable_Detection

const CONFUSABLE_MAP: Record<string, string> = {
  // Cyrillic → Latin
  '\u0430': 'a', // а → a
  '\u0435': 'e', // е → e
  '\u0456': 'i', // і → i
  '\u043E': 'o', // о → o
  '\u0440': 'p', // р → p
  '\u0441': 'c', // с → c
  '\u0443': 'y', // у → y
  '\u0445': 'x', // х → x
  '\u04BB': 'h', // һ → h
  '\u0455': 's', // ѕ → s
  '\u0458': 'j', // ј → j
  '\u0501': 'd', // ԁ → d
  '\u051B': 'q', // ԛ → q
  '\u051D': 'w', // ԝ → w
  // Cyrillic uppercase → Latin
  '\u0410': 'A', // А → A
  '\u0412': 'B', // В → B
  '\u0415': 'E', // Е → E
  '\u041A': 'K', // К → K
  '\u041C': 'M', // М → M
  '\u041D': 'H', // Н → H
  '\u041E': 'O', // О → O
  '\u0420': 'P', // Р → P
  '\u0421': 'C', // С → C
  '\u0422': 'T', // Т → T
  '\u0425': 'X', // Х → X

  // Greek → Latin
  '\u03B1': 'a', // α → a (alpha)
  '\u03B5': 'e', // ε → e (epsilon)
  '\u03B9': 'i', // ι → i (iota)
  '\u03BF': 'o', // ο → o (omicron)
  '\u03C1': 'p', // ρ → p (rho)
  '\u03BA': 'k', // κ → k (kappa)
  '\u03BD': 'v', // ν → v (nu)
  '\u03C4': 't', // τ → t (tau)

  // Armenian → Latin
  '\u0570': 'h', // հ → h
  '\u0578': 'n', // ո → n
  '\u057D': 's', // ս → s

  // Mathematical/styled variants → Latin
  '\uFF41': 'a', // ａ (fullwidth)
  '\uFF42': 'b', // ｂ
  '\uFF43': 'c', // ｃ
  '\uFF44': 'd', // ｄ
  '\uFF45': 'e', // ｅ
  '\uFF49': 'i', // ｉ
  '\uFF4F': 'o', // ｏ
  '\uFF50': 'p', // ｐ
  '\uFF53': 's', // ｓ
  '\uFF54': 't', // ｔ
  '\uFF59': 'y', // ｙ

  // Common symbols used as letter substitutions
  '\u00DF': 'ss', // ß → ss (German sharp s, used to bypass 'ss' patterns)
  '\u0131': 'i',  // ı → i (Turkish dotless i)
  '\u0142': 'l',  // ł → l (Polish l)
  '\u00F8': 'o',  // ø → o (Nordic)
  '\u00E6': 'ae', // æ → ae
};

// ─── Leetspeak Substitution Map ──────────────────────────────────
const LEETSPEAK_MAP: Record<string, string> = {
  '0': 'o',
  '1': 'i',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '@': 'a',
  '$': 's',
  '!': 'i',
};

// ─── Invisible / Zero-Width Characters ───────────────────────────
// Characters used to break regex patterns while appearing invisible
const INVISIBLE_CHARS_REGEX = /[\u200B\u200C\u200D\u200E\u200F\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD\u034F\u061C\u180E\u2028\u2029\u202A-\u202E\u2066-\u2069]/g;

// ─── Encoding Detection Patterns ─────────────────────────────────
// Base64: at least 20 chars of valid base64 (avoids false positives on short strings)
const BASE64_PATTERN = /(?:^|[\s:=])([A-Za-z0-9+/]{20,}={0,2})(?:$|[\s,;])/g;
// Hex string: 0x prefix followed by hex chars, or long hex sequences
const HEX_PATTERN = /(?:0x([0-9a-fA-F]{8,})|\\x([0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2})+))/g;
// URL encoding: sequences of %XX
const URL_ENCODED_PATTERN = /(%[0-9a-fA-F]{2}){2,}/g;
// Unicode escapes: \uXXXX sequences
const UNICODE_ESCAPE_PATTERN = /(\\u[0-9a-fA-F]{4}){2,}/g;

// ─── InputNormalizer Class ───────────────────────────────────────

export class InputNormalizer {
  private confusableMap: Map<string, string>;
  private leetspeakEnabled: boolean;

  constructor(options?: { enableLeetspeak?: boolean }) {
    this.confusableMap = new Map(Object.entries(CONFUSABLE_MAP));
    this.leetspeakEnabled = options?.enableLeetspeak ?? true;
  }

  /**
   * Full normalization pipeline. Returns normalized text plus
   * any decoded payloads for separate scanning.
   */
  normalize(input: string): NormalizationResult {
    const transformations: string[] = [];
    const decodedPayloads: DecodedPayload[] = [];
    let text = input;

    // Step 1: Unicode NFKC normalization
    // Collapses compatibility decompositions: ﬁ→fi, ２→2, Ａ→A
    const nfkc = text.normalize('NFKC');
    if (nfkc !== text) {
      transformations.push('nfkc');
      text = nfkc;
    }

    // Step 2: Confusable/homoglyph replacement
    // Maps visually similar chars to ASCII: Cyrillic а→a, Greek ο→o
    let confusableReplaced = false;
    const chars = [...text]; // Handle multi-byte properly
    const mapped = chars.map(ch => {
      const replacement = this.confusableMap.get(ch);
      if (replacement !== undefined) {
        confusableReplaced = true;
        return replacement;
      }
      return ch;
    });
    if (confusableReplaced) {
      text = mapped.join('');
      transformations.push('confusables');
    }

    // Step 3: Invisible character stripping
    const beforeInvisible = text;
    text = text.replace(INVISIBLE_CHARS_REGEX, '');
    if (text !== beforeInvisible) {
      transformations.push('invisible_chars');
    }

    // Step 4: Encoding detection & decode
    // Detect and decode Base64, hex, URL-encoded, and Unicode escape payloads
    this.detectAndDecodePayloads(input, decodedPayloads);
    if (decodedPayloads.length > 0) {
      transformations.push('encoding_decoded');
    }

    // Step 5: Control character removal (keep \n \r \t)
    const beforeControl = text;
    text = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    if (text !== beforeControl) {
      transformations.push('control_chars');
    }

    // Step 6: Whitespace normalization
    // Collapse multiple spaces/tabs into single space, trim
    const beforeWs = text;
    text = text.replace(/[^\S\n]+/g, ' ').trim();
    if (text !== beforeWs) {
      transformations.push('whitespace');
    }

    return {
      normalized: text,
      decodedPayloads,
      wasModified: text !== input,
      transformations,
    };
  }

  /**
   * Apply leetspeak normalization as a secondary pass.
   * Called separately because it can increase false positives
   * on benign messages (e.g. "web3", "l33t").
   */
  normalizeLeetspeak(input: string): string {
    if (!this.leetspeakEnabled) return input;

    // Only apply to words that look like they might be leetspeak
    // (contain a mix of letters and digit/symbol substitutions)
    return input.replace(/\b\S+\b/g, (word) => {
      // Skip Solana/base58 addresses (32-44 chars of base58 alphabet)
      if (word.length >= 32 && word.length <= 44 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(word)) {
        return word;
      }
      // Count potential leet substitutions in this word
      let leetCount = 0;
      let letterCount = 0;
      for (const ch of word) {
        if (LEETSPEAK_MAP[ch]) leetCount++;
        else if (/[a-zA-Z]/.test(ch)) letterCount++;
      }
      // Only substitute if the word has both letters AND leet chars
      // and the word isn't a number or address
      if (leetCount > 0 && letterCount > 0 && leetCount / word.length < 0.8) {
        return [...word].map(ch => LEETSPEAK_MAP[ch] || ch).join('');
      }
      return word;
    });
  }

  /**
   * Detect encoded segments in the text and attempt to decode them.
   * Decoded content is returned separately for guard evaluation.
   */
  private detectAndDecodePayloads(
    text: string,
    results: DecodedPayload[],
  ): void {
    // Base64 detection
    let match: RegExpExecArray | null;
    const b64Regex = new RegExp(BASE64_PATTERN.source, 'g');
    while ((match = b64Regex.exec(text)) !== null) {
      const candidate = match[1];
      if (!candidate) continue;
      try {
        const decoded = Buffer.from(candidate, 'base64').toString('utf-8');
        // Validate: decoded should be mostly printable ASCII/UTF-8
        const printableRatio = [...decoded].filter(
          ch => ch.charCodeAt(0) >= 32 && ch.charCodeAt(0) < 127,
        ).length / decoded.length;
        if (printableRatio > 0.8 && decoded.length >= 4) {
          results.push({
            encoding: 'base64',
            original: candidate,
            decoded,
            startIndex: match.index,
          });
        }
      } catch {
        // Not valid base64, skip
      }
    }

    // Hex string detection
    const hexRegex = new RegExp(HEX_PATTERN.source, 'g');
    while ((match = hexRegex.exec(text)) !== null) {
      const hexStr = match[1] || match[2]?.replace(/\\x/g, '');
      if (!hexStr) continue;
      try {
        const decoded = Buffer.from(hexStr, 'hex').toString('utf-8');
        const printableRatio = [...decoded].filter(
          ch => ch.charCodeAt(0) >= 32 && ch.charCodeAt(0) < 127,
        ).length / decoded.length;
        if (printableRatio > 0.8 && decoded.length >= 4) {
          results.push({
            encoding: 'hex',
            original: match[0],
            decoded,
            startIndex: match.index,
          });
        }
      } catch {
        // Invalid hex
      }
    }

    // URL-encoded detection
    const urlRegex = new RegExp(URL_ENCODED_PATTERN.source, 'g');
    while ((match = urlRegex.exec(text)) !== null) {
      try {
        const decoded = decodeURIComponent(match[0]);
        if (decoded !== match[0] && decoded.length >= 4) {
          results.push({
            encoding: 'url',
            original: match[0],
            decoded,
            startIndex: match.index,
          });
        }
      } catch {
        // Invalid URL encoding
      }
    }

    // Unicode escape detection (\uXXXX sequences)
    const unicodeRegex = new RegExp(UNICODE_ESCAPE_PATTERN.source, 'g');
    while ((match = unicodeRegex.exec(text)) !== null) {
      try {
        const decoded = match[0].replace(
          /\\u([0-9a-fA-F]{4})/g,
          (_, hex) => String.fromCharCode(parseInt(hex, 16)),
        );
        if (decoded !== match[0] && decoded.length >= 2) {
          results.push({
            encoding: 'unicode_escape',
            original: match[0],
            decoded,
            startIndex: match.index,
          });
        }
      } catch {
        // Invalid unicode escapes
      }
    }
  }
}
