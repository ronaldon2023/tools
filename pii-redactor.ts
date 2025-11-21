/**
 * PII Redaction Utility
 * Author: Ronaldo Nascimento    ronaldon2023@gmail.com    Nov-20-2025    
 * Version:1.0
 * Detects and redacts Personally Identifiable Information (PII) from text.
 * Compliant with GDPR, CCPA, and SOC 2 requirements.
 *
 * ## Mode Selection
 *
 * **strictMode: true** (default, recommended)
 * - Redacts all 15-16 digit patterns (safer for compliance)
 * - Use for: GDPR/SOC 2 compliance, production scrapers
 * - Example: "1234-5678-9012-3456" → "[REDACTED]" (even if invalid Luhn)
 *
 * **strictMode: false** (permissive)
 * - Only redacts valid Luhn checksums for credit cards
 * - Use for: Development, testing with synthetic data
 * - Example: "1234-5678-9012-3456" → "1234-5678-9012-3456" (invalid Luhn, not redacted)
 *
 * ## Expected False Positives
 *
 * Strict mode may redact non-PII patterns that resemble sensitive data:
 * - Product codes: "SKU-1234567890123456"
 * - Invoice numbers: "INV-20240115-98765"
 * - Long numeric IDs without dashes
 * - IP-like patterns in version strings: "192.168.1.999"
 *
 * **Mitigation:** Use strictMode=false if false positives are problematic,
 * but document why compliance mode is disabled (required for SOC 2 audits).
 *
 * ## Usage Examples
 *
 * @example Basic redaction (production scrapers)
 * import { redactPII } from '@/lib/utils/pii-redactor';
 * import { getPostHog } from '@/trigger/init';
 *
 * const cleanText = redactPII(tweet.text, {
 *   posthog: getPostHog(),
 *   source: 'x-scraper',
 *   strictMode: true  // default - safer for compliance
 * });
 *
 * @example Preserve entity types for AI/RAG pipelines
 * const text = "Reach me at 555-123-4567 or john.doe@company.com";
 * const redacted = redactPIIPreserveTypes(text);
 * // Result: "Reach me at [PHONE] or [EMAIL]"
 *
 * @example Get metadata for analytics
 * const result = redactPIIWithTypes(text);
 * // result.redactedText → "Reach me at [PHONE] or [EMAIL]"
 * // result.foundTypes    → ["PHONE", "EMAIL"]
 * // result.redactionCount → 2
 */

import type { PostHog } from 'posthog-node';
import { POSTHOG_EVENTS } from '@/lib/constants/posthog-events';
import * as Sentry from '@sentry/node';

export type PIIType =
  | 'CREDIT_CARD'
  | 'SSN'
  | 'IBAN'
  | 'BITCOIN'
  | 'AWS_KEY'
  | 'API_KEY'
  | 'IPV6'
  | 'PHONE'
  | 'EMAIL'
  | 'IPV4';

export interface RedactionResult {
  redactedText: string;
  foundTypes: PIIType[];
  redactionCount: number;
}

export interface RedactionOptions {
  /** Placeholder text to replace PII with */
  placeholder?: string;
  /** If true, redacts invalid credit cards too (recommended for compliance) */
  strictMode?: boolean;
  /** PostHog client for audit logging (optional) */
  posthog?: PostHog;
  /** Source identifier for logging (e.g., 'x-scraper', 'reddit-scraper') */
  source?: string;
}

interface PIIMatch {
  start: number;
  end: number;
  type: PIIType;
}

interface PIIPattern {
  type: PIIType;
  regex: RegExp;
}

/**
 * Validate credit card number using Luhn algorithm
 */
function isValidLuhn(cardNum: string): boolean {
  const digits = cardNum.replace(/\D/g, '');

  if (digits.length !== 15 && digits.length !== 16) {
    return false; // Amex=15, others=16
  }

  let checksum = 0;
  const digitArray = digits.split('').map(Number).reverse();

  for (let i = 0; i < digitArray.length; i++) {
    let digit = digitArray[i];

    if (i % 2 === 1) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    checksum += digit;
  }

  return checksum % 10 === 0;
}

/**
 * PII patterns ordered by specificity (longest/most-specific first)
 */
const PII_PATTERNS: PIIPattern[] = [
  {
    type: 'CREDIT_CARD',
    regex: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b/g,
  },
  {
    type: 'SSN',
    regex: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
  },
  {
    type: 'IBAN',
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b/g,
  },
  {
    type: 'BITCOIN',
    regex: /\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b/g,
  },
  {
    type: 'AWS_KEY',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    type: 'API_KEY',
    regex: /\b(sk-|pk-|ghp_|gho_|ghg_|rg-)[A-Za-z0-9_-]{20,}\b/g,  // Case-sensitive prefixes only
  },
  // IPv6 and IPv4 MUST come before PHONE (IPs can look like phone numbers with dots)
  {
    type: 'IPV6',
    regex: /::(?:ffff:)?(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/g,
  },
  {
    type: 'IPV4',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  },
  {
    type: 'PHONE',
    regex: /\+?\d{1,4}[\s\-.]?\(?\d{1,4}\)?[\s\-.]?\d{1,4}[\s\-.]?\d{1,4}[\s\-.]?\d{0,4}\b/g,  // Structured phone format
  },
  {
    type: 'EMAIL',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
];

/**
 * Validate matched patterns to reduce false positives
 */
function validateMatch(type: PIIType, matchText: string, strictMode: boolean): boolean {
  switch (type) {
    case 'CREDIT_CARD': {
      const cardNum = matchText.replace(/[-\s]/g, '');

      if (strictMode) {
        // Strict mode: redact all 15-16 digit patterns (safer for compliance)
        const digits = cardNum.replace(/\D/g, '');
        return digits.length === 15 || digits.length === 16;
      }
      // Permissive mode: only redact valid Luhn checksums
      return isValidLuhn(cardNum);
    }

    case 'SSN': {
      const digits = matchText.replace(/\D/g, '');
      // Reject obvious invalid SSNs (all same digit, starts with 000)
      return new Set(digits).size > 1 && !digits.startsWith('000');
    }

    case 'PHONE': {
      const digits = matchText.replace(/\D/g, '');
      // Reject if it looks like a credit card (15-16 digits) or SSN (9 digits)
      if (digits.length === 9 || digits.length === 15 || digits.length === 16) {
        return false;
      }
      // Must have at least 7 digits but not more than 14
      return digits.length >= 7 && digits.length <= 14;
    }

    case 'IPV4': {
      const parts = matchText.split('.');
      try {
        return parts.every(p => {
          const num = parseInt(p, 10);
          return num >= 0 && num <= 255;
        });
      } catch {
        return false;
      }
    }

    case 'IPV6': {
      // Must contain at least 2 colons
      if ((matchText.match(/:/g) || []).length < 2) {
        return false;
      }

      // Handle IPv4-mapped format (::ffff:192.0.2.1)
      if (matchText.includes('.')) {
        // Should start with :: and contain valid IPv4
        if (!matchText.startsWith('::')) {
          return false;
        }
        // Extract IPv4 part and validate
        const ipv4Part = matchText.split(':').pop() || '';
        try {
          const parts = ipv4Part.split('.');
          return parts.length === 4 && parts.every(p => {
            const num = parseInt(p, 10);
            return num >= 0 && num <= 255;
          });
        } catch {
          return false;
        }
      }

      // Split by colons and validate each segment
      const segments = matchText.split(':');

      // Empty segments are OK (for :: compression)
      for (const seg of segments) {
        if (seg) {
          // Non-empty segment must be valid hex (1-4 chars), no dots here
          if (seg.length < 1 || seg.length > 4 || !/^[0-9a-fA-F]+$/.test(seg)) {
            return false;
          }
        }
      }

      // Must have 3-9 segments (accounting for :: compression)
      return segments.length >= 3 && segments.length <= 9;
    }

    default:
      return true;
  }
}

/**
 * Log PII redaction to PostHog for audit trail
 */
function logRedaction(
  posthog: PostHog | undefined,
  source: string | undefined,
  foundTypes: PIIType[],
  redactionCount: number
): void {
  if (!posthog || foundTypes.length === 0) {
    return;
  }

  try {
    posthog.capture({
      distinctId: source ? `scraper:${source}` : 'system',
      event: POSTHOG_EVENTS.PII_REDACTED,
      properties: {
        source: source || 'unknown',
        pii_types: foundTypes,
        redaction_count: redactionCount,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    // Fail silently - don't break redaction if logging fails
    Sentry.captureException(error, {
      tags: { component: 'pii-redactor' },
      extra: { source, foundTypes, redactionCount },
    });
  }
}

/**
 * Redact PII from text
 *
 * @param text - Input text to redact
 * @param options - Redaction options
 * @returns Redacted text
 *
 * @example
 * redactPII("Email: john@example.com, Phone: 555-1234")
 * // Result: "Email: [REDACTED], Phone: [REDACTED]"
 *
 * @example With PostHog logging:
 * redactPII("Email: john@example.com", {
 *   posthog: getPostHog(),
 *   source: 'x-scraper',
 * })
 */
export function redactPII(
  text: string,
  options: RedactionOptions = {}
): string {
  const result = redactPIIWithTypes(text, options);
  return result.redactedText;
}

/**
 * Redact PII from text and return detected types
 *
 * @param text - Input text to redact
 * @param options - Redaction options
 * @returns Object with redactedText, foundTypes, and redactionCount
 *
 * @example
 * redactPIIWithTypes("Email: john@example.com")
 * // Result: { redactedText: "Email: [REDACTED]", foundTypes: ["EMAIL"], redactionCount: 1 }
 */
export function redactPIIWithTypes(
  text: string,
  options: RedactionOptions = {}
): RedactionResult {
  // Input validation
  if (typeof text !== 'string') {
    throw new TypeError(`Expected string, got ${typeof text}`);
  }

  const {
    placeholder = '[REDACTED]',
    strictMode = true,
    posthog,
    source,
  } = options;

  const found = new Set<PIIType>();
  const matches: PIIMatch[] = [];

  // Collect all non-overlapping matches
  for (const pattern of PII_PATTERNS) {
    // Reset regex state instead of creating new instance (performance optimization)
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.regex.exec(text)) !== null) {
      const matchText = match[0];
      if (validateMatch(pattern.type, matchText, strictMode)) {
        matches.push({
          start: match.index,
          end: match.index + matchText.length,
          type: pattern.type,
        });
      }
    }
  }

  // Sort by start position, then by length descending (greedy longest match)
  matches.sort((a, b) => {
    if (a.start !== b.start) {
      return a.start - b.start;
    }
    return (b.end - b.start) - (a.end - a.start);
  });

  // Build result, skipping overlapping matches
  const result: string[] = [];
  let pos = 0;
  let coveredUntil = 0;

  for (const match of matches) {
    if (match.start < coveredUntil) {
      // Overlaps with previous match - skip
      continue;
    }
    // Add text before this match
    result.push(text.substring(pos, match.start));
    result.push(placeholder);
    found.add(match.type);
    pos = match.end;
    coveredUntil = match.end;
  }

  result.push(text.substring(pos));

  const foundTypes = Array.from(found).sort();
  const redactionCount = matches.filter(m => m.start >= 0).length;

  // Log to PostHog if provided
  logRedaction(posthog, source, foundTypes, redactionCount);

  return {
    redactedText: result.join(''),
    foundTypes,
    redactionCount,
  };
}

/**
 * Redact PII but preserve entity type labels
 *
 * @param text - Input text to redact
 * @param options - Redaction options (strictMode, posthog, source)
 * @returns Text with PII replaced by type labels
 *
 * @example
 * redactPIIPreserveTypes("Email me at john@example.com")
 * // Result: "Email me at [EMAIL]"
 */
export function redactPIIPreserveTypes(
  text: string,
  options: Omit<RedactionOptions, 'placeholder'> = {}
): string {
  // Input validation
  if (typeof text !== 'string') {
    throw new TypeError(`Expected string, got ${typeof text}`);
  }

  const { strictMode = true, posthog, source } = options;

  const matches: PIIMatch[] = [];

  // Collect all non-overlapping matches
  for (const pattern of PII_PATTERNS) {
    // Reset regex state instead of creating new instance (performance optimization)
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.regex.exec(text)) !== null) {
      const matchText = match[0];
      if (validateMatch(pattern.type, matchText, strictMode)) {
        matches.push({
          start: match.index,
          end: match.index + matchText.length,
          type: pattern.type,
        });
      }
    }
  }

  // Sort by start position, then by length descending
  matches.sort((a, b) => {
    if (a.start !== b.start) {
      return a.start - b.start;
    }
    return (b.end - b.start) - (a.end - a.start);
  });

  // Build result
  const result: string[] = [];
  let pos = 0;
  let coveredUntil = 0;
  const found = new Set<PIIType>();

  for (const match of matches) {
    if (match.start < coveredUntil) {
      continue;
    }
    result.push(text.substring(pos, match.start));
    result.push(`[${match.type}]`);
    found.add(match.type);
    pos = match.end;
    coveredUntil = match.end;
  }

  result.push(text.substring(pos));

  // Log to PostHog if provided
  const foundTypes = Array.from(found).sort();
  logRedaction(posthog, source, foundTypes, matches.length);

  return result.join('');
}
