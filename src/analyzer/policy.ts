/**
 * NIST 800-63B Password Policy Engine
 *
 * Implements NIST 800-63B Rev 4 (August 2025) requirements:
 * - Minimum 15 characters (when password is sole authenticator)
 * - Maximum ≥64 characters minimum, ≥128 recommended
 * - All ASCII printable + space + Unicode support
 * - NO composition rules (no "must include number/symbol")
 * - Blocklist checking against compromised passwords
 * - No periodic expiration
 * - Unicode normalization (NFKC/NFKD)
 *
 * @module policy
 */

/**
 * Password policy configuration following NIST 800-63B Rev 4
 */
export interface PolicyConfig {
  /** Minimum password length (default: 15 per NIST when password is sole authenticator) */
  minLength: number;
  /** Maximum password length (default: 128 recommended by NIST) */
  maxLength: number;
  /** Require Unicode support (default: false) */
  requireUnicode?: boolean;
  /** Blocklists to check against (URLs or built-in refs) */
  blocklists?: string[];
  /** Context-specific words to ban (service name, username, etc.) */
  contextWords?: string[];
  /** Allowed characters (null = all printable) */
  allowedChars?: string | null;
  /** Unicode normalization form (default: NFKC) */
  normalization?: 'NFC' | 'NFD' | 'NFKC' | 'NFKD';
  /** Enable common pattern detection (default: true) */
  detectPatterns?: boolean;
  /** Custom validation rules */
  customRules?: ValidationRule[];
}

/**
 * Custom validation rule interface
 */
export interface ValidationRule {
  /** Rule name/identifier */
  name: string;
  /** Validation function */
  validate: (password: string, context?: ValidationContext) => boolean;
  /** Error message if validation fails */
  message: string;
  /** Severity: error blocks, warning allows but warns */
  severity: 'error' | 'warning';
}

/**
 * Validation context with user-specific information
 */
export interface ValidationContext {
  /** Username (to prevent password === username) */
  username?: string;
  /** Email address */
  email?: string;
  /** User's first name */
  firstName?: string;
  /** User's last name */
  lastName?: string;
  /** Additional context data */
  [key: string]: string | undefined;
}

/**
 * Policy violation details
 */
export interface PolicyViolation {
  /** Field that failed validation */
  field: string;
  /** User-friendly error message */
  message: string;
  /** Severity level */
  severity: 'error' | 'warning';
  /** Technical details (optional) */
  details?: string;
}

/**
 * Policy validation result
 */
export interface PolicyResult {
  /** Overall validation status */
  valid: boolean;
  /** List of violations found */
  violations: PolicyViolation[];
  /** Password strength score (0-100) */
  score?: number;
  /** Normalized password (after Unicode normalization) */
  normalized?: string;
}

// NIST 800-63B Rev 4 default configuration
const DEFAULT_POLICY: PolicyConfig = {
  minLength: 15, // When password is sole authenticator
  maxLength: 128, // Recommended by NIST
  requireUnicode: false,
  blocklists: ['common-passwords'], // Built-in list
  contextWords: [],
  allowedChars: null, // All printable characters allowed
  normalization: 'NFKC',
  detectPatterns: true,
  customRules: [],
};

/**
 * Top 10,000 most common passwords (subset for demo)
 * In production, this would be loaded from a file or API
 */
const COMMON_PASSWORDS = new Set([
  'password', '123456', '123456789', 'password1', '12345678',
  'qwerty', 'abc123', '111111', 'monkey', '1234567890',
  'letmein', '1234567', 'dragon', 'master', 'login',
  'princess', 'qwertyuiop', 'solo', 'passw0rd', 'starwars',
  'password123', '123123', 'welcome', 'admin', 'iloveyou',
  'sunshine', 'adobe123', 'ashley', 'bailey', 'access',
  'football', 'shadow', 'superman', '696969', '!@#$%^&*',
  'charlie', 'aa123456', 'donald', 'freedom', 'whatever',
  'michael', 'michelle', 'pepper', 'trustno1', 'jordan23',
  // Add more as needed...
]);

/**
 * Common keyboard patterns
 */
const KEYBOARD_PATTERNS = [
  'qwerty', 'qwertyuiop', 'asdf', 'asdfghjkl', 'zxcv', 'zxcvbnm',
  '1234', '12345', '123456', '1234567', '12345678', '123456789',
  'abcd', 'abcde', 'abcdef', 'abcdefg',
];

/**
 * Repetitive patterns
 */
const REPETITIVE_PATTERNS = [
  'aaa', 'bbb', 'ccc', '111', '222', '333',
  'aaaa', 'bbbb', '1111', '2222',
  'aaaaa', '11111',
];

/**
 * Sequential patterns
 */
const SEQUENTIAL_PATTERNS = [
  'abc', '123', 'xyz',
  'abcd', '1234', 'wxyz',
  'abcde', '12345',
];

/**
 * Normalize password using specified Unicode normalization form
 */
function normalizePassword(password: string, form: 'NFC' | 'NFD' | 'NFKC' | 'NFKD' = 'NFKC'): string {
  if (typeof password !== 'string') {
    return '';
  }

  try {
    return password.normalize(form);
  } catch (error) {
    // Fallback if normalization fails
    return password;
  }
}

/**
 * Check if password contains only allowed characters
 */
function checkAllowedCharacters(password: string, allowed: string | null): boolean {
  if (allowed === null) {
    // All characters allowed
    return true;
  }

  const allowedSet = new Set(allowed.split(''));
  for (const char of password) {
    if (!allowedSet.has(char)) {
      return false;
    }
  }

  return true;
}

/**
 * Check if password is in common passwords blocklist
 */
function checkCommonPassword(password: string): boolean {
  const normalized = password.toLowerCase();
  return COMMON_PASSWORDS.has(normalized);
}

/**
 * Check for keyboard patterns
 */
function checkKeyboardPatterns(password: string): string | null {
  const lower = password.toLowerCase();

  for (const pattern of KEYBOARD_PATTERNS) {
    if (lower.includes(pattern)) {
      return `keyboard pattern "${pattern}"`;
    }
  }

  return null;
}

/**
 * Check for repetitive characters
 */
function checkRepetitivePatterns(password: string): string | null {
  const lower = password.toLowerCase();

  for (const pattern of REPETITIVE_PATTERNS) {
    if (lower.includes(pattern)) {
      return `repetitive pattern "${pattern}"`;
    }
  }

  // Check for repeated characters (3+ in a row)
  const repeatMatch = lower.match(/(.)\1{2,}/);
  if (repeatMatch) {
    return `repeated character "${repeatMatch[1]}"`;
  }

  return null;
}

/**
 * Check for sequential patterns
 */
function checkSequentialPatterns(password: string): string | null {
  const lower = password.toLowerCase();

  for (const pattern of SEQUENTIAL_PATTERNS) {
    if (lower.includes(pattern)) {
      return `sequential pattern "${pattern}"`;
    }
    // Check reverse
    if (lower.includes(pattern.split('').reverse().join(''))) {
      return `sequential pattern "${pattern}" (reversed)`;
    }
  }

  return null;
}

/**
 * Check if password contains context words
 */
function checkContextWords(password: string, contextWords: string[], context?: ValidationContext): string[] {
  const lower = password.toLowerCase();
  const found: string[] = [];

  // Check provided context words
  for (const word of contextWords) {
    if (word && lower.includes(word.toLowerCase())) {
      found.push(word);
    }
  }

  // Check username (with and without special characters)
  if (context?.username) {
    const usernameLower = context.username.toLowerCase();
    const usernameAlphanumeric = usernameLower.replace(/[^a-z0-9]/g, '');
    if (lower.includes(usernameLower) || lower.includes(usernameAlphanumeric)) {
      found.push('username');
    }
  }

  // Check email local part
  if (context?.email) {
    const localPart = context.email.split('@')[0];
    if (localPart && lower.includes(localPart.toLowerCase())) {
      found.push('email');
    }
  }

  // Check first/last name
  if (context?.firstName && lower.includes(context.firstName.toLowerCase())) {
    found.push('first name');
  }
  if (context?.lastName && lower.includes(context.lastName.toLowerCase())) {
    found.push('last name');
  }

  return found;
}

/**
 * Check for common date patterns (years)
 */
function checkDatePatterns(password: string): string | null {
  // Check for year patterns (1900-2099)
  const yearMatch = password.match(/19\d{2}|20\d{2}/);
  if (yearMatch) {
    return `year pattern "${yearMatch[0]}"`;
  }

  return null;
}

/**
 * Validate password against NIST 800-63B policy
 *
 * Implements NIST 800-63B Rev 4 requirements with configurable options.
 * By default, enforces:
 * - 15 character minimum
 * - 128 character maximum
 * - No composition rules (letters/numbers/symbols not required)
 * - Blocklist checking
 * - Pattern detection
 * - Unicode normalization
 *
 * @param password - The password to validate
 * @param config - Policy configuration (uses NIST defaults if not provided)
 * @param context - Optional user context for personalized checks
 * @returns Validation result with violations and score
 *
 * @example
 * ```typescript
 * // Basic validation with defaults
 * const result = await validatePassword('MySecurePassword2024');
 * if (!result.valid) {
 *   console.log('Violations:', result.violations);
 * }
 * ```
 *
 * @example
 * ```typescript
 * // With context for personalized checks
 * const result = await validatePassword('password', {
 *   minLength: 12,
 *   contextWords: ['acme', 'corp']
 * }, {
 *   username: 'john.doe',
 *   email: 'john.doe@acme.com'
 * });
 * ```
 *
 * @example
 * ```typescript
 * // Custom configuration
 * const result = await validatePassword('password', {
 *   minLength: 20,
 *   maxLength: 256,
 *   normalization: 'NFKC',
 *   contextWords: ['mycompany'],
 *   customRules: [{
 *     name: 'no-profanity',
 *     validate: (pwd) => !pwd.includes('badword'),
 *     message: 'Password contains inappropriate language',
 *     severity: 'error'
 *   }]
 * });
 * ```
 */
export async function validatePassword(
  password: string,
  config: Partial<PolicyConfig> = {},
  context?: ValidationContext
): Promise<PolicyResult> {
  const policy: PolicyConfig = { ...DEFAULT_POLICY, ...config };
  const violations: PolicyViolation[] = [];

  // Apply Unicode normalization
  const normalized = normalizePassword(password, policy.normalization);

  // 1. Length checks (NIST requirement)
  if (normalized.length < policy.minLength) {
    violations.push({
      field: 'length',
      message: `Password must be at least ${policy.minLength} characters long`,
      severity: 'error',
      details: `Current length: ${normalized.length}`,
    });
  }

  if (normalized.length > policy.maxLength) {
    violations.push({
      field: 'length',
      message: `Password must not exceed ${policy.maxLength} characters`,
      severity: 'error',
      details: `Current length: ${normalized.length}`,
    });
  }

  // 2. Character restrictions (if specified)
  if (policy.allowedChars !== null && policy.allowedChars !== undefined) {
    if (!checkAllowedCharacters(normalized, policy.allowedChars)) {
      violations.push({
        field: 'characters',
        message: 'Password contains disallowed characters',
        severity: 'error',
      });
    }
  }

  // 3. Common password check (NIST blocklist requirement)
  if (policy.blocklists && policy.blocklists.length > 0) {
    if (checkCommonPassword(normalized)) {
      violations.push({
        field: 'blocklist',
        message: 'This password has been found in data breaches and is too common',
        severity: 'error',
        details: 'Password appears in common password list',
      });
    }
  }

  // 4. Pattern detection
  if (policy.detectPatterns) {
    // Keyboard patterns
    const keyboardPattern = checkKeyboardPatterns(normalized);
    if (keyboardPattern) {
      violations.push({
        field: 'pattern',
        message: 'Password contains common keyboard pattern',
        severity: 'warning',
        details: `Found ${keyboardPattern}`,
      });
    }

    // Repetitive patterns
    const repetitivePattern = checkRepetitivePatterns(normalized);
    if (repetitivePattern) {
      violations.push({
        field: 'pattern',
        message: 'Password contains repetitive pattern',
        severity: 'warning',
        details: `Found ${repetitivePattern}`,
      });
    }

    // Sequential patterns
    const sequentialPattern = checkSequentialPatterns(normalized);
    if (sequentialPattern) {
      violations.push({
        field: 'pattern',
        message: 'Password contains sequential pattern',
        severity: 'warning',
        details: `Found ${sequentialPattern}`,
      });
    }

    // Date patterns
    const datePattern = checkDatePatterns(normalized);
    if (datePattern) {
      violations.push({
        field: 'pattern',
        message: 'Password contains date pattern',
        severity: 'warning',
        details: `Found ${datePattern}`,
      });
    }
  }

  // 5. Context word check
  if (policy.contextWords && policy.contextWords.length > 0 || context) {
    const foundWords = checkContextWords(
      normalized,
      policy.contextWords || [],
      context
    );
    if (foundWords.length > 0) {
      violations.push({
        field: 'context',
        message: 'Password contains personal or service-related information',
        severity: 'error',
        details: `Found: ${foundWords.join(', ')}`,
      });
    }
  }

  // 6. Custom rules
  if (policy.customRules && policy.customRules.length > 0) {
    for (const rule of policy.customRules) {
      if (!rule.validate(normalized, context)) {
        violations.push({
          field: 'custom',
          message: rule.message,
          severity: rule.severity,
          details: `Rule: ${rule.name}`,
        });
      }
    }
  }

  // Calculate score based on violations
  let score = 100;
  for (const violation of violations) {
    if (violation.severity === 'error') {
      score -= 20;
    } else if (violation.severity === 'warning') {
      score -= 10;
    }
  }
  score = Math.max(0, score);

  // Determine validity (only errors block, warnings don't)
  const hasErrors = violations.some(v => v.severity === 'error');

  return {
    valid: !hasErrors,
    violations,
    score,
    normalized,
  };
}

/**
 * Get default NIST 800-63B policy configuration
 *
 * Returns the default policy settings following NIST 800-63B Rev 4.
 *
 * @returns Default policy configuration
 *
 * @example
 * ```typescript
 * const defaults = getDefaultPolicy();
 * console.log(`Min length: ${defaults.minLength}`); // 15
 * console.log(`Max length: ${defaults.maxLength}`); // 128
 * ```
 */
export function getDefaultPolicy(): PolicyConfig {
  return { ...DEFAULT_POLICY };
}

/**
 * Create a custom policy configuration
 *
 * Helper function to create policy configurations with type safety.
 *
 * @param config - Partial policy configuration
 * @returns Complete policy configuration
 *
 * @example
 * ```typescript
 * const policy = createPolicy({
 *   minLength: 12,
 *   contextWords: ['acme', 'corp'],
 *   customRules: [myCustomRule]
 * });
 * ```
 */
export function createPolicy(config: Partial<PolicyConfig>): PolicyConfig {
  return { ...DEFAULT_POLICY, ...config };
}

/**
 * Validate multiple passwords in batch
 *
 * Useful for auditing existing passwords or bulk validation.
 *
 * @param passwords - Array of passwords to validate
 * @param config - Policy configuration
 * @param contexts - Optional array of contexts (same length as passwords)
 * @returns Array of validation results
 *
 * @example
 * ```typescript
 * const results = await validatePasswordsBatch(
 *   ['password1', 'password2', 'password3'],
 *   { minLength: 12 }
 * );
 *
 * const invalid = results.filter(r => !r.valid);
 * console.log(`${invalid.length} passwords failed validation`);
 * ```
 */
export async function validatePasswordsBatch(
  passwords: string[],
  config: Partial<PolicyConfig> = {},
  contexts?: ValidationContext[]
): Promise<PolicyResult[]> {
  const results: PolicyResult[] = [];

  for (let i = 0; i < passwords.length; i++) {
    const password = passwords[i];
    const context = contexts?.[i];
    const result = await validatePassword(password!, config, context);
    results.push(result);
  }

  return results;
}
