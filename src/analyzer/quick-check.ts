/**
 * Quick Password Strength Check
 * Lightweight real-time feedback without heavy zxcvbn analysis
 * Ideal for use during password input
 */

/**
 * Quick strength check result
 */
export interface QuickStrengthResult {
  /** Score from 0-100 */
  score: number;
  /** Strength classification */
  strength: 'weak' | 'medium' | 'strong' | 'very-strong';
}

/**
 * Minimum password requirements result
 */
export interface MinimumRequirementsResult {
  /** Whether all requirements are met */
  meets: boolean;
  /** List of unmet requirements */
  missing: string[];
}

/**
 * Common password patterns to check
 */
const COMMON_PATTERNS = [
  /^123+/,
  /^abc+/i,
  /qwerty/i,
  /password/i,
  /admin/i,
  /letmein/i,
  /welcome/i,
  /monkey/i,
  /dragon/i,
  /master/i,
  /^(.)\1+$/, // Repeated characters
];

/**
 * Determine strength level from score
 */
function determineStrength(score: number): 'weak' | 'medium' | 'strong' | 'very-strong' {
  if (score < 40) {
    return 'weak';
  } else if (score < 60) {
    return 'medium';
  } else if (score < 80) {
    return 'strong';
  } else {
    return 'very-strong';
  }
}

/**
 * Quick strength check without zxcvbn (for real-time feedback)
 * 
 * This is much faster than full analysis and suitable for
 * providing instant feedback as users type their password.
 * 
 * @param password - Password to check
 * @returns Quick strength assessment
 * 
 * @example
 * ```typescript
 * // Use in input onChange handler for instant feedback
 * const handlePasswordChange = (value: string) => {
 *   const { strength, score } = quickStrengthCheck(value);
 *   setStrengthIndicator(strength);
 *   setStrengthScore(score);
 * };
 * ```
 */
export function quickStrengthCheck(password: string): QuickStrengthResult {
  if (!password) {
    return { score: 0, strength: 'weak' };
  }

  let score = 0;

  // Length scoring (max 40 points)
  if (password.length >= 8) score += 10;
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;
  if (password.length >= 20) score += 10;

  // Character diversity (max 40 points)
  if (/[a-z]/.test(password)) score += 10;
  if (/[A-Z]/.test(password)) score += 10;
  if (/[0-9]/.test(password)) score += 10;
  if (/[^a-zA-Z0-9]/.test(password)) score += 10;

  // No common patterns (max 20 points)
  let hasCommonPattern = false;
  for (const pattern of COMMON_PATTERNS) {
    if (pattern.test(password)) {
      hasCommonPattern = true;
      break;
    }
  }
  if (!hasCommonPattern) score += 20;

  const strength = determineStrength(score);

  return { score, strength };
}

/**
 * Check if password meets minimum security requirements
 * 
 * Useful for form validation to ensure basic password requirements
 * are met before submission.
 * 
 * @param password - Password to validate
 * @returns Validation result with list of missing requirements
 * 
 * @example
 * ```typescript
 * const { meets, missing } = meetsMinimumRequirements('abc123');
 * if (!meets) {
 *   console.log('Password must have:', missing.join(', '));
 *   // "Password must have: At least 8 characters, One uppercase letter"
 * }
 * ```
 */
export function meetsMinimumRequirements(password: string): MinimumRequirementsResult {
  const missing: string[] = [];

  if (password.length < 8) {
    missing.push('At least 8 characters');
  }

  if (!/[a-z]/.test(password)) {
    missing.push('One lowercase letter');
  }

  if (!/[A-Z]/.test(password)) {
    missing.push('One uppercase letter');
  }

  if (!/[0-9]/.test(password)) {
    missing.push('One number');
  }

  return {
    meets: missing.length === 0,
    missing,
  };
}
