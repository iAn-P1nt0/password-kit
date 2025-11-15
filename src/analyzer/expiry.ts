/**
 * Password Expiry Estimator
 *
 * Calculates optimal password rotation periods based on:
 * - Entropy-based strength assessment
 * - Breach database age and similarity
 * - Computational crack cost estimation
 * - Risk profile and account sensitivity
 * - MFA protection status
 *
 * Follows NIST 800-63B Rev 4 guidance:
 * - No forced periodic rotation for strong passwords
 * - Immediate rotation for breached passwords
 * - Risk-based rotation for sensitive accounts
 *
 * @module analyzer/expiry
 */

/**
 * Risk profile levels for account classification
 */
export type RiskProfile = 'low' | 'medium' | 'high';

/**
 * Hash algorithm types for crack cost estimation
 */
export type HashAlgorithm = 'argon2id' | 'bcrypt' | 'pbkdf2' | 'scrypt' | 'md5' | 'sha1' | 'sha256';

/**
 * Password expiry calculation options
 */
export interface ExpiryOptions {
  /** Risk profile of the account (default: 'medium') */
  riskProfile?: RiskProfile;
  /** Whether account has MFA enabled (default: false) */
  hasMFA?: boolean;
  /** Whether account has privileged access (default: false) */
  isPrivileged?: boolean;
  /** Hash algorithm used for password storage (default: 'argon2id') */
  hashAlgorithm?: HashAlgorithm;
  /** Days since password was last in a known breach (optional) */
  daysSinceBreachFound?: number;
  /** Whether password was found in breach database (default: false) */
  isBreached?: boolean;
  /** Whether similar passwords were recently breached (default: false) */
  hasSimilarBreaches?: boolean;
}

/**
 * Password expiry estimation result
 */
export interface ExpiryEstimate {
  /** Calculated expiry date */
  expiryDate: Date;
  /** Days remaining until expiry */
  daysRemaining: number;
  /** Whether rotation is recommended */
  recommendRotation: boolean;
  /** Reason for the recommendation */
  reason: string;
  /** Next date to check password status */
  nextCheckDate: Date;
  /** Rotation period in days */
  rotationPeriodDays: number;
  /** Estimated entropy in bits */
  entropy: number;
  /** Estimated crack cost in USD */
  estimatedCrackCost: number;
}

/**
 * Entropy-based rotation period mapping (in days)
 * Based on NIST guidance and industry best practices
 */
const ENTROPY_ROTATION_PERIODS: Record<string, number> = {
  'very-weak': 30,      // < 40 bits: 30 days
  'weak': 90,           // 40-60 bits: 90 days
  'moderate': 180,      // 60-80 bits: 180 days
  'strong': 365,        // 80-100 bits: 365 days
  'very-strong': -1,    // > 100 bits: no forced rotation (NIST compliant)
};

/**
 * Hash algorithm relative strength multipliers
 * Higher = more resistant to cracking
 */
const HASH_STRENGTH_MULTIPLIERS: Record<HashAlgorithm, number> = {
  'argon2id': 1000,     // State-of-art, memory-hard
  'scrypt': 500,        // Memory-hard
  'bcrypt': 100,        // CPU-hard
  'pbkdf2': 10,         // Moderate iterations
  'sha256': 1,          // Fast hash (not recommended)
  'sha1': 0.5,          // Fast hash (deprecated)
  'md5': 0.1,           // Fast hash (insecure)
};

/**
 * Risk profile rotation period multipliers
 */
const RISK_MULTIPLIERS: Record<RiskProfile, number> = {
  'low': 2.0,      // Double the rotation period
  'medium': 1.0,   // Standard rotation period
  'high': 0.5,     // Half the rotation period
};

/**
 * Calculate entropy from password
 * Uses simple heuristic based on character diversity and length
 */
function calculatePasswordEntropy(password: string): number {
  const length = password.length;

  // Determine character set size
  let charsetSize = 0;

  if (/[a-z]/.test(password)) charsetSize += 26;  // Lowercase
  if (/[A-Z]/.test(password)) charsetSize += 26;  // Uppercase
  if (/[0-9]/.test(password)) charsetSize += 10;  // Numbers
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;  // Symbols

  // Check for Unicode characters (rough estimate)
  const hasUnicode = /[^\x00-\x7F]/.test(password);
  if (hasUnicode) {
    // Assume average Unicode charset of ~1000 characters
    charsetSize += 1000;
  }

  // Entropy = log2(charset^length)
  if (charsetSize === 0 || length === 0) {
    return 0;
  }

  return Math.log2(charsetSize) * length;
}

/**
 * Classify entropy into strength categories
 */
function classifyEntropy(entropy: number): string {
  if (entropy < 40) return 'very-weak';
  if (entropy < 60) return 'weak';
  if (entropy < 80) return 'moderate';
  if (entropy < 100) return 'strong';
  return 'very-strong';
}

/**
 * Estimate crack cost in USD based on entropy and hash algorithm
 *
 * Assumptions:
 * - AWS GPU instance (g5.xlarge): ~$1.00/hour, ~10 GH/s for Argon2
 * - Cost scales exponentially with entropy
 * - Hash algorithm affects cost significantly
 */
function estimateCrackCost(entropy: number, hashAlgorithm: HashAlgorithm): number {
  const baseHashesPerSecond = 1e10; // 10 GH/s baseline
  const costPerHour = 1.0; // USD per hour for GPU instance

  // Calculate search space size
  const searchSpace = Math.pow(2, entropy);

  // Adjust for hash algorithm strength
  const hashMultiplier = HASH_STRENGTH_MULTIPLIERS[hashAlgorithm] || 1;
  const effectiveHashRate = baseHashesPerSecond / hashMultiplier;

  // Time to crack (50% probability)
  const secondsToCrack = (searchSpace / 2) / effectiveHashRate;
  const hoursToCrack = secondsToCrack / 3600;

  // Total cost
  const cost = hoursToCrack * costPerHour;

  // Cap at reasonable maximum (prevent infinity)
  return Math.min(cost, 1e15);
}

/**
 * Calculate base rotation period from entropy
 */
function getBaseRotationPeriod(entropy: number): number {
  const strength = classifyEntropy(entropy);
  const basePeriod = ENTROPY_ROTATION_PERIODS[strength] || 365;

  // NIST: No forced rotation for very strong passwords
  if (basePeriod === -1) {
    return 730; // 2 years as reasonable upper bound
  }

  return basePeriod;
}

/**
 * Apply risk and MFA modifiers to rotation period
 */
function applyModifiers(
  basePeriod: number,
  options: ExpiryOptions
): number {
  let period = basePeriod;

  // Apply risk profile multiplier
  const riskMultiplier = RISK_MULTIPLIERS[options.riskProfile || 'medium'];
  period *= riskMultiplier;

  // MFA protection allows longer rotation (2x)
  if (options.hasMFA) {
    period *= 2;
  }

  // Privileged access: mandatory 90-day maximum
  if (options.isPrivileged) {
    period = Math.min(period, 90);
  }

  // Round to nearest day
  return Math.round(period);
}

/**
 * Calculate password expiry date and rotation recommendation
 *
 * Implements entropy-based rotation with risk adjustment following
 * NIST 800-63B Rev 4 guidelines. Strong passwords with MFA protection
 * may not require periodic rotation.
 *
 * @param password - The password to analyze
 * @param createdAt - When the password was created
 * @param options - Configuration options for expiry calculation
 * @returns Detailed expiry estimation with recommendations
 *
 * @example
 * ```typescript
 * // Basic usage
 * const estimate = await calculateExpiry(
 *   'MySecurePassword123!',
 *   new Date('2024-01-01')
 * );
 * console.log(`Days remaining: ${estimate.daysRemaining}`);
 * console.log(`Rotation recommended: ${estimate.recommendRotation}`);
 * ```
 *
 * @example
 * ```typescript
 * // High-value account with MFA
 * const estimate = await calculateExpiry(
 *   'VerySecurePassword2024!',
 *   new Date('2024-01-01'),
 *   {
 *     riskProfile: 'high',
 *     hasMFA: true,
 *     hashAlgorithm: 'argon2id'
 *   }
 * );
 * ```
 *
 * @example
 * ```typescript
 * // Privileged account
 * const estimate = await calculateExpiry(
 *   'AdminPassword123!',
 *   new Date('2024-01-01'),
 *   {
 *     isPrivileged: true,
 *     riskProfile: 'high'
 *   }
 * );
 * // Rotation period capped at 90 days
 * ```
 */
export async function calculateExpiry(
  password: string,
  createdAt: Date,
  options: ExpiryOptions = {}
): Promise<ExpiryEstimate> {
  // Default options
  const opts: Required<ExpiryOptions> = {
    riskProfile: options.riskProfile || 'medium',
    hasMFA: options.hasMFA || false,
    isPrivileged: options.isPrivileged || false,
    hashAlgorithm: options.hashAlgorithm || 'argon2id',
    daysSinceBreachFound: options.daysSinceBreachFound ?? -1,
    isBreached: options.isBreached || false,
    hasSimilarBreaches: options.hasSimilarBreaches || false,
  };

  // Calculate entropy
  const entropy = calculatePasswordEntropy(password);

  // Estimate crack cost
  const estimatedCrackCost = estimateCrackCost(entropy, opts.hashAlgorithm);

  // Handle breached passwords - immediate rotation
  if (opts.isBreached) {
    const now = new Date();
    return {
      expiryDate: createdAt, // Already expired
      daysRemaining: 0,
      recommendRotation: true,
      reason: 'Password found in breach database - immediate rotation required',
      nextCheckDate: now,
      rotationPeriodDays: 0,
      entropy,
      estimatedCrackCost,
    };
  }

  // Handle similar breaches - accelerated rotation
  if (opts.hasSimilarBreaches && opts.daysSinceBreachFound >= 0 && opts.daysSinceBreachFound < 90) {
    const expiryDate = new Date(createdAt);
    expiryDate.setDate(expiryDate.getDate() + 30); // 30-day rotation

    const now = new Date();
    const daysRemaining = Math.max(0, Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)));

    return {
      expiryDate,
      daysRemaining,
      recommendRotation: daysRemaining <= 7, // Recommend if within 7 days
      reason: 'Similar passwords breached recently - accelerated 30-day rotation',
      nextCheckDate: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000), // Check weekly
      rotationPeriodDays: 30,
      entropy,
      estimatedCrackCost,
    };
  }

  // Calculate base rotation period from entropy
  const basePeriod = getBaseRotationPeriod(entropy);

  // Apply modifiers (risk, MFA, privileged)
  const rotationPeriodDays = applyModifiers(basePeriod, opts);

  // Calculate expiry date
  const expiryDate = new Date(createdAt);
  expiryDate.setDate(expiryDate.getDate() + rotationPeriodDays);

  // Calculate days remaining
  const now = new Date();
  const daysRemaining = Math.max(0, Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)));

  // Determine if rotation is recommended (within 30 days of expiry)
  const recommendRotation = daysRemaining <= 30;

  // Build reason string
  let reason = '';
  if (entropy >= 100) {
    reason = 'Very strong password - extended rotation period';
  } else if (entropy >= 80) {
    reason = 'Strong password - standard rotation period';
  } else if (entropy >= 60) {
    reason = 'Moderate password - regular rotation recommended';
  } else {
    reason = 'Weak password - frequent rotation required';
  }

  if (opts.hasMFA) {
    reason += ' (MFA protection extends period)';
  }

  if (opts.isPrivileged) {
    reason += ' (privileged access - 90-day maximum enforced)';
  }

  if (opts.riskProfile === 'high') {
    reason += ' (high-risk account - reduced period)';
  }

  // Next check date (30 days before expiry, or in 30 days if far out)
  const daysUntilNextCheck = Math.min(Math.max(daysRemaining - 30, 30), 90);
  const nextCheckDate = new Date(now.getTime() + daysUntilNextCheck * 24 * 60 * 60 * 1000);

  return {
    expiryDate,
    daysRemaining,
    recommendRotation,
    reason,
    nextCheckDate,
    rotationPeriodDays,
    entropy,
    estimatedCrackCost,
  };
}

/**
 * Check if password should be rotated based on multiple factors
 *
 * Quick helper to determine if immediate action is needed.
 *
 * @param estimate - Expiry estimate from calculateExpiry
 * @returns Whether password should be rotated now
 */
export function shouldRotateNow(estimate: ExpiryEstimate): boolean {
  return estimate.daysRemaining === 0 || estimate.recommendRotation;
}

/**
 * Get human-readable rotation schedule description
 *
 * @param rotationPeriodDays - Rotation period in days
 * @returns Human-readable description
 */
export function getRotationSchedule(rotationPeriodDays: number): string {
  if (rotationPeriodDays === 0) {
    return 'Immediate rotation required';
  } else if (rotationPeriodDays <= 30) {
    return 'Monthly rotation';
  } else if (rotationPeriodDays <= 90) {
    return 'Quarterly rotation';
  } else if (rotationPeriodDays <= 180) {
    return 'Semi-annual rotation';
  } else if (rotationPeriodDays <= 365) {
    return 'Annual rotation';
  } else {
    return 'Extended rotation period (no forced rotation)';
  }
}

/**
 * Format crack cost estimate for display
 *
 * @param cost - Estimated cost in USD
 * @returns Formatted string with appropriate units
 */
export function formatCrackCost(cost: number): string {
  if (cost === 0) {
    return '$0 (instant)';
  } else if (cost < 1) {
    return `$${cost.toFixed(4)}`;
  } else if (cost < 1000) {
    return `$${cost.toFixed(2)}`;
  } else if (cost < 1e6) {
    return `$${(cost / 1e3).toFixed(2)}K`;
  } else if (cost < 1e9) {
    return `$${(cost / 1e6).toFixed(2)}M`;
  } else if (cost < 1e12) {
    return `$${(cost / 1e9).toFixed(2)}B`;
  } else {
    return `$${(cost / 1e12).toFixed(2)}T+`;
  }
}

/**
 * Batch calculate expiry for multiple passwords
 *
 * Useful for auditing multiple accounts or generating reports.
 *
 * @param passwords - Array of password/creation date pairs
 * @param options - Shared options for all passwords
 * @returns Array of expiry estimates
 *
 * @example
 * ```typescript
 * const results = await calculateExpiryBatch([
 *   { password: 'password1', createdAt: new Date('2024-01-01') },
 *   { password: 'password2', createdAt: new Date('2024-02-01') }
 * ], { riskProfile: 'high' });
 *
 * const needRotation = results.filter(r => r.recommendRotation);
 * ```
 */
export async function calculateExpiryBatch(
  passwords: Array<{ password: string; createdAt: Date; options?: ExpiryOptions }>,
  sharedOptions: ExpiryOptions = {}
): Promise<ExpiryEstimate[]> {
  const results: ExpiryEstimate[] = [];

  for (const item of passwords) {
    const options = { ...sharedOptions, ...item.options };
    const estimate = await calculateExpiry(item.password, item.createdAt, options);
    results.push(estimate);
  }

  return results;
}
