/**
 * @trustvault/password-utils
 * 
 * Cryptographically secure password and passphrase generation utilities
 * with comprehensive strength analysis.
 * 
 * @packageDocumentation
 */

// Password Generator
export {
  generatePassword,
  generatePasswords,
  generatePronounceablePassword,
  getDefaultOptions,
  type PasswordGeneratorOptions,
  type GeneratedPassword,
} from './generators/password';

// Passphrase Generator
export {
  generatePassphrase,
  generateMemorablePassphrase,
  getDefaultPassphraseOptions,
  type PassphraseOptions,
} from './generators/passphrase';

// Strength Analysis
export {
  analyzePasswordStrength,
  type PasswordStrengthResult,
} from './analyzer/strength';

// Quick Check & Validation
export {
  quickStrengthCheck,
  meetsMinimumRequirements,
  type QuickStrengthResult,
  type MinimumRequirementsResult,
} from './analyzer/quick-check';

// Breach Checking
export {
  checkPasswordBreach,
  clearBreachCache,
  type BreachResult,
  type BreachCheckOptions,
} from './analyzer/breach';

// Password Hashing (Argon2id)
export {
  hashPassword,
  verifyPassword,
  getCapabilities,
  getDefaultArgon2Options,
  estimateHashingTime,
  benchmarkHashing,
  recommendOptions,
  Argon2Type,
  type Argon2Options,
  type HashResult,
} from './utils/argon2';

// NIST 800-63B Policy Engine
export {
  validatePassword,
  getDefaultPolicy,
  createPolicy,
  validatePasswordsBatch,
  type PolicyConfig,
  type PolicyResult,
  type PolicyViolation,
  type ValidationRule,
  type ValidationContext,
} from './analyzer/policy';

// Unicode Character Sets
export {
  generateUnicodePassword,
  getDefaultUnicodeOptions,
  getCharsetInfo,
  validateUnicodePassword,
  generateEmojiPassword,
  calculateMixedEntropy,
  CharsetType,
  type UnicodePasswordOptions,
  type UnicodePasswordResult,
} from './generators/unicode';

// Password Expiry Estimator
export {
  calculateExpiry,
  shouldRotateNow,
  getRotationSchedule,
  formatCrackCost,
  calculateExpiryBatch,
  type ExpiryOptions,
  type ExpiryEstimate,
  type RiskProfile,
  type HashAlgorithm,
} from './analyzer/expiry';

// Utilities
export {
  formatTOTPCode,
} from './utils';
