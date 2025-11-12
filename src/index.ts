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

// Utilities
export {
  formatTOTPCode,
} from './utils';
