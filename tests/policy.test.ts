/**
 * Tests for NIST 800-63B Password Policy Engine
 *
 * Tests cover:
 * - NIST 800-63B Rev 4 compliance
 * - Length requirements
 * - Blocklist checking
 * - Pattern detection
 * - Context-aware validation
 * - Unicode normalization
 * - Custom rules
 */

import { describe, it, expect } from 'vitest';
import {
  validatePassword,
  getDefaultPolicy,
  createPolicy,
  validatePasswordsBatch,
  type ValidationRule,
} from '../src/analyzer/policy';

describe('NIST 800-63B Compliance', () => {
  it('should enforce minimum 15 characters by default', async () => {
    const result = await validatePassword('short');

    expect(result.valid).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]?.field).toBe('length');
    expect(result.violations[0]?.message).toContain('15 characters');
  });

  it('should allow passwords ≥15 characters', async () => {
    const result = await validatePassword('ThisIsAValidPassword123');

    // May have warnings but should be valid (no errors)
    expect(result.violations.every(v => v.severity !== 'error')).toBe(true);
  });

  it('should enforce maximum 128 characters by default', async () => {
    const longPassword = 'a'.repeat(200);
    const result = await validatePassword(longPassword);

    expect(result.valid).toBe(false);
    const lengthViolation = result.violations.find(v => v.field === 'length');
    expect(lengthViolation?.message).toContain('128');
  });

  it('should allow all printable ASCII characters by default', async () => {
    const password = 'Test!@#$%^&*()_+-={}[]|:;<>?,./~`123';
    const result = await validatePassword(password);

    // Should not have character restriction violations
    const charViolation = result.violations.find(v => v.field === 'characters');
    expect(charViolation).toBeUndefined();
  });

  it('should support Unicode characters', async () => {
    const password = 'пароль密码🔐Test123456';
    const result = await validatePassword(password);

    // Should not have character violations for Unicode
    const charViolation = result.violations.find(v => v.field === 'characters');
    expect(charViolation).toBeUndefined();
  });

  it('should NOT enforce composition rules', async () => {
    // All lowercase, no numbers/symbols - NIST says this is OK if long enough
    const password = 'thisisavalidpasswordwithnorules';
    const result = await validatePassword(password);

    // Should be valid (NIST prohibits composition rules)
    expect(result.valid).toBe(true);
  });
});

describe('Length Validation', () => {
  it('should enforce custom minimum length', async () => {
    const result = await validatePassword('short', { minLength: 20 });

    expect(result.valid).toBe(false);
    expect(result.violations[0]?.message).toContain('20 characters');
  });

  it('should enforce custom maximum length', async () => {
    const password = 'a'.repeat(100);
    const result = await validatePassword(password, { maxLength: 64 });

    expect(result.valid).toBe(false);
    expect(result.violations[0]?.message).toContain('64');
  });

  it('should accept password at exact minimum length', async () => {
    const password = 'a'.repeat(15);
    const result = await validatePassword(password, { minLength: 15 });

    // Length should be OK
    const lengthViolation = result.violations.find(
      v => v.field === 'length' && v.severity === 'error'
    );
    expect(lengthViolation).toBeUndefined();
  });
});

describe('Common Password Blocklist', () => {
  it('should reject common passwords', async () => {
    const commonPasswords = ['password', '123456', 'qwerty', 'abc123'];

    for (const pwd of commonPasswords) {
      const result = await validatePassword(pwd, { minLength: 1 }); // Override length for testing

      expect(result.valid).toBe(false);
      const blocklist = result.violations.find(v => v.field === 'blocklist');
      expect(blocklist).toBeDefined();
      expect(blocklist?.severity).toBe('error');
    }
  });

  it('should be case-insensitive for blocklist', async () => {
    const result = await validatePassword('PASSWORD', { minLength: 1 });

    expect(result.valid).toBe(false);
    const blocklist = result.violations.find(v => v.field === 'blocklist');
    expect(blocklist).toBeDefined();
  });

  it('should allow uncommon passwords', async () => {
    const password = 'VeryUniquePassword2024!ForTesting';
    const result = await validatePassword(password);

    const blocklist = result.violations.find(v => v.field === 'blocklist');
    expect(blocklist).toBeUndefined();
  });
});

describe('Pattern Detection', () => {
  it('should detect keyboard patterns', async () => {
    const result = await validatePassword('qwertyuiopasdfgh', { minLength: 10 });

    const pattern = result.violations.find(v => v.field === 'pattern');
    expect(pattern).toBeDefined();
    expect(pattern?.details).toContain('keyboard pattern');
  });

  it('should detect repetitive patterns', async () => {
    const result = await validatePassword('aaaabbbbccccdddd', { minLength: 10 });

    const pattern = result.violations.find(v => v.field === 'pattern');
    expect(pattern).toBeDefined();
    expect(pattern?.details).toContain('repetitive');
  });

  it('should detect sequential patterns', async () => {
    const passwords = [
      'abc123defghijklm',
      '123456789abcdefg',
      'abcdefghijklmnop',
    ];

    for (const pwd of passwords) {
      const result = await validatePassword(pwd, { minLength: 10 });

      const pattern = result.violations.find(v => v.field === 'pattern');
      expect(pattern).toBeDefined();
    }
  });

  it('should detect year patterns', async () => {
    const result = await validatePassword('MyPassword2024!!', { minLength: 10 });

    const pattern = result.violations.find(
      v => v.field === 'pattern' && v.details?.includes('year')
    );
    expect(pattern).toBeDefined();
  });

  it('should allow disabling pattern detection', async () => {
    const result = await validatePassword('qwerty1234567890', {
      minLength: 10,
      detectPatterns: false,
    });

    const patterns = result.violations.filter(v => v.field === 'pattern');
    expect(patterns).toHaveLength(0);
  });

  it('should mark pattern violations as warnings, not errors', async () => {
    const result = await validatePassword('qwertyPasswordTest123', {
      minLength: 10,
    });

    const patterns = result.violations.filter(v => v.field === 'pattern');
    patterns.forEach(pattern => {
      expect(pattern.severity).toBe('warning');
    });
  });
});

describe('Context-Aware Validation', () => {
  it('should reject password containing username', async () => {
    const result = await validatePassword(
      'john.doePassword123',
      { minLength: 10 },
      { username: 'john.doe' }
    );

    expect(result.valid).toBe(false);
    const context = result.violations.find(v => v.field === 'context');
    expect(context).toBeDefined();
    expect(context?.details).toContain('username');
  });

  it('should reject password containing email local part', async () => {
    const result = await validatePassword(
      'john.smith123Password',
      { minLength: 10 },
      { email: 'john.smith@example.com' }
    );

    expect(result.valid).toBe(false);
    const context = result.violations.find(v => v.field === 'context');
    expect(context).toBeDefined();
    expect(context?.details).toContain('email');
  });

  it('should reject password containing first or last name', async () => {
    const result1 = await validatePassword(
      'JohnSecurePassword2024',
      { minLength: 10 },
      { firstName: 'John' }
    );

    expect(result1.valid).toBe(false);
    expect(result1.violations.find(v => v.field === 'context')).toBeDefined();

    const result2 = await validatePassword(
      'SmithSecurePassword2024',
      { minLength: 10 },
      { lastName: 'Smith' }
    );

    expect(result2.valid).toBe(false);
    expect(result2.violations.find(v => v.field === 'context')).toBeDefined();
  });

  it('should reject password containing context words', async () => {
    const result = await validatePassword(
      'AcmeCorpPassword2024',
      {
        minLength: 10,
        contextWords: ['acme', 'corp'],
      }
    );

    expect(result.valid).toBe(false);
    const context = result.violations.find(v => v.field === 'context');
    expect(context).toBeDefined();
  });

  it('should be case-insensitive for context checks', async () => {
    const result = await validatePassword(
      'JOHNDOEPassword2024',
      { minLength: 10 },
      { username: 'john.doe' }
    );

    expect(result.valid).toBe(false);
  });
});

describe('Unicode Normalization', () => {
  it('should normalize password using NFKC by default', async () => {
    // Different representations of same character
    const password1 = 'Café'; // é as single char (U+00E9)
    const password2 = 'Café'; // é as e + combining acute (U+0065 U+0301)

    const result1 = await validatePassword(password1 + 'SecureTest123');
    const result2 = await validatePassword(password2 + 'SecureTest123');

    // After normalization, should be equivalent
    expect(result1.normalized).toBe(result2.normalized);
  });

  it('should support different normalization forms', async () => {
    const password = 'Café123SecurePassword';

    const nfc = await validatePassword(password, { normalization: 'NFC' });
    const nfd = await validatePassword(password, { normalization: 'NFD' });
    const nfkc = await validatePassword(password, { normalization: 'NFKC' });
    const nfkd = await validatePassword(password, { normalization: 'NFKD' });

    expect(nfc.normalized).toBeDefined();
    expect(nfd.normalized).toBeDefined();
    expect(nfkc.normalized).toBeDefined();
    expect(nfkd.normalized).toBeDefined();
  });
});

describe('Custom Rules', () => {
  it('should support custom validation rules', async () => {
    const noProfanityRule: ValidationRule = {
      name: 'no-profanity',
      validate: (pwd) => !pwd.toLowerCase().includes('badword'),
      message: 'Password contains inappropriate language',
      severity: 'error',
    };

    const result = await validatePassword(
      'badwordInPassword123',
      {
        minLength: 10,
        customRules: [noProfanityRule],
      }
    );

    expect(result.valid).toBe(false);
    const custom = result.violations.find(v => v.field === 'custom');
    expect(custom).toBeDefined();
    expect(custom?.message).toContain('inappropriate language');
  });

  it('should support warning-level custom rules', async () => {
    const preferUpperRule: ValidationRule = {
      name: 'prefer-uppercase',
      validate: (pwd) => /[A-Z]/.test(pwd),
      message: 'Password should contain at least one uppercase letter',
      severity: 'warning',
    };

    const result = await validatePassword(
      'alllowercasepassword123',
      {
        minLength: 10,
        customRules: [preferUpperRule],
      }
    );

    // Should be valid (warning doesn't block)
    expect(result.valid).toBe(true);
    const custom = result.violations.find(v => v.field === 'custom');
    expect(custom).toBeDefined();
    expect(custom?.severity).toBe('warning');
  });

  it('should pass context to custom rules', async () => {
    const noUsernameInReverseRule: ValidationRule = {
      name: 'no-reverse-username',
      validate: (pwd, ctx) => {
        if (!ctx?.username) return true;
        const reversed = ctx.username.split('').reverse().join('');
        return !pwd.toLowerCase().includes(reversed.toLowerCase());
      },
      message: 'Password contains username in reverse',
      severity: 'error',
    };

    const result = await validatePassword(
      'eodnhojPassword2024',
      {
        minLength: 10,
        customRules: [noUsernameInReverseRule],
      },
      { username: 'johndoe' }
    );

    expect(result.valid).toBe(false);
  });
});

describe('Score Calculation', () => {
  it('should calculate score based on violations', async () => {
    const perfect = await validatePassword('VerySecureUniquePassword2024!Test');
    expect(perfect.score).toBeGreaterThan(70);

    const weak = await validatePassword('password', { minLength: 1 });
    // "password" gets 1 error (blocklist) = 100 - 20 = 80
    expect(weak.score).toBe(80);
    expect(weak.valid).toBe(false);
  });

  it('should penalize errors more than warnings', async () => {
    // Just warnings (keyboard pattern)
    const warnings = await validatePassword('qwertyPasswordUniqueTest', {
      minLength: 10,
    });

    // Multiple errors (length + blocklist)
    const errors = await validatePassword('password');

    // Warnings: 100 - 10 = 90
    // Errors: 100 - 20 (blocklist) - 20 (length) = 60
    expect(warnings.score).toBeGreaterThan(errors.score || 0);
  });
});

describe('Helper Functions', () => {
  it('should return default policy', () => {
    const defaults = getDefaultPolicy();

    expect(defaults.minLength).toBe(15);
    expect(defaults.maxLength).toBe(128);
    expect(defaults.normalization).toBe('NFKC');
    expect(defaults.detectPatterns).toBe(true);
  });

  it('should create custom policy', () => {
    const policy = createPolicy({
      minLength: 20,
      contextWords: ['test'],
    });

    expect(policy.minLength).toBe(20);
    expect(policy.maxLength).toBe(128); // Default
    expect(policy.contextWords).toContain('test');
  });
});

describe('Batch Validation', () => {
  it('should validate multiple passwords', async () => {
    const passwords = [
      'ValidPassword123Test',
      'password',
      'AnotherValidOne2024!',
    ];

    const results = await validatePasswordsBatch(passwords, { minLength: 10 });

    expect(results).toHaveLength(3);
    expect(results[0]?.valid).toBe(true);
    expect(results[1]?.valid).toBe(false);
    expect(results[2]?.valid).toBe(true);
  });

  it('should support contexts in batch validation', async () => {
    const passwords = ['john.doePassword123', 'UniquePassword123'];
    const contexts = [{ username: 'john.doe' }, { username: 'alice' }];

    const results = await validatePasswordsBatch(
      passwords,
      { minLength: 10 },
      contexts
    );

    expect(results[0]?.valid).toBe(false); // Contains username
    expect(results[1]?.valid).toBe(true); // Doesn't contain alice
  });
});

describe('Edge Cases', () => {
  it('should handle empty password', async () => {
    const result = await validatePassword('');

    expect(result.valid).toBe(false);
    expect(result.violations[0]?.field).toBe('length');
  });

  it('should handle null/undefined gracefully', async () => {
    const result = await validatePassword(undefined as any);

    expect(result.valid).toBe(false);
  });

  it('should handle very long passwords', async () => {
    const veryLong = 'a'.repeat(1000);
    const result = await validatePassword(veryLong, { maxLength: 256 });

    expect(result.valid).toBe(false);
    expect(result.violations[0]?.field).toBe('length');
  });

  it('should handle special Unicode characters', async () => {
    const emoji = '🔐🔑🛡️MySecurePassword2024';
    const result = await validatePassword(emoji);

    // Should normalize and validate
    expect(result.normalized).toBeDefined();
  });
});
