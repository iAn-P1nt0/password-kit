/**
 * Tests for passphrase generator
 */

import { describe, it, expect } from 'vitest';
import {
  generatePassphrase,
  generateMemorablePassphrase,
  getDefaultPassphraseOptions,
  type PassphraseOptions,
} from '../src/generators/passphrase';

describe('Passphrase Generator', () => {
  describe('generatePassphrase', () => {
    it('should generate passphrase with correct word count', () => {
      const options: PassphraseOptions = {
        wordCount: 5,
        separator: 'dash',
        capitalize: 'none',
        includeNumbers: false,
      };

      const result = generatePassphrase(options);
      const words = result.password.split('-');
      expect(words).toHaveLength(5);
    });

    it('should use dash separator correctly', () => {
      const options: PassphraseOptions = {
        wordCount: 4,
        separator: 'dash',
        capitalize: 'none',
        includeNumbers: false,
      };

      const result = generatePassphrase(options);
      expect(result.password).toMatch(/[\-_]/); // Should contain dash or underscore
    });

    it('should use space separator correctly', () => {
      const options: PassphraseOptions = {
        wordCount: 4,
        separator: 'space',
        capitalize: 'none',
        includeNumbers: false,
      };

      const result = generatePassphrase(options);
      expect(result.password).toMatch(/\s/); // Should contain space
    });

    it('should use no separator correctly', () => {
      const options: PassphraseOptions = {
        wordCount: 4,
        separator: 'none',
        capitalize: 'none',
        includeNumbers: false,
      };

      const result = generatePassphrase(options);
      expect(result.password).not.toMatch(/[\s\-_]/); // No separators
      expect(result.password.length).toBeGreaterThan(10); // Multiple words concatenated
    });

    it('should capitalize first word when requested', () => {
      const options: PassphraseOptions = {
        wordCount: 4,
        separator: 'dash',
        capitalize: 'first',
        includeNumbers: false,
      };

      const result = generatePassphrase(options);
      const firstChar = result.password.charAt(0);
      expect(firstChar).toMatch(/[A-Z0-9]/); // First char should be uppercase or number if includeNumbers was true
    });

    it('should capitalize all words when requested', () => {
      const options: PassphraseOptions = {
        wordCount: 4,
        separator: 'dash',
        capitalize: 'all',
        includeNumbers: false,
      };

      const result = generatePassphrase(options);
      const words = result.password.split(/[\-_]/);
      words.forEach(word => {
        if (word.length > 0) {
          expect(word.charAt(0)).toMatch(/[A-Z]/);
        }
      });
    });

    it('should include numbers when requested', () => {
      const options: PassphraseOptions = {
        wordCount: 5,
        separator: 'dash',
        capitalize: 'none',
        includeNumbers: true,
      };

      const result = generatePassphrase(options);
      expect(result.password).toMatch(/[0-9]/); // Should contain digits
    });

    it('should calculate entropy correctly', () => {
      const options: PassphraseOptions = {
        wordCount: 5,
        separator: 'dash',
        capitalize: 'none',
        includeNumbers: false,
      };

      const result = generatePassphrase(options);
      // 5 words from 384-word list: log2(384^5) ≈ 43 bits
      expect(result.entropy).toBeGreaterThan(40);
      expect(result.entropy).toBeLessThan(50);
    });

    it('should determine strength based on word count', () => {
      const weakOptions: PassphraseOptions = {
        wordCount: 4,
        separator: 'dash',
        capitalize: 'none',
        includeNumbers: false,
      };

      const strongOptions: PassphraseOptions = {
        wordCount: 7,
        separator: 'dash',
        capitalize: 'none',
        includeNumbers: false,
      };

      const weakResult = generatePassphrase(weakOptions);
      const strongResult = generatePassphrase(strongOptions);

      expect(['weak', 'medium']).toContain(weakResult.strength);
      expect(['strong', 'very-strong']).toContain(strongResult.strength);
    });

    it('should throw error for invalid word count', () => {
      const invalidOptions: PassphraseOptions = {
        wordCount: 2, // Too few
        separator: 'dash',
        capitalize: 'none',
        includeNumbers: false,
      };

      expect(() => generatePassphrase(invalidOptions)).toThrow('Word count must be between 4 and 8');
    });

    it('should generate unique passphrases', () => {
      const options: PassphraseOptions = {
        wordCount: 5,
        separator: 'dash',
        capitalize: 'none',
        includeNumbers: false,
      };

      const passphrases = new Set<string>();
      for (let i = 0; i < 50; i++) {
        passphrases.add(generatePassphrase(options).password);
      }

      // Most should be unique (allowing for small collision chance with 384-word list)
      expect(passphrases.size).toBeGreaterThan(45);
    });
  });

  describe('generateMemorablePassphrase', () => {
    it('should generate short passphrase with 4 words', () => {
      const result = generateMemorablePassphrase('short');
      // 4 words concatenated without separator, all capitalized
      expect(result.password).toMatch(/^[A-Z][a-z]+/); // Starts with capital
      expect(result.password).toMatch(/[0-9]/); // Has numbers
    });

    it('should generate medium passphrase with 5 words', () => {
      const result = generateMemorablePassphrase('medium');
      expect(result.password.length).toBeGreaterThan(20); // Roughly 5 words
    });

    it('should generate long passphrase with 6 words', () => {
      const result = generateMemorablePassphrase('long');
      expect(result.password.length).toBeGreaterThan(24); // Roughly 6 words
    });

    it('should capitalize all words', () => {
      const result = generateMemorablePassphrase('short');
      // Check for multiple uppercase letters (each word starts with one)
      const uppercaseCount = (result.password.match(/[A-Z]/g) || []).length;
      expect(uppercaseCount).toBeGreaterThanOrEqual(2); // At least 2 capital letters
    });
  });

  describe('getDefaultPassphraseOptions', () => {
    it('should return secure default options', () => {
      const defaults = getDefaultPassphraseOptions();

      expect(defaults.wordCount).toBe(5);
      expect(defaults.separator).toBe('dash');
      expect(defaults.capitalize).toBe('first');
      expect(defaults.includeNumbers).toBe(true);
    });
  });
});
