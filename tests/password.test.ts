/**
 * Tests for password generator
 */

import { describe, it, expect } from 'vitest';
import {
  generatePassword,
  generatePasswords,
  generatePronounceablePassword,
  getDefaultOptions,
  type PasswordGeneratorOptions,
} from '../src/generators/password';

describe('Password Generator', () => {
  describe('generatePassword', () => {
    it('should generate password with correct length', () => {
      const options: PasswordGeneratorOptions = {
        length: 16,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true,
        excludeAmbiguous: false,
      };

      const result = generatePassword(options);
      expect(result.password).toHaveLength(16);
    });

    it('should include all selected character types', () => {
      const options: PasswordGeneratorOptions = {
        length: 20,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true,
        excludeAmbiguous: false,
      };

      const result = generatePassword(options);
      expect(result.password).toMatch(/[A-Z]/); // Has uppercase
      expect(result.password).toMatch(/[a-z]/); // Has lowercase
      expect(result.password).toMatch(/[0-9]/); // Has numbers
      expect(result.password).toMatch(/[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/); // Has symbols
    });

    it('should exclude ambiguous characters when requested', () => {
      const options: PasswordGeneratorOptions = {
        length: 20,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: false,
        excludeAmbiguous: true,
      };

      const result = generatePassword(options);
      expect(result.password).not.toMatch(/[0Ol1I]/); // No ambiguous chars
    });

    it('should calculate entropy correctly', () => {
      const options: PasswordGeneratorOptions = {
        length: 16,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true,
        excludeAmbiguous: false,
      };

      const result = generatePassword(options);
      expect(result.entropy).toBeGreaterThan(90); // 16 chars with all types
      expect(result.entropy).toBeLessThan(110);
    });

    it('should determine strength correctly', () => {
      const weakOptions: PasswordGeneratorOptions = {
        length: 8,
        includeUppercase: false,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: false,
        excludeAmbiguous: false,
      };

      const strongOptions: PasswordGeneratorOptions = {
        length: 20,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true,
        excludeAmbiguous: false,
      };

      const weakResult = generatePassword(weakOptions);
      const strongResult = generatePassword(strongOptions);

      expect(['weak', 'medium']).toContain(weakResult.strength);
      expect(['strong', 'very-strong']).toContain(strongResult.strength);
    });

    it('should throw error for invalid length', () => {
      const invalidOptions: PasswordGeneratorOptions = {
        length: 5, // Too short
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers: true,
        includeSymbols: true,
        excludeAmbiguous: false,
      };

      expect(() => generatePassword(invalidOptions)).toThrow('Password length must be between 8 and 128');
    });

    it('should throw error when no character sets selected', () => {
      const invalidOptions: PasswordGeneratorOptions = {
        length: 12,
        includeUppercase: false,
        includeLowercase: false,
        includeNumbers: false,
        includeSymbols: false,
        excludeAmbiguous: false,
      };

      expect(() => generatePassword(invalidOptions)).toThrow('At least one character set must be selected');
    });

    it('should use custom charset when provided', () => {
      const options: PasswordGeneratorOptions = {
        length: 10,
        includeUppercase: false,
        includeLowercase: false,
        includeNumbers: false,
        includeSymbols: false,
        excludeAmbiguous: false,
        customCharset: 'ABC123',
      };

      const result = generatePassword(options);
      expect(result.password).toMatch(/^[ABC123]+$/);
      expect(result.password).toHaveLength(10);
    });

    it('should generate unique passwords', () => {
      const options = getDefaultOptions();
      const passwords = new Set<string>();

      for (let i = 0; i < 100; i++) {
        passwords.add(generatePassword(options).password);
      }

      // All 100 passwords should be unique
      expect(passwords.size).toBe(100);
    });
  });

  describe('generatePasswords', () => {
    it('should generate multiple passwords', () => {
      const options = getDefaultOptions();
      const passwords = generatePasswords(5, options);

      expect(passwords).toHaveLength(5);
      passwords.forEach(p => {
        expect(p.password).toHaveLength(options.length);
        expect(p.entropy).toBeGreaterThan(0);
      });
    });

    it('should throw error for invalid count', () => {
      const options = getDefaultOptions();
      expect(() => generatePasswords(0, options)).toThrow('Count must be between 1 and 100');
      expect(() => generatePasswords(101, options)).toThrow('Count must be between 1 and 100');
    });
  });

  describe('generatePronounceablePassword', () => {
    it('should generate pronounceable password with correct length', () => {
      const result = generatePronounceablePassword(12);
      expect(result.password).toHaveLength(12);
    });

    it('should contain vowels and consonants', () => {
      const result = generatePronounceablePassword(16);
      expect(result.password).toMatch(/[aeiou]/i); // Has vowels
      expect(result.password).toMatch(/[bcdfghjklmnpqrstvwxyz]/i); // Has consonants
    });

    it('should contain numbers', () => {
      const result = generatePronounceablePassword(16);
      expect(result.password).toMatch(/[0-9]/); // Has numbers
    });

    it('should throw error for invalid length', () => {
      expect(() => generatePronounceablePassword(5)).toThrow('Length must be between 8 and 128');
      expect(() => generatePronounceablePassword(200)).toThrow('Length must be between 8 and 128');
    });
  });

  describe('getDefaultOptions', () => {
    it('should return secure default options', () => {
      const defaults = getDefaultOptions();

      expect(defaults.length).toBe(16);
      expect(defaults.includeUppercase).toBe(true);
      expect(defaults.includeLowercase).toBe(true);
      expect(defaults.includeNumbers).toBe(true);
      expect(defaults.includeSymbols).toBe(true);
      expect(defaults.excludeAmbiguous).toBe(false);
    });
  });
});
