/**
 * Tests for password strength analyzer
 */

import { describe, it, expect } from 'vitest';
import { analyzePasswordStrength } from '../src/analyzer/strength';
import {
  quickStrengthCheck,
  meetsMinimumRequirements,
} from '../src/analyzer/quick-check';

describe('Password Strength Analyzer', () => {
  describe('analyzePasswordStrength', () => {
    it('should return weak for empty password', () => {
      const result = analyzePasswordStrength('');
      expect(result.strength).toBe('weak');
      expect(result.score).toBe(0);
      expect(result.weaknesses).toContain('Password is empty');
    });

    it('should return weak for short password', () => {
      const result = analyzePasswordStrength('abc123');
      expect(result.strength).toBe('weak');
      expect(result.weaknesses).toContain('Password is too short (minimum 8 characters)');
    });

    it('should detect common patterns', () => {
      const result = analyzePasswordStrength('password123');
      expect(result.weaknesses.some(w => w.includes('common pattern'))).toBe(true);
    });

    it('should detect keyboard patterns', () => {
      const result = analyzePasswordStrength('qwerty12345');
      expect(result.weaknesses.some(w => w.includes('keyboard pattern'))).toBe(true);
    });

    it('should detect year patterns', () => {
      const result = analyzePasswordStrength('test2024pass');
      expect(result.weaknesses.some(w => w.includes('year or date'))).toBe(true);
    });

    it('should return strong for good password', () => {
      const result = analyzePasswordStrength('X9$mK#2pL@7qR!4s');
      expect(['strong', 'very-strong']).toContain(result.strength);
      expect(result.score).toBeGreaterThan(60);
    });

    it('should calculate entropy', () => {
      const result = analyzePasswordStrength('MyP@ssw0rd123');
      expect(result.entropy).toBeGreaterThan(0);
      expect(result.entropy).toBeLessThan(100);
    });

    it('should provide crack time estimate', () => {
      const result = analyzePasswordStrength('weakpass');
      expect(result.crackTime).toBeTruthy();
      expect(result.crackTimeSeconds).toBeGreaterThanOrEqual(0);
    });

    it('should provide feedback', () => {
      const result = analyzePasswordStrength('password');
      expect(result.feedback).toBeDefined();
      expect(result.feedback.suggestions).toBeInstanceOf(Array);
    });

    it('should detect lack of character diversity', () => {
      const result = analyzePasswordStrength('alllowercase');
      expect(result.weaknesses.some(w => w.includes('character diversity'))).toBe(true);
    });

    it('should give higher score to diverse passwords', () => {
      const simple = analyzePasswordStrength('aaaaaaaa');
      const diverse = analyzePasswordStrength('aB3$fG9@');
      
      expect(diverse.score).toBeGreaterThan(simple.score);
      expect(diverse.entropy).toBeGreaterThan(simple.entropy);
    });
  });

  describe('quickStrengthCheck', () => {
    it('should return weak for empty password', () => {
      const result = quickStrengthCheck('');
      expect(result.strength).toBe('weak');
      expect(result.score).toBe(0);
    });

    it('should give points for length', () => {
      const short = quickStrengthCheck('abc123');
      const long = quickStrengthCheck('abcdefghijklmnopqrstuvwxyz');
      
      expect(long.score).toBeGreaterThan(short.score);
    });

    it('should give points for character diversity', () => {
      const simple = quickStrengthCheck('aaaaaaaaaa');
      const diverse = quickStrengthCheck('Aa1!bcdefg');
      
      expect(diverse.score).toBeGreaterThan(simple.score);
    });

    it('should penalize common patterns', () => {
      const unique = quickStrengthCheck('xK9$mPqR2#');
      const common = quickStrengthCheck('password12');
      
      expect(unique.score).toBeGreaterThan(common.score);
    });

    it('should classify strength correctly', () => {
      const weak = quickStrengthCheck('pass');
      const medium = quickStrengthCheck('password123');
      const strong = quickStrengthCheck('MyP@ssw0rd!2024');
      const veryStrong = quickStrengthCheck('X9$mK#2pL@7qR!4sWnYb');

      expect(weak.strength).toBe('weak');
      expect(['weak', 'medium']).toContain(medium.strength);
      expect(['medium', 'strong', 'very-strong']).toContain(strong.strength);
      expect(['strong', 'very-strong']).toContain(veryStrong.strength);
    });

    it('should be fast enough for real-time use', () => {
      const start = Date.now();
      for (let i = 0; i < 100; i++) {
        quickStrengthCheck('test-password-' + i);
      }
      const duration = Date.now() - start;
      
      // Should complete 100 checks in under 100ms
      expect(duration).toBeLessThan(100);
    });
  });

  describe('meetsMinimumRequirements', () => {
    it('should pass for valid password', () => {
      const result = meetsMinimumRequirements('MyP@ssw0rd');
      expect(result.meets).toBe(true);
      expect(result.missing).toHaveLength(0);
    });

    it('should require at least 8 characters', () => {
      const result = meetsMinimumRequirements('Abc1');
      expect(result.meets).toBe(false);
      expect(result.missing).toContain('At least 8 characters');
    });

    it('should require lowercase letter', () => {
      const result = meetsMinimumRequirements('ABCD1234');
      expect(result.meets).toBe(false);
      expect(result.missing).toContain('One lowercase letter');
    });

    it('should require uppercase letter', () => {
      const result = meetsMinimumRequirements('abcd1234');
      expect(result.meets).toBe(false);
      expect(result.missing).toContain('One uppercase letter');
    });

    it('should require number', () => {
      const result = meetsMinimumRequirements('Abcdefgh');
      expect(result.meets).toBe(false);
      expect(result.missing).toContain('One number');
    });

    it('should list all missing requirements', () => {
      const result = meetsMinimumRequirements('abc');
      expect(result.meets).toBe(false);
      expect(result.missing.length).toBeGreaterThan(1);
    });

    it('should not require symbols', () => {
      // Symbols are recommended but not required
      const result = meetsMinimumRequirements('MyPassword123');
      expect(result.meets).toBe(true);
    });
  });
});
