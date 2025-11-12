/**
 * Tests for utility functions
 */

import { describe, it, expect } from 'vitest';
import { formatTOTPCode } from '../src/utils';

describe('Utilities', () => {
  describe('formatTOTPCode', () => {
    it('should format 6-digit code with space', () => {
      const result = formatTOTPCode('123456');
      expect(result).toBe('123 456');
    });

    it('should not modify non-6-digit codes', () => {
      expect(formatTOTPCode('12345')).toBe('12345');
      expect(formatTOTPCode('1234567')).toBe('1234567');
      expect(formatTOTPCode('1234')).toBe('1234');
    });

    it('should handle empty string', () => {
      const result = formatTOTPCode('');
      expect(result).toBe('');
    });
  });
});
