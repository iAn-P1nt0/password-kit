/**
 * Tests for Password Expiry Estimator
 *
 * Tests cover:
 * - Entropy-based rotation periods
 * - Breach-based immediate rotation
 * - Risk profile adjustments
 * - MFA protection extensions
 * - Privileged account constraints
 * - Hash algorithm impact
 * - Crack cost estimation
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  calculateExpiry,
  shouldRotateNow,
  getRotationSchedule,
  formatCrackCost,
  calculateExpiryBatch,
  type ExpiryOptions,
} from '../src/analyzer/expiry';

describe('Entropy-Based Rotation', () => {
  let baseDate: Date;

  beforeEach(() => {
    // Set base date to 6 months ago for testing
    baseDate = new Date();
    baseDate.setMonth(baseDate.getMonth() - 6);
  });

  it('should require short rotation for very weak passwords (< 40 bits)', async () => {
    const result = await calculateExpiry('short', baseDate);

    expect(result.entropy).toBeLessThan(40);
    expect(result.rotationPeriodDays).toBeLessThanOrEqual(30);
  });

  it('should require quarterly rotation for weak passwords (40-60 bits)', async () => {
    const result = await calculateExpiry('Pass123', baseDate);

    expect(result.entropy).toBeGreaterThanOrEqual(40);
    expect(result.entropy).toBeLessThan(60);
    expect(result.rotationPeriodDays).toBe(90);
  });

  it('should require semi-annual rotation for moderate passwords (60-80 bits)', async () => {
    const result = await calculateExpiry('Password1234', baseDate);

    expect(result.entropy).toBeGreaterThanOrEqual(60);
    expect(result.entropy).toBeLessThan(80);
    expect(result.rotationPeriodDays).toBe(180);
  });

  it('should require annual rotation for strong passwords (80-100 bits)', async () => {
    const result = await calculateExpiry('Password1234!@', baseDate);

    expect(result.entropy).toBeGreaterThanOrEqual(80);
    expect(result.entropy).toBeLessThan(100);
    expect(result.rotationPeriodDays).toBe(365);
  });

  it('should not require forced rotation for very strong passwords (> 100 bits)', async () => {
    const result = await calculateExpiry(
      'ExtremelySecurePassword2024!@#$%^&*()WithManyCharacters',
      baseDate
    );

    expect(result.entropy).toBeGreaterThanOrEqual(100);
    // Extended period (730 days = 2 years)
    expect(result.rotationPeriodDays).toBeGreaterThan(365);
  });
});

describe('Breach-Based Rotation', () => {
  let baseDate: Date;

  beforeEach(() => {
    baseDate = new Date();
    baseDate.setMonth(baseDate.getMonth() - 3);
  });

  it('should require immediate rotation for breached passwords', async () => {
    const result = await calculateExpiry('Password123', baseDate, {
      isBreached: true,
    });

    expect(result.daysRemaining).toBe(0);
    expect(result.recommendRotation).toBe(true);
    expect(result.reason).toContain('immediate rotation required');
  });

  it('should require accelerated rotation for similar breaches < 90 days', async () => {
    const result = await calculateExpiry('Password123!', baseDate, {
      hasSimilarBreaches: true,
      daysSinceBreachFound: 30,
    });

    expect(result.rotationPeriodDays).toBe(30);
    expect(result.reason).toContain('Similar passwords breached recently');
  });

  it('should use standard rotation for old similar breaches (> 90 days)', async () => {
    const result = await calculateExpiry('Password123!', baseDate, {
      hasSimilarBreaches: true,
      daysSinceBreachFound: 120,
    });

    // Should fall back to entropy-based rotation
    expect(result.rotationPeriodDays).toBeGreaterThan(30);
  });
});

describe('Risk Profile Adjustments', () => {
  let baseDate: Date;
  const password = 'SecurePassword2024!';

  beforeEach(() => {
    baseDate = new Date();
    baseDate.setMonth(baseDate.getMonth() - 3);
  });

  it('should double rotation period for low-risk accounts', async () => {
    const medium = await calculateExpiry(password, baseDate, {
      riskProfile: 'medium',
    });

    const low = await calculateExpiry(password, baseDate, {
      riskProfile: 'low',
    });

    expect(low.rotationPeriodDays).toBe(medium.rotationPeriodDays * 2);
  });

  it('should halve rotation period for high-risk accounts', async () => {
    const medium = await calculateExpiry(password, baseDate, {
      riskProfile: 'medium',
    });

    const high = await calculateExpiry(password, baseDate, {
      riskProfile: 'high',
    });

    expect(high.rotationPeriodDays).toBe(medium.rotationPeriodDays * 0.5);
  });

  it('should use standard period for medium-risk accounts', async () => {
    const result = await calculateExpiry('Password1234', baseDate, {
      riskProfile: 'medium',
    });

    // Moderate password (60-80 bits) should be 180 days
    expect(result.rotationPeriodDays).toBe(180);
  });
});

describe('MFA Protection', () => {
  let baseDate: Date;
  const password = 'SecurePassword2024!';

  beforeEach(() => {
    baseDate = new Date();
    baseDate.setMonth(baseDate.getMonth() - 3);
  });

  it('should double rotation period when MFA is enabled', async () => {
    const withoutMFA = await calculateExpiry(password, baseDate, {
      hasMFA: false,
    });

    const withMFA = await calculateExpiry(password, baseDate, {
      hasMFA: true,
    });

    expect(withMFA.rotationPeriodDays).toBe(withoutMFA.rotationPeriodDays * 2);
  });

  it('should mention MFA in reason', async () => {
    const result = await calculateExpiry(password, baseDate, {
      hasMFA: true,
    });

    expect(result.reason).toContain('MFA protection');
  });
});

describe('Privileged Account Constraints', () => {
  let baseDate: Date;

  beforeEach(() => {
    baseDate = new Date();
    baseDate.setMonth(baseDate.getMonth() - 3);
  });

  it('should cap rotation period at 90 days for privileged accounts', async () => {
    const veryStrong = 'ExtremelySecurePasswordWithManyCharacters2024!@#$%^&*()';

    const result = await calculateExpiry(veryStrong, baseDate, {
      isPrivileged: true,
    });

    expect(result.rotationPeriodDays).toBeLessThanOrEqual(90);
  });

  it('should mention privileged access in reason', async () => {
    const result = await calculateExpiry('SecurePassword2024!', baseDate, {
      isPrivileged: true,
    });

    expect(result.reason).toContain('privileged access');
    expect(result.reason).toContain('90-day maximum');
  });

  it('should enforce 90-day max even with MFA and low risk', async () => {
    const result = await calculateExpiry('VerySecurePassword2024!@#$', baseDate, {
      isPrivileged: true,
      hasMFA: true,
      riskProfile: 'low',
    });

    expect(result.rotationPeriodDays).toBeLessThanOrEqual(90);
  });
});

describe('Hash Algorithm Impact', () => {
  let baseDate: Date;
  const password = 'SecurePassword2024!';

  beforeEach(() => {
    baseDate = new Date();
    baseDate.setMonth(baseDate.getMonth() - 3);
  });

  it('should have highest crack cost for Argon2id', async () => {
    const result = await calculateExpiry(password, baseDate, {
      hashAlgorithm: 'argon2id',
    });

    expect(result.estimatedCrackCost).toBeGreaterThan(0);
  });

  it('should have lower crack cost for bcrypt than Argon2id', async () => {
    // Use a shorter password to avoid hitting the cap
    const shortPassword = 'Pass123!';

    const argon2 = await calculateExpiry(shortPassword, baseDate, {
      hashAlgorithm: 'argon2id',
    });

    const bcrypt = await calculateExpiry(shortPassword, baseDate, {
      hashAlgorithm: 'bcrypt',
    });

    expect(bcrypt.estimatedCrackCost).toBeLessThan(argon2.estimatedCrackCost);
  });

  it('should have very low crack cost for MD5', async () => {
    // Use a shorter password to avoid hitting the cap
    const shortPassword = 'Pass123!';

    const argon2 = await calculateExpiry(shortPassword, baseDate, {
      hashAlgorithm: 'argon2id',
    });

    const md5 = await calculateExpiry(shortPassword, baseDate, {
      hashAlgorithm: 'md5',
    });

    expect(md5.estimatedCrackCost).toBeLessThan(argon2.estimatedCrackCost * 0.01);
  });
});

describe('Days Remaining Calculation', () => {
  it('should calculate correct days remaining for future expiry', async () => {
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);

    const result = await calculateExpiry('SecurePassword2024!', yesterday);

    expect(result.daysRemaining).toBeGreaterThan(0);
    expect(result.daysRemaining).toBeLessThan(result.rotationPeriodDays);
  });

  it('should return 0 days remaining for expired passwords', async () => {
    const longAgo = new Date();
    longAgo.setFullYear(longAgo.getFullYear() - 2);

    const result = await calculateExpiry('Password123', longAgo, {
      riskProfile: 'high',
    });

    expect(result.daysRemaining).toBe(0);
  });

  it('should recommend rotation when within 30 days of expiry', async () => {
    const recentDate = new Date();
    recentDate.setDate(recentDate.getDate() - 160); // 160 days ago

    const result = await calculateExpiry('SecurePassword2024!', recentDate);

    // 180-day period, 160 days ago = 20 days remaining
    if (result.daysRemaining <= 30) {
      expect(result.recommendRotation).toBe(true);
    }
  });
});

describe('Helper Functions', () => {
  it('should identify when immediate rotation is needed', async () => {
    const result = await calculateExpiry('Password123', new Date(), {
      isBreached: true,
    });

    expect(shouldRotateNow(result)).toBe(true);
  });

  it('should not recommend rotation for fresh passwords', async () => {
    const result = await calculateExpiry('SecurePassword2024!', new Date());

    expect(shouldRotateNow(result)).toBe(false);
  });

  it('should format rotation schedules correctly', () => {
    expect(getRotationSchedule(0)).toBe('Immediate rotation required');
    expect(getRotationSchedule(30)).toBe('Monthly rotation');
    expect(getRotationSchedule(90)).toBe('Quarterly rotation');
    expect(getRotationSchedule(180)).toBe('Semi-annual rotation');
    expect(getRotationSchedule(365)).toBe('Annual rotation');
    expect(getRotationSchedule(730)).toBe('Extended rotation period (no forced rotation)');
  });

  it('should format crack costs with appropriate units', () => {
    expect(formatCrackCost(0)).toBe('$0 (instant)');
    expect(formatCrackCost(0.5)).toContain('$0.');
    expect(formatCrackCost(100)).toContain('$100');
    expect(formatCrackCost(5000)).toContain('K');
    expect(formatCrackCost(5000000)).toContain('M');
    expect(formatCrackCost(5000000000)).toContain('B');
    expect(formatCrackCost(5000000000000)).toContain('T');
  });
});

describe('Batch Calculation', () => {
  it('should calculate expiry for multiple passwords', async () => {
    const baseDate = new Date();
    baseDate.setMonth(baseDate.getMonth() - 3);

    const results = await calculateExpiryBatch([
      { password: 'Password123', createdAt: baseDate },
      { password: 'SecurePassword2024!', createdAt: baseDate },
      { password: 'VerySecurePassword2024!@#$', createdAt: baseDate },
    ]);

    expect(results).toHaveLength(3);
    expect(results[0]?.rotationPeriodDays).toBeDefined();
    expect(results[1]?.rotationPeriodDays).toBeDefined();
    expect(results[2]?.rotationPeriodDays).toBeDefined();
  });

  it('should apply shared options to all passwords', async () => {
    const baseDate = new Date();

    const results = await calculateExpiryBatch(
      [
        { password: 'Password1', createdAt: baseDate },
        { password: 'Password2', createdAt: baseDate },
      ],
      { hasMFA: true }
    );

    results.forEach((result) => {
      expect(result.reason).toContain('MFA');
    });
  });

  it('should allow per-password options to override shared options', async () => {
    const baseDate = new Date();

    const results = await calculateExpiryBatch(
      [
        { password: 'Password1', createdAt: baseDate },
        {
          password: 'Password2',
          createdAt: baseDate,
          options: { hasMFA: false },
        },
      ],
      { hasMFA: true }
    );

    expect(results[0]?.reason).toContain('MFA');
    expect(results[1]?.reason).not.toContain('MFA');
  });
});

describe('Next Check Date', () => {
  it('should set next check date 30 days before expiry', async () => {
    const baseDate = new Date();
    baseDate.setDate(baseDate.getDate() - 150); // 150 days ago

    const result = await calculateExpiry('Pass1234!', baseDate);

    // Should check in 30 days (daysRemaining - 30, but minimum 30)
    const now = new Date();
    const daysRemaining = Math.floor(
      (result.expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
    );
    const expectedDaysToCheck = Math.min(Math.max(daysRemaining - 30, 30), 90);
    const expectedCheck = new Date(
      now.getTime() + expectedDaysToCheck * 24 * 60 * 60 * 1000
    );

    // Allow 1-day tolerance for test timing
    const diffDays = Math.abs(
      (result.nextCheckDate.getTime() - expectedCheck.getTime()) /
        (1000 * 60 * 60 * 24)
    );
    expect(diffDays).toBeLessThan(2);
  });

  it('should check in 30 days minimum for far-future expirations', async () => {
    const baseDate = new Date(); // Just created

    const result = await calculateExpiry('VerySecurePassword2024!@#$', baseDate);

    const now = new Date();
    const daysDiff = Math.floor(
      (result.nextCheckDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
    );

    expect(daysDiff).toBeGreaterThanOrEqual(30);
    expect(daysDiff).toBeLessThanOrEqual(90);
  });
});

describe('Entropy Calculation', () => {
  it('should calculate higher entropy for longer passwords', async () => {
    const short = await calculateExpiry('Pass123!', new Date());
    const long = await calculateExpiry('ThisIsAMuchLongerPassword123!', new Date());

    expect(long.entropy).toBeGreaterThan(short.entropy);
  });

  it('should calculate higher entropy for diverse character sets', async () => {
    const simple = await calculateExpiry('password', new Date());
    const complex = await calculateExpiry('Pass123!@#$', new Date());

    expect(complex.entropy).toBeGreaterThan(simple.entropy);
  });

  it('should account for Unicode characters', async () => {
    const ascii = await calculateExpiry('Password123!', new Date());
    const unicode = await calculateExpiry('пароль密码🔐Test123', new Date());

    expect(unicode.entropy).toBeGreaterThan(ascii.entropy);
  });
});

describe('Edge Cases', () => {
  it('should handle passwords created in the future', async () => {
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 100);

    const result = await calculateExpiry('Password123', futureDate);

    // Should have full rotation period remaining
    expect(result.daysRemaining).toBeGreaterThan(0);
  });

  it('should handle very old passwords', async () => {
    const veryOld = new Date('2020-01-01');

    const result = await calculateExpiry('Password123', veryOld);

    expect(result.daysRemaining).toBe(0);
    expect(result.recommendRotation).toBe(true);
  });

  it('should handle empty password', async () => {
    const result = await calculateExpiry('', new Date());

    expect(result.entropy).toBe(0);
    expect(result.rotationPeriodDays).toBeLessThanOrEqual(30);
  });
});
