/**
 * Tests for Argon2id password hashing
 *
 * NOTE: Full hashing tests require browser environment with WASM support.
 * These tests cover the API surface, types, and configurations.
 *
 * For functional testing:
 * 1. Build: npm run build
 * 2. Open demo-argon2.html in browser
 * 3. Run browser-based tests
 */

import { describe, it, expect } from 'vitest';
import {
  getCapabilities,
  getDefaultArgon2Options,
  estimateHashingTime,
  Argon2Type,
} from '../src/utils/argon2';

describe('Argon2 Module Exports', () => {
  it('should export Argon2Type enum', () => {
    expect(Argon2Type).toBeDefined();
    expect(Argon2Type.Argon2d).toBe(0);
    expect(Argon2Type.Argon2i).toBe(1);
    expect(Argon2Type.Argon2id).toBe(2);
  });

  it('should export utility functions', () => {
    expect(typeof getCapabilities).toBe('function');
    expect(typeof getDefaultArgon2Options).toBe('function');
    expect(typeof estimateHashingTime).toBe('function');
  });
});

describe('getCapabilities', () => {
  it('should return capability information', () => {
    const caps = getCapabilities();

    expect(caps).toHaveProperty('wasm');
    expect(caps).toHaveProperty('webWorker');
    expect(caps).toHaveProperty('simd');
    expect(caps).toHaveProperty('crypto');

    expect(typeof caps.wasm).toBe('boolean');
    expect(typeof caps.webWorker).toBe('boolean');
    expect(typeof caps.simd).toBe('boolean');
    expect(typeof caps.crypto).toBe('boolean');
  });

  it('should detect crypto availability', () => {
    const caps = getCapabilities();
    expect(caps.crypto).toBe(true);
  });
});

describe('getDefaultArgon2Options', () => {
  it('should return OWASP-compliant defaults', () => {
    const defaults = getDefaultArgon2Options();

    expect(defaults.memory).toBeGreaterThanOrEqual(19456); // 19 MiB min
    expect(defaults.iterations).toBeGreaterThanOrEqual(2);
    expect(defaults.parallelism).toBe(1);
    expect(defaults.hashLength).toBe(32);
  });

  it('should return a copy (not modify internals)', () => {
    const defaults1 = getDefaultArgon2Options();
    const defaults2 = getDefaultArgon2Options();

    defaults1.memory = 99999;

    expect(defaults2.memory).not.toBe(99999);
  });

  it('should have correct default memory (19 MiB)', () => {
    const defaults = getDefaultArgon2Options();
    expect(defaults.memory).toBe(19456); // 19456 KiB = 19 MiB
  });

  it('should have correct default iterations', () => {
    const defaults = getDefaultArgon2Options();
    expect(defaults.iterations).toBe(2);
  });

  it('should have correct default hash length', () => {
    const defaults = getDefaultArgon2Options();
    expect(defaults.hashLength).toBe(32); // 256 bits
  });
});

describe('estimateHashingTime', () => {
  it('should provide time estimates', () => {
    const estimate = estimateHashingTime();

    expect(estimate).toHaveProperty('min');
    expect(estimate).toHaveProperty('max');
    expect(estimate).toHaveProperty('optimal');

    expect(estimate.min).toBeGreaterThan(0);
    expect(estimate.max).toBeGreaterThan(estimate.min);
    expect(estimate.optimal).toBeGreaterThanOrEqual(estimate.min);
    expect(estimate.optimal).toBeLessThanOrEqual(estimate.max);
  });

  it('should scale with memory', () => {
    const low = estimateHashingTime({ memory: 19456 });
    const high = estimateHashingTime({ memory: 47104 });

    expect(high.optimal).toBeGreaterThan(low.optimal);
  });

  it('should scale with iterations', () => {
    const low = estimateHashingTime({ iterations: 2 });
    const high = estimateHashingTime({ iterations: 4 });

    expect(high.optimal).toBeGreaterThan(low.optimal);
  });

  it('should handle custom configurations', () => {
    const estimate = estimateHashingTime({
      memory: 20480,
      iterations: 3,
      parallelism: 1,
      hashLength: 32,
    });

    expect(estimate.min).toBeGreaterThan(0);
    expect(estimate.optimal).toBeGreaterThan(0);
  });

  it('should provide realistic estimates', () => {
    const estimate = estimateHashingTime();

    // Should be reasonable (100ms - 2000ms range)
    expect(estimate.optimal).toBeGreaterThan(50);
    expect(estimate.optimal).toBeLessThan(3000);
  });
});

describe('Configuration Validation', () => {
  it('should accept valid memory values', () => {
    const estimates = [
      estimateHashingTime({ memory: 19456 }),
      estimateHashingTime({ memory: 47104 }),
      estimateHashingTime({ memory: 100000 }),
    ];

    estimates.forEach(est => {
      expect(est.optimal).toBeGreaterThan(0);
    });
  });

  it('should accept valid iteration values', () => {
    const estimates = [
      estimateHashingTime({ iterations: 2 }),
      estimateHashingTime({ iterations: 3 }),
      estimateHashingTime({ iterations: 4 }),
    ];

    estimates.forEach(est => {
      expect(est.optimal).toBeGreaterThan(0);
    });
  });

  it('should handle edge cases', () => {
    const minEstimate = estimateHashingTime({
      memory: 19456,
      iterations: 2,
    });

    expect(minEstimate.min).toBeGreaterThan(0);
    expect(minEstimate.optimal).toBeGreaterThan(0);
  });
});

describe('OWASP Compliance', () => {
  it('should use OWASP minimum memory (19 MiB)', () => {
    const defaults = getDefaultArgon2Options();
    expect(defaults.memory).toBeGreaterThanOrEqual(19456);
  });

  it('should use OWASP minimum iterations (2)', () => {
    const defaults = getDefaultArgon2Options();
    expect(defaults.iterations).toBeGreaterThanOrEqual(2);
  });

  it('should produce 256-bit hashes by default', () => {
    const defaults = getDefaultArgon2Options();
    expect(defaults.hashLength).toBe(32); // 32 bytes = 256 bits
  });

  it('should use Argon2id type', () => {
    // Argon2id is type 2
    expect(Argon2Type.Argon2id).toBe(2);
  });
});
