/**
 * React Hook: usePasswordStrength
 * 
 * Provides real-time password strength analysis with debouncing
 * 
 * @example
 * ```tsx
 * function PasswordInput() {
 *   const [password, setPassword] = useState('');
 *   const { strength, loading } = usePasswordStrength(password, { debounce: 300 });
 * 
 *   return (
 *     <div>
 *       <input 
 *         type="password" 
 *         value={password}
 *         onChange={(e) => setPassword(e.target.value)}
 *       />
 *       {loading ? (
 *         <p>Analyzing...</p>
 *       ) : strength ? (
 *         <div>
 *           <p>Strength: {strength.strength}</p>
 *           <p>Score: {strength.score}/100</p>
 *           <p>Crack time: {strength.crackTime}</p>
 *         </div>
 *       ) : null}
 *     </div>
 *   );
 * }
 * ```
 */

import { useState, useEffect, useRef } from 'react';
import { 
  analyzePasswordStrength, 
  preloadZxcvbn,
  type PasswordStrengthResult 
} from '@trustvault/password-utils';

/**
 * Options for usePasswordStrength hook
 */
export interface UsePasswordStrengthOptions {
  /** Debounce delay in milliseconds (default: 300) */
  debounce?: number;
  /** Enable analysis (default: true) */
  enabled?: boolean;
  /** Preload zxcvbn on mount (default: true) */
  preload?: boolean;
}

/**
 * Result from usePasswordStrength hook
 */
export interface UsePasswordStrengthResult {
  /** Password strength analysis result */
  strength: PasswordStrengthResult | null;
  /** Loading state during analysis */
  loading: boolean;
  /** Error during analysis if any */
  error: Error | null;
}

/**
 * React hook for password strength analysis
 * 
 * Automatically analyzes password strength with configurable debouncing.
 * Lazy-loads zxcvbn library on first use to minimize bundle size.
 * 
 * @param password - Password to analyze
 * @param options - Configuration options
 * @returns Strength analysis state
 * 
 * @example
 * ```tsx
 * function PasswordField() {
 *   const [password, setPassword] = useState('');
 *   const { strength, loading } = usePasswordStrength(password);
 * 
 *   return (
 *     <div>
 *       <input 
 *         type="password"
 *         value={password}
 *         onChange={(e) => setPassword(e.target.value)}
 *       />
 *       {!loading && strength && (
 *         <StrengthMeter score={strength.score} />
 *       )}
 *     </div>
 *   );
 * }
 * ```
 * 
 * @example
 * ```tsx
 * // Custom debounce and disable on demand
 * const { strength, loading } = usePasswordStrength(password, {
 *   debounce: 500,
 *   enabled: isFormActive,
 *   preload: false
 * });
 * ```
 */
export function usePasswordStrength(
  password: string,
  options: UsePasswordStrengthOptions = {}
): UsePasswordStrengthResult {
  const {
    debounce = 300,
    enabled = true,
    preload = true,
  } = options;

  const [strength, setStrength] = useState<PasswordStrengthResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);
  const cancelledRef = useRef(false);

  // Preload zxcvbn on mount
  useEffect(() => {
    if (preload) {
      preloadZxcvbn().catch((err: unknown) => {
        console.warn('Failed to preload zxcvbn:', err);
      });
    }
  }, [preload]);

  useEffect(() => {
    // Reset cancelled flag
    cancelledRef.current = false;

    // Clear strength if password is empty or disabled
    if (!password || !enabled) {
      setStrength(null);
      setLoading(false);
      setError(null);
      return;
    }

    // Clear previous timeout
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }

    setLoading(true);
    setError(null);

    // Debounce analysis
    timeoutRef.current = setTimeout(() => {
      analyzePasswordStrength(password)
        .then((result) => {
          if (!cancelledRef.current) {
            setStrength(result);
            setLoading(false);
          }
        })
        .catch((err: unknown) => {
          if (!cancelledRef.current) {
            setError(err instanceof Error ? err : new Error(String(err)));
            setStrength(null);
            setLoading(false);
          }
        });
    }, debounce);

    // Cleanup
    return () => {
      cancelledRef.current = true;
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
    };
  }, [password, enabled, debounce]);

  return {
    strength,
    loading,
    error,
  };
}
