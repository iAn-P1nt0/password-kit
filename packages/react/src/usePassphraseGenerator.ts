/**
 * React Hook: usePassphraseGenerator
 * 
 * Provides stateful passphrase generation with loading states
 * 
 * @example
 * ```tsx
 * function PassphraseForm() {
 *   const { passphrase, generate, loading } = usePassphraseGenerator({
 *     wordCount: 5,
 *     separator: 'dash'
 *   });
 * 
 *   return (
 *     <div>
 *       <button onClick={() => generate()} disabled={loading}>
 *         Generate Passphrase
 *       </button>
 *       <p>{passphrase}</p>
 *     </div>
 *   );
 * }
 * ```
 */

import { useState, useCallback } from 'react';
import {
  generatePassphrase,
  type PassphraseOptions,
  type GeneratedPassword,
} from '@trustvault/password-utils';

/**
 * Result from usePassphraseGenerator hook
 */
export interface UsePassphraseGeneratorResult {
  /** Currently generated passphrase */
  passphrase: string;
  /** Loading state during generation */
  loading: boolean;
  /** Full result object from last generation */
  result: GeneratedPassword | null;
  /** Generate new passphrase with optional override options */
  generate: (options?: Partial<PassphraseOptions>) => Promise<GeneratedPassword>;
  /** Clear current passphrase */
  clear: () => void;
}

/**
 * React hook for passphrase generation
 * 
 * Manages passphrase generation state including loading indicators.
 * Uses Diceware methodology with EFF wordlist.
 * 
 * @param initialOptions - Default options for passphrase generation
 * @returns Hook state and actions
 * 
 * @example
 * ```tsx
 * const { passphrase, generate, loading } = usePassphraseGenerator({
 *   wordCount: 6,
 *   separator: 'space',
 *   capitalize: 'first',
 *   includeNumbers: true
 * });
 * 
 * // Generate with default options
 * await generate();
 * 
 * // Override options
 * await generate({ wordCount: 8, separator: 'dash' });
 * ```
 */
export function usePassphraseGenerator(
  initialOptions?: Partial<PassphraseOptions>
): UsePassphraseGeneratorResult {
  const [passphrase, setPassphrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<GeneratedPassword | null>(null);

  const generate = useCallback(
    async (
      overrideOptions?: Partial<PassphraseOptions>
    ): Promise<GeneratedPassword> => {
      setLoading(true);
      try {
        const options: PassphraseOptions = {
          wordCount: 4,
          separator: 'dash',
          capitalize: 'none',
          includeNumbers: false,
          ...initialOptions,
          ...overrideOptions,
        };

        const generatedResult = generatePassphrase(options);
        setPassphrase(generatedResult.password);
        setResult(generatedResult);
        return generatedResult;
      } finally {
        setLoading(false);
      }
    },
    [initialOptions]
  );

  const clear = useCallback(() => {
    setPassphrase('');
    setResult(null);
  }, []);

  return {
    passphrase,
    loading,
    result,
    generate,
    clear,
  };
}
