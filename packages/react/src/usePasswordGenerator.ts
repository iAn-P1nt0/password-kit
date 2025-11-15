/**
 * React Hook: usePasswordGenerator
 * 
 * Provides stateful password generation with loading states
 * 
 * @example
 * ```tsx
 * function PasswordForm() {
 *   const { password, generate, loading } = usePasswordGenerator({
 *     length: 16,
 *     includeSymbols: true
 *   });
 * 
 *   return (
 *     <div>
 *       <button onClick={() => generate()} disabled={loading}>
 *         {loading ? 'Generating...' : 'Generate Password'}
 *       </button>
 *       <input type="text" value={password} readOnly />
 *     </div>
 *   );
 * }
 * ```
 */

import { useState, useCallback } from 'react';
import {
  generatePassword,
  type PasswordGeneratorOptions,
  type GeneratedPassword,
} from '@trustvault/password-utils';

/**
 * Result from usePasswordGenerator hook
 */
export interface UsePasswordGeneratorResult {
  /** Currently generated password */
  password: string;
  /** Loading state during generation */
  loading: boolean;
  /** Full result object from last generation */
  result: GeneratedPassword | null;
  /** Generate new password with optional override options */
  generate: (options?: Partial<PasswordGeneratorOptions>) => Promise<GeneratedPassword>;
  /** Clear current password */
  clear: () => void;
}

/**
 * React hook for password generation
 * 
 * Manages password generation state including loading indicators
 * and error handling. Automatically debounces rapid generation calls.
 * 
 * @param initialOptions - Default options for password generation
 * @returns Hook state and actions
 * 
 * @example
 * ```tsx
 * const { password, generate, loading, clear } = usePasswordGenerator({
 *   length: 20,
 *   includeSymbols: true,
 *   includeNumbers: true
 * });
 * 
 * // Generate with default options
 * await generate();
 * 
 * // Override specific options
 * await generate({ length: 32 });
 * 
 * // Clear password
 * clear();
 * ```
 */
export function usePasswordGenerator(
  initialOptions?: Partial<PasswordGeneratorOptions>
): UsePasswordGeneratorResult {
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<GeneratedPassword | null>(null);

  const generate = useCallback(
    async (
      overrideOptions?: Partial<PasswordGeneratorOptions>
    ): Promise<GeneratedPassword> => {
      setLoading(true);
      try {
        const options: PasswordGeneratorOptions = {
          length: 16,
          includeUppercase: true,
          includeLowercase: true,
          includeNumbers: true,
          includeSymbols: true,
          excludeAmbiguous: false,
          ...initialOptions,
          ...overrideOptions,
        };

        const generatedResult = generatePassword(options);
        setPassword(generatedResult.password);
        setResult(generatedResult);
        return generatedResult;
      } finally {
        setLoading(false);
      }
    },
    [initialOptions]
  );

  const clear = useCallback(() => {
    setPassword('');
    setResult(null);
  }, []);

  return {
    password,
    loading,
    result,
    generate,
    clear,
  };
}
