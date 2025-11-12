/**
 * Utility functions for password management
 */

/**
 * Format a TOTP code with a space in the middle for readability
 * 
 * @param code - TOTP code to format (typically 6 digits)
 * @returns Formatted code with space separator
 * 
 * @example
 * ```typescript
 * const formatted = formatTOTPCode('123456');
 * console.log(formatted); // "123 456"
 * ```
 */
export function formatTOTPCode(code: string): string {
  if (code.length === 6) {
    return `${code.substring(0, 3)} ${code.substring(3)}`;
  }
  return code;
}
