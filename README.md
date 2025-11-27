# password-kit

[![npm version](https://img.shields.io/npm/v/password-kit.svg)](https://www.npmjs.com/package/password-kit)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/iAn-P1nt0/password-kit/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org/)

Cryptographically secure password and passphrase generation utilities with comprehensive strength analysis. Built with TypeScript and leveraging the Web Crypto API for maximum security.

> 🌐 **[View Landing Page](https://ian-p1nt0.github.io/password-kit/)** | 💖 **[Sponsor on GitHub](https://github.com/sponsors/iAn-P1nt0)**

## Features

✅ **Cryptographically Secure** - Uses Web Crypto API with rejection sampling to eliminate modulo bias  
✅ **Password Generation** - Configurable length (8-128 chars) with customizable character sets  
✅ **Passphrase Generation** - Diceware-based with 384-word EFF wordlist subset  
✅ **Breach Checking** - HIBP integration with k-Anonymity protocol (privacy-preserving)  
✅ **Strength Analysis** - Powered by zxcvbn (lazy-loaded) with detailed feedback  
✅ **Argon2id Hashing** - OWASP-recommended password hashing with Web Workers  
✅ **Policy Validation** - NIST 800-63B compliance checking  
✅ **Quick Validation** - Lightweight real-time password checking  
✅ **TypeScript First** - Full type definitions and IntelliSense support  
✅ **Framework Integrations** - React hooks, Web Component, CLI tool  
✅ **Tree Shakeable** - Optimized bundle size with ESM and CommonJS support

## Installation

```bash
npm install password-kit
```

```bash
yarn add password-kit
```

```bash
pnpm add password-kit
```

## Quick Start

### Password Generation

```typescript
import { generatePassword } from 'password-kit';

const result = generatePassword({
  length: 16,
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: true
});

console.log(result.password);  // "Kp9$mNz2@Qw5Xr8T"
console.log(result.strength);  // "very-strong"
console.log(result.entropy);   // 95.2
```

### Passphrase Generation

```typescript
import { generatePassphrase } from 'password-kit';

const result = generatePassphrase({
  wordCount: 5,
  separator: 'dash',
  capitalization: 'first',
  includeNumber: true
});

console.log(result.password);  // "Forest-Mountain-River-Sky-Ocean47"
console.log(result.entropy);   // 67.2
```

### Password Strength Analysis

```typescript
import { analyzePasswordStrength } from 'password-kit';

const analysis = analyzePasswordStrength("password123");

console.log(analysis.score);        // 12
console.log(analysis.strength);     // "weak"
console.log(analysis.crackTime);    // "instant"
console.log(analysis.suggestions);  // ["Add more unique characters", ...]
console.log(analysis.weaknesses);   // ["Common password", "Predictable sequence"]
```

### Real-time Validation

```typescript
import { quickStrengthCheck } from 'password-kit';

const check = quickStrengthCheck(userInput);

console.log(check.feedback);   // "Password is too short"
console.log(check.score);      // 25
console.log(check.strength);   // "weak"
```

## Framework Integrations

### React Hooks

Install the React hooks package:

```bash
npm install password-kit-react
```

```tsx
import { usePasswordGenerator, usePasswordStrength } from 'password-kit-react';

function PasswordForm() {
  const { password, generate, loading } = usePasswordGenerator({ length: 20 });
  const { strength } = usePasswordStrength(password, { debounce: 300 });

  return (
    <div>
      <button onClick={() => generate()} disabled={loading}>
        Generate Password
      </button>
      <input type="text" value={password} readOnly />
      {strength && <StrengthMeter score={strength.score} />}
    </div>
  );
}
```

**Available Hooks:**
- `usePasswordGenerator` - Generate passwords with state management
- `usePasswordStrength` - Real-time strength analysis with debouncing
- `usePassphraseGenerator` - Generate passphrases
- `useBreachCheck` - Check passwords against HIBP database

📖 [Full React Documentation](./packages/react/README.md)

---

### Web Component

Install the Web Component package:

```bash
npm install password-generator-element
```

**Works with any framework or vanilla HTML:**

```html
<script type="module">
  import 'password-generator-element';
</script>

<password-generator 
  length="20"
  include-symbols="true"
  auto-generate="false">
</password-generator>

<script>
  const generator = document.querySelector('password-generator');
  
  generator.addEventListener('password-generated', (e) => {
    console.log('Password:', e.detail.password);
    console.log('Strength:', e.detail.strength);
  });
</script>
```

**Features:**
- ✅ Framework-agnostic (works everywhere)
- ✅ Shadow DOM for style encapsulation
- ✅ Full keyboard accessibility (WCAG 2.1 Level AA)
- ✅ Dark mode support
- ✅ Custom events for integration

📖 [Full Web Component Documentation](./packages/web-component/README.md)

---

### CLI Tool

Install globally or use with npx:

```bash
# Global install
npm install -g password-cli

# Or use with npx (no install required)
npx password-cli generate
```

**Commands:**

```bash
# Generate password
tvpg generate --length 32 --count 5

# Generate passphrase
tvpg passphrase --words 6 --separator dash

# Analyze password strength
tvpg analyze "MyP@ssw0rd123"

# Check for breaches
tvpg breach "password123"

# Quick strength check
tvpg quick "abc123"

# JSON output
tvpg generate --json
```

**Features:**
- ✅ Auto-copy to clipboard (30s timeout)
- ✅ Colorized terminal output
- ✅ JSON output for scripting
- ✅ Batch generation
- ✅ Cross-platform (macOS, Linux, Windows)

📖 [Full CLI Documentation](./packages/cli/README.md)

---

## API Reference

### Password Generation

#### `generatePassword(options?: PasswordGeneratorOptions): GeneratedPassword`

Generates a cryptographically secure password.

**Options:**
```typescript
interface PasswordGeneratorOptions {
  length?: number;              // 8-128 (default: 16)
  includeUppercase?: boolean;   // default: true
  includeLowercase?: boolean;   // default: true
  includeNumbers?: boolean;     // default: true
  includeSymbols?: boolean;     // default: true
  excludeAmbiguous?: boolean;   // Exclude 0, O, l, 1, I (default: false)
  customCharset?: string;       // Custom character set (overrides other options)
}
```

**Returns:**
```typescript
interface GeneratedPassword {
  password: string;
  entropy: number;
  strength: 'weak' | 'medium' | 'strong' | 'very-strong';
}
```

#### `generatePasswords(count: number, options?: PasswordGeneratorOptions): GeneratedPassword[]`

Generate multiple passwords at once (1-100).

#### `generatePronounceablePassword(length?: number): GeneratedPassword`

Generate a memorable password with alternating consonants and vowels.

#### `getDefaultOptions(): PasswordGeneratorOptions`

Returns secure default configuration.

---

### Passphrase Generation

#### `generatePassphrase(options?: PassphraseOptions): GeneratedPassword`

Generates a Diceware-based passphrase.

**Options:**
```typescript
interface PassphraseOptions {
  wordCount?: number;           // 4-8 words (default: 5)
  separator?: 'dash' | 'space' | 'symbol' | 'none';  // default: 'dash'
  capitalization?: 'none' | 'first' | 'all' | 'random';  // default: 'none'
  includeNumber?: boolean;      // default: false
}
```

#### `generateMemorablePassphrase(length?: number): GeneratedPassword`

Pre-configured for maximum memorability.

#### `getDefaultPassphraseOptions(): PassphraseOptions`

Returns secure default configuration.

---

### Strength Analysis

#### `analyzePasswordStrength(password: string): PasswordStrengthResult`

Comprehensive password strength analysis using zxcvbn.

**Returns:**
```typescript
interface PasswordStrengthResult {
  score: number;                // 0-100
  strength: string;             // weak | medium | strong | very-strong
  entropy: number;              // Bits of entropy
  crackTime: string;            // Human-readable estimate
  warning: string | null;       // Primary warning
  suggestions: string[];        // Improvement suggestions
  weaknesses: string[];         // Detected issues
}
```

**Detects:**
- Common passwords and dictionary words
- Keyboard patterns (qwerty, asdf)
- Repeated sequences (aaa, 123)
- Date patterns and years
- Personal information patterns

---

### Quick Validation

#### `quickStrengthCheck(password: string): QuickStrengthResult`

Lightweight real-time validation (no zxcvbn overhead).

**Returns:**
```typescript
interface QuickStrengthResult {
  score: number;                // 0-100
  strength: string;             // weak | medium | strong | very-strong
  feedback: string;             // User-friendly message
  weaknesses: string[];         // Basic issues
}
```

#### `meetsMinimumRequirements(password: string): MinimumRequirementsResult`

Check if password meets baseline requirements.

**Returns:**
```typescript
interface MinimumRequirementsResult {
  meets: boolean;
  missingRequirements: string[];
}
```

---

### Utilities

#### `formatTOTPCode(code: string): string`

Format 6-digit TOTP codes with space separator.

```typescript
formatTOTPCode("123456")  // Returns: "123 456"
```

## Security

### Cryptographic Guarantees

- **Random Generation:** Uses `crypto.getRandomValues()` from Web Crypto API
- **No Bias:** Implements rejection sampling to eliminate modulo bias
- **Entropy Calculation:** Accurate mathematical entropy: log₂(charset_size^length)
- **No Predictable Patterns:** True random generation, not pseudo-random

### Strength Classification

| Strength | Entropy | Use Case |
|----------|---------|----------|
| Weak | < 40 bits | ❌ Not recommended |
| Medium | 40-59 bits | ⚠️ Low-security accounts |
| Strong | 60-79 bits | ✅ Standard accounts |
| Very Strong | ≥ 80 bits | ✅ High-security accounts |

### Best Practices

1. **Use Strong Passwords:** Minimum 16 characters with all character types
2. **Use Passphrases:** For memorability, use 5+ words with separators
3. **Avoid Patterns:** Don't use keyboard patterns, dates, or personal info
4. **Unique Passwords:** Never reuse passwords across services
5. **Regular Updates:** Change passwords periodically for critical accounts

## TypeScript Support

Full TypeScript definitions included. Import types directly:

```typescript
import type {
  PasswordGeneratorOptions,
  GeneratedPassword,
  PassphraseOptions,
  PasswordStrengthResult,
  QuickStrengthResult,
  MinimumRequirementsResult
} from 'password-kit';
```

## Bundle Size

- **Core library:** ~30KB gzipped
- **With zxcvbn:** ~400KB gzipped (lazy loaded)
- **Types:** ~5KB

The library uses tree-shaking, so you only bundle what you import.

## Browser Support

Requires browsers with Web Crypto API support:

- Chrome/Edge 37+
- Firefox 34+
- Safari 11+
- Opera 24+
- Node.js 20+

## Examples

### React Hook Example

```typescript
import { useState, useCallback } from 'react';
import { generatePassword, analyzePasswordStrength } from 'password-kit';

function usePasswordGenerator() {
  const [password, setPassword] = useState('');
  const [analysis, setAnalysis] = useState(null);

  const generate = useCallback(() => {
    const result = generatePassword({ length: 16 });
    setPassword(result.password);
    setAnalysis(analyzePasswordStrength(result.password));
  }, []);

  return { password, analysis, generate };
}
```

### Form Validation Example

```typescript
import { quickStrengthCheck, meetsMinimumRequirements } from 'password-kit';

function validatePassword(password: string): string | null {
  const requirements = meetsMinimumRequirements(password);

  if (!requirements.meets) {
    return requirements.missingRequirements.join(', ');
  }

  const check = quickStrengthCheck(password);

  if (check.strength === 'weak') {
    return 'Password is too weak. ' + check.feedback;
  }

  return null; // Valid
}
```

### Batch Generation Example

```typescript
import { generatePasswords } from 'password-kit';

// Generate 10 passwords for testing
const passwords = generatePasswords(10, {
  length: 20,
  includeSymbols: true
});

passwords.forEach(p => {
  console.log(`${p.password} (${p.strength}, ${p.entropy.toFixed(1)} bits)`);
});
```

## Testing

The library includes comprehensive test coverage:

```bash
npm test                # Run tests
npm run test:watch      # Watch mode
npm run test:coverage   # Coverage report
```

**Test categories:**
- Security tests (randomness quality, bias detection)
- Functional tests (feature correctness)
- Integration tests (end-to-end workflows)
- Edge case tests (boundary conditions)

## Development

```bash
# Install dependencies
npm install

# Build the library
npm run build

# Run tests
npm test

# Type checking
npm run type-check

# Linting
npm run lint
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Security First** - Never compromise cryptographic integrity
2. **Tests Required** - All new features must include tests
3. **Type Safety** - Full TypeScript coverage required
4. **Documentation** - Update README and JSDoc comments
5. **No Breaking Changes** - Follow semantic versioning

See [AGENTS.md](https://github.com/iAn-P1nt0/password-kit/blob/main/AGENTS.md) for detailed development guidelines.

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Credits

- **zxcvbn** - Password strength estimation by Dropbox
- **@noble/hashes** - Cryptographic primitives by Paul Miller
- **EFF Wordlist** - Diceware wordlist by Electronic Frontier Foundation

## Support

- **Landing Page:** [https://ian-p1nt0.github.io/password-kit/](https://ian-p1nt0.github.io/password-kit/)
- **Issues:** [GitHub Issues](https://github.com/iAn-P1nt0/password-kit/issues)
- **Repository:** [GitHub](https://github.com/iAn-P1nt0/password-kit)
- **NPM:** [password-kit](https://www.npmjs.com/package/password-kit)
- **Sponsor:** [GitHub Sponsors](https://github.com/sponsors/iAn-P1nt0) 💖

---

**Made with ❤️ by TrustVault Team**
