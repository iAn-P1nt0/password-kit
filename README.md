# @trustvault/password-utils

> Cryptographically secure password and passphrase generation utilities with comprehensive strength analysis

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)

## 🎯 Features

- 🔐 **Cryptographically Secure** - Uses Web Crypto API (`crypto.getRandomValues()`)
- 🎲 **Multiple Generation Methods**
  - Strong random passwords with customizable character sets
  - Diceware passphrases for memorable security
  - Pronounceable passwords for easier typing
- 📊 **Comprehensive Strength Analysis** - Powered by zxcvbn
- ⚡ **Real-time Feedback** - Lightweight quick-check for instant UI feedback
- 🎯 **Minimal Dependencies** - Only `@noble/hashes` and `zxcvbn`
- 📦 **Dual Format** - ESM and CommonJS support
- 🔒 **TypeScript First** - Full type definitions included

## 📦 Installation

```bash
npm install @trustvault/password-utils
```

## 🚀 Quick Start

### Generate a Strong Password

```typescript
import { generatePassword, getDefaultOptions } from '@trustvault/password-utils';

const result = generatePassword(getDefaultOptions());
console.log(result.password);  // "aB3$fG9@kL2#pQ5!"
console.log(result.strength);  // "very-strong"
console.log(result.entropy);   // 95.2 bits
```

### Generate a Memorable Passphrase

```typescript
import { generatePassphrase } from '@trustvault/password-utils';

const passphrase = generatePassphrase({
  wordCount: 5,
  separator: 'dash',
  capitalize: 'first',
  includeNumbers: true
});

console.log(passphrase.password);  // "Correct-horse-battery-staple-42"
console.log(passphrase.entropy);   // 43.5 bits
```

### Analyze Password Strength

```typescript
import { analyzePasswordStrength } from '@trustvault/password-utils';

const analysis = analyzePasswordStrength('MyP@ssw0rd123');
console.log(analysis.strength);      // "medium"
console.log(analysis.score);         // 55/100
console.log(analysis.crackTime);     // "3 hours"
console.log(analysis.weaknesses);    // ["Contains year pattern"]
```

## 📚 API Reference

### Password Generation

#### `generatePassword(options)`

Generate a cryptographically secure random password.

```typescript
const password = generatePassword({
  length: 16,              // 8-128 characters
  includeUppercase: true,  // A-Z
  includeLowercase: true,  // a-z
  includeNumbers: true,    // 0-9
  includeSymbols: true,    // !@#$%^&*...
  excludeAmbiguous: false  // Exclude 0, O, l, 1, I
});
```

**Returns:** `GeneratedPassword`
- `password: string` - The generated password
- `entropy: number` - Bits of entropy
- `strength: 'weak' | 'medium' | 'strong' | 'very-strong'`

#### `generatePassphrase(options)`

Generate a diceware-style memorable passphrase.

```typescript
const passphrase = generatePassphrase({
  wordCount: 5,          // 4-8 words
  separator: 'dash',     // 'dash' | 'space' | 'symbol' | 'none'
  capitalize: 'first',   // 'none' | 'first' | 'all' | 'random'
  includeNumbers: true
});
```

#### `generatePronounceablePassword(length)`

Generate a password using consonant-vowel patterns.

```typescript
const password = generatePronounceablePassword(16);
console.log(password.password);  // "VaTo3MiLe5NaPu"
```

### Strength Analysis

#### `analyzePasswordStrength(password)`

Full strength analysis using zxcvbn.

```typescript
const analysis = analyzePasswordStrength('MyPassword123');
// Returns: PasswordStrengthResult
// {
//   score: 55,
//   strength: "medium",
//   entropy: 52.4,
//   crackTime: "3 hours",
//   crackTimeSeconds: 10800,
//   feedback: {
//     warning: "This is similar to a commonly used password",
//     suggestions: ["Add more words", "Avoid dates"]
//   },
//   weaknesses: ["Contains year pattern"]
// }
```

#### `quickStrengthCheck(password)`

Fast strength check for real-time UI feedback (no zxcvbn).

```typescript
const { strength, score } = quickStrengthCheck('abc123');
// Returns: { strength: 'weak', score: 20 }
```

#### `meetsMinimumRequirements(password)`

Validate basic password requirements.

```typescript
const { meets, missing } = meetsMinimumRequirements('abc123');
// Returns: {
//   meets: false,
//   missing: ["At least 8 characters", "One uppercase letter"]
// }
```

### Utilities

#### `formatTOTPCode(code)`

Format a 6-digit TOTP code with spacing.

```typescript
formatTOTPCode('123456')  // "123 456"
```

## 🔒 Security

### Cryptographic Randomness

All password generation uses the Web Crypto API which provides:
- True randomness from OS CSPRNG
- No predictable patterns
- Suitable for security-critical applications

### Entropy Levels

| Level | Bits | Security |
|-------|------|----------|
| **Weak** | < 40 | Crackable with modest resources |
| **Medium** | 40-59 | Resistant to online attacks |
| **Strong** | 60-79 | Resistant to offline attacks |
| **Very Strong** | ≥ 80 | Resistant to advanced attacks |

### Character Diversity

The generator ensures:
- At least one character from each selected set
- Uniform distribution using rejection sampling
- No modulo bias in random number generation

## 💡 Real-time UI Integration

For password input with instant feedback:

```typescript
import { quickStrengthCheck, meetsMinimumRequirements } from '@trustvault/password-utils';

function PasswordInput() {
  const handleChange = (value: string) => {
    // Fast check for visual feedback (< 1ms)
    const { strength, score } = quickStrengthCheck(value);
    updateStrengthBar(strength, score);
    
    // Validate requirements
    const { meets, missing } = meetsMinimumRequirements(value);
    updateRequirementsList(missing);
  };
}
```

For detailed analysis on blur/submit:

```typescript
import { analyzePasswordStrength } from '@trustvault/password-utils';

const handleBlur = () => {
  const analysis = analyzePasswordStrength(password);
  if (analysis.strength === 'weak') {
    showWarning(analysis.feedback.warning);
    showSuggestions(analysis.feedback.suggestions);
  }
};
```

## 🌐 Browser Compatibility

Requires Web Crypto API support:
- Chrome/Edge 37+
- Firefox 34+
- Safari 11+
- Node.js 15+ (with `crypto` global)

## 📘 TypeScript

Full TypeScript support with comprehensive type definitions:

```typescript
import type {
  PasswordGeneratorOptions,
  PassphraseOptions,
  GeneratedPassword,
  PasswordStrengthResult,
  QuickStrengthResult,
  MinimumRequirementsResult
} from '@trustvault/password-utils';
```

## 🤝 Contributing

Contributions welcome! Please read our [Contributing Guide](CONTRIBUTING.md) first.

## 📄 License

Apache-2.0 - see [LICENSE](LICENSE) file for details.

## 🙏 Credits

- Strength analysis: [zxcvbn](https://github.com/dropbox/zxcvbn)
- Cryptography: [@noble/hashes](https://github.com/paulmillr/noble-hashes)
- Wordlist inspired by: [EFF's Diceware List](https://www.eff.org/dice)

---

**Developed by TrustVault** | [GitHub](https://github.com/indi-gamification-initiative/TrustVault-password-utils) | [Issues](https://github.com/indi-gamification-initiative/TrustVault-password-utils/issues)
