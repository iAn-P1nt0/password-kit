# Contributing to TrustVault Password Utils

Thank you for your interest in contributing to TrustVault Password Utils! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Contribution Guidelines](#contribution-guidelines)
- [Testing Requirements](#testing-requirements)
- [Security Guidelines](#security-guidelines)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of experience level, background, or identity.

### Expected Behavior

- Be respectful and considerate
- Welcome newcomers and help them get started
- Accept constructive criticism gracefully
- Focus on what's best for the project
- Show empathy towards other contributors

### Unacceptable Behavior

- Harassment, trolling, or discriminatory comments
- Personal attacks or insults
- Publishing others' private information
- Other conduct that could reasonably be considered inappropriate

---

## Getting Started

### Prerequisites

- Node.js 20.x or higher
- npm 10.x or higher
- Git
- TypeScript knowledge
- Understanding of cryptographic concepts (recommended)

### Setup

1. **Fork the repository**
   ```bash
   # Click "Fork" on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/TrustVault-password-utils.git
   cd TrustVault-password-utils
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

4. **Run tests to ensure everything works**
   ```bash
   npm test
   ```

---

## Development Workflow

### 1. Development Commands

```bash
# Run tests in watch mode
npm run test:watch

# Type checking
npm run type-check

# Linting
npm run lint

# Build the package
npm run build

# Run all checks
npm run test && npm run type-check && npm run lint
```

### 2. Making Changes

1. **Write code** - Implement your feature or fix
2. **Add tests** - Ensure comprehensive test coverage
3. **Update documentation** - Update README, JSDoc, and CHANGELOG
4. **Run tests** - Verify all tests pass
5. **Commit changes** - Use conventional commit format

### 3. Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): subject

body (optional)

footer (optional)
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation changes
- `test` - Test updates
- `refactor` - Code refactoring
- `perf` - Performance improvements
- `security` - Security fixes
- `chore` - Build/tooling changes

**Examples:**
```bash
git commit -m "feat(generator): add support for custom character sets"
git commit -m "fix(analyzer): correct entropy calculation for edge cases"
git commit -m "docs(readme): add examples for passphrase generation"
git commit -m "security(crypto): fix modulo bias in random generation"
```

---

## Contribution Guidelines

### What to Contribute

**Welcome contributions:**
- ✅ Bug fixes
- ✅ New features (see roadmap in AGENTS.md)
- ✅ Performance improvements
- ✅ Documentation improvements
- ✅ Test coverage improvements
- ✅ Accessibility enhancements
- ✅ TypeScript type improvements

**Please discuss first:**
- ⚠️ Major architectural changes
- ⚠️ Breaking API changes
- ⚠️ New dependencies
- ⚠️ Changes to security-critical code

### Before Starting

1. **Check existing issues** - Someone may already be working on it
2. **Create an issue** - Discuss your idea or proposal
3. **Wait for feedback** - Get maintainer approval before investing time
4. **Review AGENTS.md** - Understand the project roadmap and architecture

---

## Testing Requirements

### Required Tests

All contributions must include appropriate tests:

1. **Unit Tests** - Test individual functions
2. **Integration Tests** - Test feature workflows
3. **Security Tests** - For security-critical features
4. **Edge Case Tests** - Boundary conditions and error handling

### Test Coverage

- **Minimum:** 90% overall coverage
- **Security code:** 100% coverage required
- **New features:** Must include comprehensive tests
- **Bug fixes:** Must include regression tests

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage

# View coverage report
open coverage/index.html
```

### Writing Tests

Example test structure:

```typescript
import { describe, it, expect } from 'vitest';
import { generatePassword } from '../generators/password';

describe('generatePassword', () => {
  describe('security properties', () => {
    it('should use cryptographically secure randomness', () => {
      const samples = Array.from({ length: 1000 }, () =>
        generatePassword({ length: 16 })
      );

      const unique = new Set(samples.map(s => s.password));
      expect(unique.size).toBeGreaterThan(990);
    });
  });

  describe('functional behavior', () => {
    it('should generate password with specified length', () => {
      const result = generatePassword({ length: 20 });
      expect(result.password).toHaveLength(20);
    });
  });

  describe('edge cases', () => {
    it('should handle minimum length', () => {
      const result = generatePassword({ length: 8 });
      expect(result.password).toHaveLength(8);
    });
  });
});
```

---

## Security Guidelines

### Critical Security Rules

**ALWAYS:**
- ✅ Use `crypto.getRandomValues()` for random generation
- ✅ Implement rejection sampling to avoid modulo bias
- ✅ Calculate entropy accurately
- ✅ Validate all inputs
- ✅ Write security tests

**NEVER:**
- ❌ Use `Math.random()` for anything security-related
- ❌ Log, store, or transmit passwords
- ❌ Introduce timing attacks
- ❌ Use predictable patterns
- ❌ Commit secrets or credentials

### Security Review Required

The following changes require security review:

- Cryptographic functions
- Random number generation
- Entropy calculations
- Password/passphrase generation
- Authentication-related code

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities.

Instead:
1. Email security concerns to the maintainers
2. Create a private security advisory on GitHub
3. Wait for response before disclosure

---

## Pull Request Process

### Before Submitting

- [ ] All tests pass
- [ ] Type checking passes
- [ ] Linting passes
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Commits follow conventional format
- [ ] Branch is up to date with main

### Submitting a PR

1. **Push your branch**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create pull request** on GitHub

3. **Fill out PR template** with:
   - Description of changes
   - Related issue number
   - Testing performed
   - Screenshots (if applicable)
   - Breaking changes (if any)

4. **Wait for review** - Maintainers will review your PR

5. **Address feedback** - Make requested changes

6. **Get approval** - At least one maintainer approval required

### PR Title Format

Use conventional commit format:

```
feat(scope): add new feature
fix(scope): resolve bug
docs(scope): update documentation
```

### Review Process

1. **Automated checks** - CI/CD runs tests, linting, type checking
2. **Code review** - Maintainer reviews code quality and design
3. **Security review** - For security-critical changes
4. **Testing verification** - Verify tests are adequate
5. **Approval** - Maintainer approves PR
6. **Merge** - Maintainer merges PR

---

## Coding Standards

### TypeScript Style

**Do:**
```typescript
// ✅ Clear, typed, documented
/**
 * Generates a cryptographically secure password.
 */
export function generatePassword(
  options: PasswordGeneratorOptions
): GeneratedPassword {
  // Implementation
}
```

**Don't:**
```typescript
// ❌ No types, no docs
export function gen(opts: any): any {
  // Implementation
}
```

### Naming Conventions

- **Functions:** `camelCase` (e.g., `generatePassword`)
- **Classes:** `PascalCase` (e.g., `PasswordGenerator`)
- **Interfaces:** `PascalCase` (e.g., `PasswordOptions`)
- **Constants:** `UPPER_SNAKE_CASE` (e.g., `MAX_LENGTH`)
- **Files:** `kebab-case` (e.g., `password-generator.ts`)

### Documentation

**All exported functions must have:**
- JSDoc comments
- `@param` tags for parameters
- `@returns` tag for return value
- `@throws` tag for exceptions
- `@example` with usage example

**Example:**
```typescript
/**
 * Analyzes password strength using multiple factors.
 *
 * @param password - The password to analyze
 * @returns Detailed strength analysis
 * @throws {Error} If password is empty
 *
 * @example
 * ```typescript
 * const result = analyzePasswordStrength("Tr0ub4dor&3");
 * console.log(result.strength); // "strong"
 * ```
 */
export function analyzePasswordStrength(
  password: string
): PasswordStrengthResult {
  // Implementation
}
```

### Code Organization

```typescript
// 1. Imports
import { crypto } from 'node:crypto';
import type { PasswordOptions } from './types';

// 2. Constants
const MAX_LENGTH = 128;

// 3. Types
interface InternalState {
  // ...
}

// 4. Helper functions (private)
function validateLength(length: number): void {
  // ...
}

// 5. Exported functions
export function generatePassword(options: PasswordOptions): string {
  // ...
}
```

---

## Additional Resources

### Documentation

- **README.md** - User documentation
- **AGENTS.md** - Detailed development guide and roadmap
- **CLAUDE.md** - Project overview
- **PUBLISHING.md** - Publishing guidelines

### External References

- [OWASP Guidelines](https://owasp.org/www-project-password-guidelines/)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [TypeScript Documentation](https://www.typescriptlang.org/docs/)
- [Conventional Commits](https://www.conventionalcommits.org/)

---

## Questions?

- **General questions:** Open a GitHub discussion
- **Bug reports:** Create a GitHub issue
- **Feature requests:** Create a GitHub issue with [Feature Request] label
- **Security concerns:** Email maintainers privately

---

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

---

**Thank you for contributing to TrustVault Password Utils! 🙏**
