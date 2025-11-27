# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-01-12

### Changed
- Updated repository URLs from `indi-gamification-initiative` to `iAn-P1nt0`
- Updated all documentation links to reflect new GitHub username
- Updated package.json repository, bugs, and homepage URLs

## [1.0.0] - 2025-01-12

### Added
- Initial release of password-kit
- Cryptographically secure password generation with Web Crypto API
- Configurable password options (length, character sets, ambiguous character exclusion)
- Batch password generation (1-100 passwords)
- Pronounceable password generation (consonant-vowel patterns)
- Diceware-based passphrase generation with 384-word EFF subset
- Passphrase customization (word count, separators, capitalization, numbers)
- Comprehensive password strength analysis powered by zxcvbn
- Pattern detection (dictionary words, keyboard patterns, sequences, dates)
- Entropy calculation and crack time estimation
- Detailed feedback and improvement suggestions
- Lightweight quick strength checking for real-time validation
- Minimum requirements validation
- TOTP code formatting utility
- Full TypeScript support with complete type definitions
- Dual module format (CommonJS + ESM)
- Tree-shakeable exports for optimized bundle size
- Rejection sampling to eliminate modulo bias
- Comprehensive test coverage (security, functional, integration)
- OWASP compliance validation

### Security
- Uses crypto.getRandomValues() for cryptographically secure randomness
- Implements rejection sampling to prevent modulo bias
- Zero-knowledge architecture (no password storage or logging)
- Constant-time operations where applicable
- No predictable patterns in generation

### Documentation
- Comprehensive README with API reference and examples
- AGENTS.md with detailed development guidelines and roadmap
- CLAUDE.md with project overview and feature descriptions
- Full JSDoc comments in source code
- TypeScript type definitions

## [Unreleased]

### Planned for v1.1.0
- Password history checking with timing attack prevention
- Breach database integration (HIBP API with k-anonymity)
- Secure password hashing utilities (Argon2id/scrypt)

### Planned for v1.2.0
- Custom dictionary support for passphrases
- Password policy engine with customizable rules
- Multi-language character set support (CJK, Cyrillic, Arabic)

### Planned for v1.3.0
- Password expiry calculation and renewal recommendations
- Machine learning-based pattern detection
- Enhanced accessibility features for screen readers

### Planned for v1.4.0
- React/Vue/Angular hooks (password-kit-react)
- Web Component (<password-generator>)
- CLI tool (password-cli)

---

[1.0.0]: https://github.com/iAn-P1nt0/password-kit/releases/tag/v1.0.0
