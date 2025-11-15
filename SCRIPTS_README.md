# Build, Test, and Coverage Scripts

This directory contains automated scripts for building, testing, and generating coverage reports for all packages in the TrustVault Password Utils monorepo.

## Scripts Overview

### 🔨 build-all.sh
Builds all packages in the monorepo.

**Usage:**
```bash
./build-all.sh
# OR
npm run build:all
```

**Features:**
- Builds main package
- Builds React hooks package
- Builds CLI package
- Builds Web Component package
- Color-coded output
- Error tracking and reporting
- Build status summary

**Output:**
- Success/failure for each package
- Build logs saved to `/tmp/*-build.log`
- Summary of successful and failed builds

---

### 🧪 test-all.sh
Runs tests for all packages with timeout protection.

**Usage:**
```bash
./test-all.sh
# OR
npm run test:all
```

**Features:**
- Tests each package individually
- 120-second timeout for main and React packages
- 60-second timeout for CLI and Web Component
- Prevents infinite hangs
- Test status tracking
- Comprehensive summary

**Output:**
- Test results for each package
- Test logs saved to `/tmp/*-test.log`
- Summary of passed/failed/timed-out tests

---

### 📊 generate-coverage.sh
Generates comprehensive test coverage reports.

**Usage:**
```bash
./generate-coverage.sh
# OR
npm run coverage:all
```

**Features:**
- Generates coverage for all packages
- Multiple report formats (HTML, JSON, text)
- 180-300 second timeouts for slow tests
- Creates combined summary document
- Handles missing test files gracefully

**Output:**
- `coverage-reports/` directory with all reports
- `coverage-reports/COVERAGE_SUMMARY.md` - Overview and instructions
- `coverage-reports/*-coverage/` - HTML reports for each package
- `coverage-reports/*-coverage.txt` - Text summaries

---

## Quick Start

### Build Everything
```bash
npm run build:all
```

### Test Everything
```bash
npm run test:all
```

### Generate Coverage
```bash
npm run coverage:all
```

### View Coverage Reports
```bash
# Open HTML reports (macOS)
open coverage-reports/main-coverage/index.html
open coverage-reports/react-coverage/index.html

# Open HTML reports (Linux)
xdg-open coverage-reports/main-coverage/index.html

# View text summaries
cat coverage-reports/*-coverage.txt
```

---

## Package Structure

```
TrustVault-password-utils/
├── build-all.sh              # Build all packages
├── test-all.sh               # Test all packages
├── generate-coverage.sh      # Generate coverage reports
├── package.json              # Root package with npm scripts
├── packages/
│   ├── react/                # React hooks package
│   ├── cli/                  # CLI tool package
│   └── web-component/        # Web Component package
└── coverage-reports/         # Generated coverage (gitignored)
    ├── COVERAGE_SUMMARY.md
    ├── main-coverage/
    ├── react-coverage/
    ├── cli-coverage/
    └── webcomponent-coverage/
```

---

## NPM Scripts

All scripts are available as npm commands in the root `package.json`:

| Command | Description |
|---------|-------------|
| `npm run build` | Build main package only |
| `npm run build:all` | Build all packages |
| `npm test` | Test main package only |
| `npm run test:all` | Test all packages |
| `npm run test:coverage` | Coverage for main package |
| `npm run coverage:all` | Coverage for all packages |

---

## Script Outputs

### Build Script Output
```
==================================================
Building all TrustVault Password Utils packages
==================================================

==> Building main package (@ian-p1nt0/password-utils)...
✓ Main package built successfully

==> Building React hooks package (@trustvault/password-utils-react)...
✓ React package built successfully

...

✓ All packages built successfully!
```

### Test Script Output
```
==================================================
Testing all TrustVault Password Utils packages
==================================================

==> Testing main package...
✓ Main package tests passed

...

Tests passed: 2/4
```

### Coverage Script Output
```
==================================================
Generating Test Coverage Reports
==================================================

==> Generating coverage for main package...
✓ Main package coverage generated

...

✓ Coverage reports saved to: coverage-reports/
```

---

## Troubleshooting

### Scripts Won't Execute
```bash
# Make scripts executable
chmod +x build-all.sh test-all.sh generate-coverage.sh
```

### Tests Timeout
The scripts have built-in timeout protection:
- Main package tests: 120 seconds
- React package tests: 120 seconds
- CLI package tests: 60 seconds
- Web Component tests: 60 seconds
- Coverage generation: 180-300 seconds

If tests consistently timeout, check for:
- Network-dependent tests (breach checker)
- Infinite loops
- Missing test mocks

### Coverage Reports Missing
Some packages may not have tests yet:
- Check `coverage-reports/COVERAGE_SUMMARY.md` for status
- CLI and Web Component packages need test files added

### Build Failures
Check individual build logs:
```bash
cat /tmp/main-build.log
cat /tmp/react-build.log
cat /tmp/cli-build.log
cat /tmp/webcomponent-build.log
```

---

## CI/CD Integration

These scripts are designed for use in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
steps:
  - name: Install dependencies
    run: npm install
  
  - name: Build all packages
    run: npm run build:all
  
  - name: Test all packages
    run: npm run test:all
  
  - name: Generate coverage
    run: npm run coverage:all
  
  - name: Upload coverage
    uses: codecov/codecov-action@v3
    with:
      directory: ./coverage-reports
```

---

## Development Workflow

### Adding New Tests
1. Add test files to package `tests/` or `src/__tests__/` directories
2. Run `npm run test:all` to verify
3. Run `npm run coverage:all` to check coverage

### Before Committing
```bash
# Verify everything works
npm run build:all && npm run test:all
```

### Before Releasing
```bash
# Full validation
npm run build:all
npm run test:all
npm run coverage:all
# Review coverage reports
```

---

## Requirements

- **Node.js:** ≥20.0.0
- **npm:** ≥10.0.0
- **Bash:** For script execution (built-in on macOS/Linux, WSL on Windows)

---

## Support

For issues with these scripts:
1. Check this README
2. Review `BUILD_TEST_COVERAGE_REPORT.md`
3. Check individual package `package.json` for test configurations
4. Open an issue on GitHub

---

**Last Updated:** November 15, 2025
**Version:** 1.0.0
