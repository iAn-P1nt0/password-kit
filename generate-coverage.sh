#!/bin/bash

# Generate Test Coverage Report
# This script generates comprehensive coverage reports for all packages

set -e

echo "=================================================="
echo "Generating Test Coverage Reports"
echo "=================================================="
echo ""

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${BLUE}==>${NC} ${1}"
}

print_success() {
    echo -e "${GREEN}✓${NC} ${1}"
}

print_error() {
    echo -e "${RED}✗${NC} ${1}"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} ${1}"
}

# Create coverage directory
COVERAGE_DIR="coverage-reports"
mkdir -p "$COVERAGE_DIR"

# Track coverage status
SUCCESSFUL_COVERAGE=""
FAILED_COVERAGE=""

# Main package coverage with timeout
print_step "Generating coverage for main package..."
# Increase test timeout to handle slow breach checker tests
export VITEST_TEST_TIMEOUT=180000
if timeout 300 npm run test:coverage -- --reporter=verbose --testTimeout=180000 2>&1 | tee "$COVERAGE_DIR/main-coverage.txt"; then
    if [ -d "coverage" ]; then
        cp -r coverage "$COVERAGE_DIR/main-coverage"
        print_success "Main package coverage generated"
        SUCCESSFUL_COVERAGE="${SUCCESSFUL_COVERAGE}\n  - Main package: ${COVERAGE_DIR}/main-coverage/"
    else
        print_warning "Main package coverage completed but no coverage directory found"
    fi
else
    TEST_EXIT=$?
    if [ $TEST_EXIT -eq 124 ]; then
        print_warning "Main package coverage timed out after 300 seconds"
        FAILED_COVERAGE="${FAILED_COVERAGE}\n  - Main package (timeout)"
    else
        print_error "Main package coverage failed"
        FAILED_COVERAGE="${FAILED_COVERAGE}\n  - Main package"
    fi
fi
unset VITEST_TEST_TIMEOUT
echo ""

# React package coverage
print_step "Generating coverage for React hooks package..."
cd packages/react
if timeout 180 npm run test:coverage -- --reporter=verbose 2>&1 | tee "../../$COVERAGE_DIR/react-coverage.txt"; then
    if [ -d "coverage" ]; then
        cp -r coverage "../../$COVERAGE_DIR/react-coverage"
        print_success "React package coverage generated"
        SUCCESSFUL_COVERAGE="${SUCCESSFUL_COVERAGE}\n  - React hooks package: ${COVERAGE_DIR}/react-coverage/"
    else
        print_warning "React package coverage completed but no coverage directory found"
    fi
else
    TEST_EXIT=$?
    if [ $TEST_EXIT -eq 124 ]; then
        print_warning "React package coverage timed out after 180 seconds"
        FAILED_COVERAGE="${FAILED_COVERAGE}\n  - React hooks package (timeout)"
    else
        print_error "React package coverage failed"
        FAILED_COVERAGE="${FAILED_COVERAGE}\n  - React hooks package"
    fi
fi
cd ../..
echo ""

# CLI package coverage
print_step "Checking CLI package for coverage support..."
cd packages/cli
if grep -q "test:coverage" package.json; then
    if timeout 120 npm run test:coverage -- --reporter=verbose 2>&1 | tee "../../$COVERAGE_DIR/cli-coverage.txt"; then
        if [ -d "coverage" ]; then
            cp -r coverage "../../$COVERAGE_DIR/cli-coverage"
            print_success "CLI package coverage generated"
            SUCCESSFUL_COVERAGE="${SUCCESSFUL_COVERAGE}\n  - CLI package: ${COVERAGE_DIR}/cli-coverage/"
        else
            print_warning "CLI package coverage completed but no coverage directory found"
        fi
    else
        print_warning "CLI package coverage failed or has no tests"
        FAILED_COVERAGE="${FAILED_COVERAGE}\n  - CLI package (no coverage)"
    fi
else
    print_warning "CLI package does not have coverage script"
    FAILED_COVERAGE="${FAILED_COVERAGE}\n  - CLI package (no coverage script)"
fi
cd ../..
echo ""

# Web Component package coverage
print_step "Checking Web Component package for coverage support..."
cd packages/web-component
if grep -q "test:coverage" package.json; then
    if timeout 120 npm run test:coverage -- --reporter=verbose 2>&1 | tee "../../$COVERAGE_DIR/webcomponent-coverage.txt"; then
        if [ -d "coverage" ]; then
            cp -r coverage "../../$COVERAGE_DIR/webcomponent-coverage"
            print_success "Web Component package coverage generated"
            SUCCESSFUL_COVERAGE="${SUCCESSFUL_COVERAGE}\n  - Web Component package: ${COVERAGE_DIR}/webcomponent-coverage/"
        else
            print_warning "Web Component package coverage completed but no coverage directory found"
        fi
    else
        print_warning "Web Component package coverage failed or has no tests"
        FAILED_COVERAGE="${FAILED_COVERAGE}\n  - Web Component package (no coverage)"
    fi
else
    print_warning "Web Component package does not have coverage script"
    FAILED_COVERAGE="${FAILED_COVERAGE}\n  - Web Component package (no coverage script)"
fi
cd ../..
echo ""

# Generate combined report
print_step "Creating combined coverage summary..."
cat > "$COVERAGE_DIR/COVERAGE_SUMMARY.md" << 'EOF'
# Test Coverage Report

This directory contains comprehensive test coverage reports for all packages in the TrustVault Password Utils monorepo.

## Generated Reports

EOF

if [ -n "$SUCCESSFUL_COVERAGE" ]; then
    echo "### Successfully Generated Coverage Reports" >> "$COVERAGE_DIR/COVERAGE_SUMMARY.md"
    echo "" >> "$COVERAGE_DIR/COVERAGE_SUMMARY.md"
    echo -e "$SUCCESSFUL_COVERAGE" | sed 's/\\n/\n/g' >> "$COVERAGE_DIR/COVERAGE_SUMMARY.md"
    echo "" >> "$COVERAGE_DIR/COVERAGE_SUMMARY.md"
fi

if [ -n "$FAILED_COVERAGE" ]; then
    echo "### Failed or Missing Coverage Reports" >> "$COVERAGE_DIR/COVERAGE_SUMMARY.md"
    echo "" >> "$COVERAGE_DIR/COVERAGE_SUMMARY.md"
    echo -e "$FAILED_COVERAGE" | sed 's/\\n/\n/g' >> "$COVERAGE_DIR/COVERAGE_SUMMARY.md"
    echo "" >> "$COVERAGE_DIR/COVERAGE_SUMMARY.md"
fi

cat >> "$COVERAGE_DIR/COVERAGE_SUMMARY.md" << 'EOF'

## Report Formats

Each package has coverage reports in multiple formats:

1. **HTML Reports**: Open `index.html` in each coverage directory to view interactive reports
2. **Text Reports**: View `*.txt` files for console output with coverage percentages
3. **JSON Reports**: Coverage data in JSON format for programmatic access

## How to View

### HTML Reports (Recommended)

```bash
# Open main package coverage
open coverage-reports/main-coverage/index.html

# Open React package coverage
open coverage-reports/react-coverage/index.html
```

### Command Line

```bash
# View text summary
cat coverage-reports/main-coverage.txt

# View all summaries
cat coverage-reports/*-coverage.txt
```

## Coverage Metrics

The coverage reports include:

- **Statement Coverage**: Percentage of executable statements executed
- **Branch Coverage**: Percentage of conditional branches tested
- **Function Coverage**: Percentage of functions called
- **Line Coverage**: Percentage of source lines executed

## Minimum Coverage Targets

- Main Package: 80%+ recommended
- React Hooks: 70%+ recommended
- CLI Package: 60%+ (many features require interactive testing)
- Web Component: 70%+ recommended

## Continuous Improvement

To improve coverage:

1. Identify uncovered code in HTML reports (highlighted in red)
2. Add tests for critical paths first
3. Focus on edge cases and error handling
4. Ensure all public APIs are tested

## Generated

$(date)
EOF

print_success "Combined coverage summary created"
echo ""

# Print final summary
echo "=================================================="
echo "Coverage Generation Summary"
echo "=================================================="
echo ""

if [ -n "$SUCCESSFUL_COVERAGE" ]; then
    echo -e "${GREEN}Successfully generated:${NC}"
    echo -e "$SUCCESSFUL_COVERAGE"
    echo ""
fi

if [ -n "$FAILED_COVERAGE" ]; then
    echo -e "${YELLOW}Failed or missing:${NC}"
    echo -e "$FAILED_COVERAGE"
    echo ""
fi

print_success "Coverage reports saved to: $COVERAGE_DIR/"
echo ""
echo "To view reports:"
echo "  - Open $COVERAGE_DIR/COVERAGE_SUMMARY.md for overview"
echo "  - Open $COVERAGE_DIR/*/index.html for interactive HTML reports"
echo "  - View $COVERAGE_DIR/*-coverage.txt for console summaries"
echo ""
