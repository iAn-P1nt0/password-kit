#!/bin/bash

# Build All Packages Script
# This script builds all packages in the monorepo

set -e

echo "=================================================="
echo "Building all TrustVault Password Utils packages"
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

# Track build status
FAILED_BUILDS=""
SUCCESSFUL_BUILDS=""

# Build main package
print_step "Building main package (password-kit)..."
if npm run build 2>&1 | tee /tmp/main-build.log; then
    print_success "Main package built successfully"
    SUCCESSFUL_BUILDS="${SUCCESSFUL_BUILDS}\n  - Main package"
else
    print_error "Main package build failed"
    FAILED_BUILDS="${FAILED_BUILDS}\n  - Main package"
fi
echo ""

# Build React package
print_step "Building React hooks package (password-kit-react)..."
cd packages/react
if npm install --silent 2>&1 && npm run build 2>&1 | tee /tmp/react-build.log; then
    print_success "React package built successfully"
    SUCCESSFUL_BUILDS="${SUCCESSFUL_BUILDS}\n  - React hooks package"
else
    print_error "React package build failed"
    FAILED_BUILDS="${FAILED_BUILDS}\n  - React hooks package"
fi
cd ../..
echo ""

# Build CLI package
print_step "Building CLI package (password-cli)..."
cd packages/cli
if npm install --silent 2>&1 && npm run build 2>&1 | tee /tmp/cli-build.log; then
    print_success "CLI package built successfully"
    SUCCESSFUL_BUILDS="${SUCCESSFUL_BUILDS}\n  - CLI package"
else
    print_error "CLI package build failed"
    FAILED_BUILDS="${FAILED_BUILDS}\n  - CLI package"
fi
cd ../..
echo ""

# Build Web Component package
print_step "Building Web Component package (password-generator-element)..."
cd packages/web-component
if npm install --silent 2>&1 && npm run build 2>&1 | tee /tmp/webcomponent-build.log; then
    print_success "Web Component package built successfully"
    SUCCESSFUL_BUILDS="${SUCCESSFUL_BUILDS}\n  - Web Component package"
else
    print_error "Web Component package build failed"
    FAILED_BUILDS="${FAILED_BUILDS}\n  - Web Component package"
fi
cd ../..
echo ""

# Print summary
echo "=================================================="
echo "Build Summary"
echo "=================================================="

if [ -n "$SUCCESSFUL_BUILDS" ]; then
    echo -e "${GREEN}Successful builds:${NC}"
    echo -e "$SUCCESSFUL_BUILDS"
    echo ""
fi

if [ -n "$FAILED_BUILDS" ]; then
    echo -e "${RED}Failed builds:${NC}"
    echo -e "$FAILED_BUILDS"
    echo ""
    exit 1
else
    print_success "All packages built successfully!"
    exit 0
fi
