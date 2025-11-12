# Publishing Guide for @trustvault/password-utils

This guide walks through the process of publishing this package to the npm registry.

## Prerequisites

### 1. NPM Account Setup

**Create an npm account:**
```bash
npm adduser
```

Or login if you already have an account:
```bash
npm login
```

Verify you're logged in:
```bash
npm whoami
```

### 2. Package Scope Access

This package uses the `@trustvault` scope. Ensure you have publishing rights:

- **Organization member:** If `@trustvault` is an npm organization, you need to be added as a member with publish permissions
- **Personal scope:** If this is your personal scope, you're automatically authorized

### 3. Two-Factor Authentication (Recommended)

Enable 2FA for additional security:
```bash
npm profile enable-2fa auth-and-writes
```

---

## Pre-Publishing Checklist

Before publishing, ensure all criteria are met:

### Code Quality
- [ ] All tests pass: `npm test`
- [ ] Type checking passes: `npm run type-check`
- [ ] Linting passes: `npm run lint`
- [ ] Build succeeds: `npm run build`

### Package Configuration
- [ ] `package.json` version is correct
- [ ] `package.json` name is `@trustvault/password-utils`
- [ ] `package.json` has correct repository URLs
- [ ] `package.json` has appropriate keywords
- [ ] `package.json` `files` field includes only necessary files
- [ ] `private` field is set to `false`

### Documentation
- [ ] README.md is complete and accurate
- [ ] CHANGELOG.md is updated with version changes
- [ ] LICENSE file exists (Apache-2.0)
- [ ] All exported functions have JSDoc comments

### Security
- [ ] No secrets or credentials in code
- [ ] No security vulnerabilities: `npm audit`
- [ ] Dependencies are up to date
- [ ] .npmignore excludes development files

---

## Publishing Process

### Step 1: Verify Package Contents

**Dry run to see what will be published:**
```bash
npm pack --dry-run
```

This shows all files that will be included in the package.

**Create a test tarball:**
```bash
npm pack
```

This creates a `.tgz` file you can inspect. Extract and verify:
```bash
tar -xzf trustvault-password-utils-1.0.0.tgz
cd package
ls -la
```

### Step 2: Test the Package Locally

**Install from tarball:**
```bash
npm install /path/to/trustvault-password-utils-1.0.0.tgz
```

**Test in a separate project:**
```bash
mkdir test-project
cd test-project
npm init -y
npm install ../TrustVault-password-utils/trustvault-password-utils-1.0.0.tgz
```

Create a test file:
```javascript
// test.js
const { generatePassword, analyzePasswordStrength } = require('@trustvault/password-utils');

const result = generatePassword({ length: 16 });
console.log('Password:', result.password);
console.log('Strength:', result.strength);

const analysis = analyzePasswordStrength(result.password);
console.log('Analysis:', analysis);
```

Run it:
```bash
node test.js
```

### Step 3: Run Pre-Publish Script

The `prepublishOnly` script automatically runs before publishing:
```bash
npm run prepublishOnly
```

This runs:
1. `npm run test` - Ensures all tests pass
2. `npm run build` - Builds the package

If this fails, **DO NOT PUBLISH**. Fix the issues first.

### Step 4: Publish to npm

**For a public scoped package:**
```bash
npm publish --access public
```

**For a private scoped package:**
```bash
npm publish --access restricted
```

**For first-time publishing with 2FA:**
```bash
npm publish --access public --otp=123456
```
(Replace `123456` with your 2FA code)

### Step 5: Verify Publication

**Check on npm:**
```bash
npm view @trustvault/password-utils
```

**Install and test:**
```bash
npm install @trustvault/password-utils
```

**View on npmjs.com:**
```
https://www.npmjs.com/package/@trustvault/password-utils
```

---

## Version Management

### Semantic Versioning

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.x.x → 2.x.x): Breaking changes
- **MINOR** (x.1.x → x.2.x): New features (backward compatible)
- **PATCH** (x.x.1 → x.x.2): Bug fixes (backward compatible)

### Updating Version

**Manually:**
Edit `package.json` and update the `version` field.

**Using npm:**
```bash
npm version patch   # 1.0.0 → 1.0.1
npm version minor   # 1.0.0 → 1.1.0
npm version major   # 1.0.0 → 2.0.0
```

This automatically:
1. Updates `package.json`
2. Creates a git commit
3. Creates a git tag

**Update CHANGELOG.md:**
Document all changes in CHANGELOG.md before publishing.

---

## Release Workflow

### Standard Release (Patch/Minor)

```bash
# 1. Ensure main branch is up to date
git checkout main
git pull origin main

# 2. Run tests and build
npm run test
npm run build

# 3. Update version
npm version minor   # or patch

# 4. Update CHANGELOG.md
# Edit CHANGELOG.md to document changes

# 5. Commit changelog
git add CHANGELOG.md
git commit -m "docs: update changelog for v1.1.0"

# 6. Push commits and tags
git push origin main --tags

# 7. Publish to npm
npm publish --access public

# 8. Create GitHub release
gh release create v1.1.0 --title "v1.1.0" --notes "See CHANGELOG.md"
```

### Major Release (Breaking Changes)

Same as above, but:

```bash
# Update version
npm version major   # 1.0.0 → 2.0.0

# Include migration guide in CHANGELOG.md
# Document all breaking changes
# Provide migration examples
```

---

## Publishing Checklist

**Before `npm publish`:**
- [ ] Tests pass (`npm test`)
- [ ] Build succeeds (`npm run build`)
- [ ] Version updated in `package.json`
- [ ] CHANGELOG.md updated
- [ ] Git commits pushed
- [ ] Git tag created and pushed
- [ ] No uncommitted changes

**After `npm publish`:**
- [ ] Verify on npmjs.com
- [ ] Test installation: `npm install @trustvault/password-utils`
- [ ] Create GitHub release
- [ ] Announce on relevant channels
- [ ] Update documentation site (if applicable)

---

## Troubleshooting

### "You do not have permission to publish"

**Solution:**
- Verify you're logged in: `npm whoami`
- Check scope ownership: `npm owner ls @trustvault/password-utils`
- Request access from organization admin
- Or change package name to your own scope

### "Package name too similar to existing package"

**Solution:**
- Choose a different package name
- Or use a scope: `@yourname/password-utils`

### "Version already exists"

**Solution:**
- Update version in `package.json`
- Use `npm version patch/minor/major`

### "prepublishOnly script failed"

**Solution:**
- Fix failing tests: `npm test`
- Fix build errors: `npm run build`
- Ensure all dependencies are installed: `npm install`

### "402 Payment Required"

**Solution:**
- Private scoped packages require a paid npm account
- Use `--access public` for free public packages
- Or publish to GitHub Package Registry instead

---

## Alternative: GitHub Package Registry

You can also publish to GitHub Package Registry:

### 1. Configure .npmrc

Create `.npmrc` in project root:
```
@trustvault:registry=https://npm.pkg.github.com
```

### 2. Authenticate

```bash
npm login --registry=https://npm.pkg.github.com
```

Use your GitHub username and personal access token.

### 3. Update package.json

```json
{
  "name": "@trustvault/password-utils",
  "repository": {
    "type": "git",
    "url": "https://github.com/indi-gamification-initiative/TrustVault-password-utils.git"
  },
  "publishConfig": {
    "registry": "https://npm.pkg.github.com"
  }
}
```

### 4. Publish

```bash
npm publish
```

---

## Best Practices

### 1. Test Before Publishing
Always test the package in a real project before publishing.

### 2. Use Semantic Versioning
Follow semver strictly to avoid breaking user code.

### 3. Document Changes
Keep CHANGELOG.md up to date with all changes.

### 4. Tag Releases
Always create git tags for releases: `git tag v1.0.0`

### 5. Never Publish Secrets
Double-check that no API keys or credentials are in the code.

### 6. Use .npmignore
Exclude development files from the published package.

### 7. Test in Multiple Environments
Test in Node.js, browsers, TypeScript, and JavaScript projects.

### 8. Automate with CI/CD
Consider using GitHub Actions to automate testing and publishing.

---

## CI/CD Automation (Optional)

Create `.github/workflows/publish.yml`:

```yaml
name: Publish Package

on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm test
      - run: npm run build
      - run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Add `NPM_TOKEN` to GitHub repository secrets.

---

## Support

For publishing issues:
- npm documentation: https://docs.npmjs.com/
- npm support: https://www.npmjs.com/support
- GitHub Package Registry: https://docs.github.com/en/packages

For package-specific issues:
- GitHub Issues: https://github.com/indi-gamification-initiative/TrustVault-password-utils/issues

---

**Happy Publishing! 🚀**
