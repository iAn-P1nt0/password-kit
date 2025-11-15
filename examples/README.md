# TrustVault Password Utils - Examples

This folder contains interactive demos showcasing @trustvault/password-utils features.

## Available Demos

### 1. Argon2id Password Hashing (`demo-argon2.html`)
Interactive browser demo for OWASP-compliant password hashing.

**Run:**
```bash
npm run build
python3 -m http.server 8000
# Visit: http://localhost:8000/examples/demo-argon2.html
```

### 2. Breach Checker Browser (`demo-breach-checker.html`)
Check passwords against Have I Been Pwned database.

**Run:**
```bash
npm run build
python3 -m http.server 8000
# Visit: http://localhost:8000/examples/demo-breach-checker.html
```

### 3. Breach Checker CLI (`demo-breach-checker.js`)
Command-line demo with colored output.

**Run:**
```bash
npm run build
node examples/demo-breach-checker.js
```

## Security Notes

- ✅ All operations happen locally
- ✅ Passwords never sent to servers
- ✅ HTTPS-only APIs
- ✅ OWASP 2023 compliant

See main README for full documentation.
