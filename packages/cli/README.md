# password-cli

🔐 Secure password generation from the command line

[![npm version](https://img.shields.io/npm/v/password-cli.svg)](https://www.npmjs.com/package/password-cli)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/iAn-P1nt0/password-kit/blob/main/LICENSE)

Generate cryptographically secure passwords and passphrases directly from your terminal. Uses Web Crypto API for maximum security.

## Features

✅ **Secure Random Generation** - Uses Web Crypto API  
✅ **Multiple Formats** - Passwords, passphrases, PINs  
✅ **Strength Analysis** - Powered by zxcvbn  
✅ **Breach Checking** - HIBP integration with k-Anonymity  
✅ **Clipboard Support** - Auto-copy with 30s timeout  
✅ **JSON Output** - Machine-readable format  
✅ **Cross-Platform** - Works on macOS, Linux, Windows  
✅ **No Installation Required** - Use with `npx`  

## Installation

### Global Install

```bash
npm install -g password-cli
```

### Use with npx (No Install)

```bash
npx password-cli generate
```

### Alias

```bash
alias tvpg="npx password-cli"
```

## Quick Start

```bash
# Generate a password (default: 16 characters)
tvpg generate

# Generate a passphrase (default: 5 words)
tvpg passphrase

# Check password strength
tvpg analyze "MyP@ssw0rd123"

# Check for breaches
tvpg breach "password123"
```

## Commands

### `generate` - Generate Password

Generate a secure random password with customizable options.

```bash
tvpg generate [options]
# Aliases: gen, g
```

**Options:**

```bash
-l, --length <number>    Password length (8-128) [default: 16]
-c, --count <number>     Number of passwords to generate [default: 1]
--no-uppercase           Exclude uppercase letters
--no-lowercase           Exclude lowercase letters
--no-numbers             Exclude numbers
--no-symbols             Exclude symbols
--no-copy                Do not copy to clipboard
--json                   Output as JSON
-q, --quiet              Minimal output (password only)
```

**Examples:**

```bash
# Basic password
tvpg generate
# Output: Kp9$mNz2@Qw5Xr8T

# Custom length
tvpg generate --length 32

# Generate 5 passwords
tvpg generate --count 5

# Alphanumeric only (no symbols)
tvpg generate --no-symbols

# Quiet mode (password only)
tvpg generate --quiet

# JSON output
tvpg generate --json
# Output: {"password":"...","strength":"very-strong","entropy":95.2}

# Don't copy to clipboard
tvpg generate --no-copy
```

### `passphrase` - Generate Passphrase

Generate a memorable Diceware-style passphrase.

```bash
tvpg passphrase [options]
# Aliases: phrase, p
```

**Options:**

```bash
-w, --words <number>         Number of words (3-10) [default: 5]
-s, --separator <type>       Separator: dash, space, none [default: dash]
-c, --capitalize <type>      Capitalize: none, first, all [default: first]
-n, --number                 Include a random number
--no-copy                    Do not copy to clipboard
--json                       Output as JSON
-q, --quiet                  Minimal output (passphrase only)
```

**Examples:**

```bash
# Basic passphrase
tvpg passphrase
# Output: Forest-Mountain-River-Sky-Ocean

# With number
tvpg passphrase --number
# Output: Forest-Mountain-River-Sky-Ocean47

# All caps with spaces
tvpg passphrase --capitalize all --separator space
# Output: FOREST MOUNTAIN RIVER SKY OCEAN

# 8 words, no separator
tvpg passphrase --words 8 --separator none
# Output: forestmountainriverskyoceanvalleyhillpeak
```

### `analyze` - Analyze Password Strength

Comprehensive password strength analysis using zxcvbn.

```bash
tvpg analyze <password> [options]
# Aliases: check, a
```

**Options:**

```bash
--json    Output as JSON
```

**Examples:**

```bash
# Analyze password
tvpg analyze "MyP@ssw0rd123"

# Output:
# Password Strength Analysis
#
# Overall Score: 42/100
# Strength:      medium
# Entropy:       45.2 bits
# Crack Time:    3 hours
#
# ⚠ Warning: This is similar to a commonly used password
#
# 💡 Suggestions:
#   • Add more unique characters
#   • Avoid predictable substitutions like '@' for 'a'
#
# 🔍 Weaknesses:
#   • Contains common pattern or dictionary word
#   • Contains year or date pattern

# JSON output
tvpg analyze "password" --json
```

### `quick` - Quick Strength Check

Fast strength check without loading heavy dependencies.

```bash
tvpg quick <password> [options]
# Alias: q
```

**Examples:**

```bash
tvpg quick "abc123"
# Output:
# Score:    25/100
# Strength: weak
# Feedback: Password is too short (minimum 8 characters)
```

### `breach` - Check for Breaches

Check if password has been exposed in data breaches (HIBP).

```bash
tvpg breach <password> [options]
# Alias: b
```

**Options:**

```bash
--no-network          Cache-only mode (offline)
--timeout <ms>        Request timeout in milliseconds [default: 5000]
--json                Output as JSON
```

**Examples:**

```bash
# Check password
tvpg breach "password123"

# Output:
# ⚠ PASSWORD BREACHED!
#
# This password has been found in 2,418,927 data breaches.
# Do NOT use this password!

# Check with timeout
tvpg breach "MySecureP@ss" --timeout 3000

# Offline mode (cache only)
tvpg breach "test" --no-network
```

### `interactive` - Interactive Mode

Interactive password generator (coming soon).

```bash
tvpg interactive
# Alias: i
```

## Output Formats

### Standard Output

Human-readable formatted output with colors:

```bash
$ tvpg generate --length 20

Generated Password:
Kp9$mNz2@Qw5Xr8T1Mf3

Strength: very-strong
Entropy:  119.4 bits
Length:   20 characters

✓ Copied to clipboard
  (Auto-clears in 30 seconds)
```

### Quiet Mode

Minimal output (password/passphrase only):

```bash
$ tvpg generate --quiet
Kp9$mNz2@Qw5Xr8T
```

### JSON Output

Machine-readable JSON format:

```bash
$ tvpg generate --json
{
  "password": "Kp9$mNz2@Qw5Xr8T",
  "strength": "very-strong",
  "entropy": 95.2
}
```

## Clipboard Integration

By default, generated passwords are automatically copied to clipboard:

- ✅ Auto-copy to clipboard
- ⏱️ Auto-clear after 30 seconds
- 🔒 Secure clipboard handling
- ❌ Use `--no-copy` to disable

**Security Notes:**
- Clipboard is automatically cleared after 30 seconds
- On shared systems, consider using `--no-copy` flag
- In CI/CD environments, clipboard may not be available

## Shell Integration

### Bash/Zsh Aliases

```bash
# ~/.bashrc or ~/.zshrc
alias genpw="npx password-cli generate"
alias genphrase="npx password-cli passphrase"
alias checkpw="npx password-cli analyze"
```

### Fish Shell

```fish
# ~/.config/fish/config.fish
alias genpw "npx password-cli generate"
alias genphrase "npx password-cli passphrase"
```

### PowerShell

```powershell
# $PROFILE
function genpw { npx password-cli generate $args }
function genphrase { npx password-cli passphrase $args }
```

## Advanced Usage

### Generate Multiple Passwords

```bash
# Generate 10 passwords
tvpg generate --count 10 --quiet

# Save to file
tvpg generate --count 100 --quiet > passwords.txt
```

### Password Manager Integration

```bash
#!/bin/bash
# generate-and-save.sh

PASSWORD=$(tvpg generate --length 32 --quiet)
echo "Password: $PASSWORD"

# Save to password manager
pass insert -e myapp/password <<< "$PASSWORD"
```

### JSON Processing with jq

```bash
# Get just the password
tvpg generate --json | jq -r '.password'

# Get entropy
tvpg generate --json | jq '.entropy'

# Batch generate and process
for i in {1..5}; do
  tvpg generate --length 20 --json | jq -r '.password'
done
```

### Conditional Breach Check

```bash
#!/bin/bash
# check-before-use.sh

PASSWORD=$(tvpg generate --quiet)

# Check for breaches
RESULT=$(tvpg breach "$PASSWORD" --json)
BREACHED=$(echo "$RESULT" | jq -r '.breached')

if [ "$BREACHED" = "true" ]; then
  echo "Password breached! Generating new one..."
  ./check-before-use.sh  # Retry
else
  echo "Safe password: $PASSWORD"
fi
```

## Security Best Practices

1. **Never log passwords** - Avoid piping to log files
2. **Clear clipboard** - Use `--no-copy` on shared systems
3. **Check breaches** - Always check generated passwords
4. **Use passphrases** - For memorable passwords
5. **Sufficient length** - Minimum 16 characters for passwords
6. **Unique passwords** - Generate unique password per service

## Environment Variables

```bash
# Disable clipboard (override default)
export TVPG_NO_COPY=1

# Default password length
export TVPG_LENGTH=24

# Default passphrase words
export TVPG_WORDS=6
```

## Exit Codes

- `0` - Success
- `1` - Error (invalid options, generation failed, etc.)

## Platform Support

- ✅ macOS 10.13+
- ✅ Linux (any recent distribution)
- ✅ Windows 10/11
- ✅ WSL (Windows Subsystem for Linux)

**Requirements:**
- Node.js 20+
- Terminal with color support (recommended)

## Examples Collection

### Generate Strong Password for Banking

```bash
tvpg generate --length 32 --symbols
```

### Generate Memorable Password for WiFi

```bash
tvpg passphrase --words 4 --separator none --capitalize all --number
# Output: FORESTMOUNTAINRIVERSKY7284
```

### Check if Common Password is Safe

```bash
tvpg breach "Welcome123"
```

### Generate API Key

```bash
tvpg generate --length 64 --quiet
```

### Bulk Generate Passwords

```bash
tvpg generate --count 20 --quiet | tee passwords.txt
```

## Troubleshooting

### Clipboard Not Working

```bash
# Install clipboard dependencies

# macOS - Already supported
# Linux
sudo apt-get install xclip  # Debian/Ubuntu
sudo yum install xclip      # RHEL/CentOS

# Or disable clipboard
tvpg generate --no-copy
```

### Colors Not Displaying

```bash
# Enable color support
export FORCE_COLOR=1

# Or use NO_COLOR to disable
export NO_COLOR=1
```

### Permission Denied

```bash
# Ensure execute permissions
chmod +x ./node_modules/.bin/tvpg

# Or use npx
npx password-cli generate
```

## Related Packages

- [password-kit](https://www.npmjs.com/package/password-kit) - Core library
- [password-kit-react](https://www.npmjs.com/package/password-kit-react) - React hooks
- [password-generator-element](https://www.npmjs.com/package/password-generator-element) - Web component

## Contributing

See [CONTRIBUTING.md](https://github.com/iAn-P1nt0/password-kit/blob/main/CONTRIBUTING.md)

## License

Apache-2.0

## Support

- 📖 [Documentation](https://github.com/iAn-P1nt0/password-kit)
- 🐛 [Issue Tracker](https://github.com/iAn-P1nt0/password-kit/issues)
- 💬 [Discussions](https://github.com/iAn-P1nt0/password-kit/discussions)
