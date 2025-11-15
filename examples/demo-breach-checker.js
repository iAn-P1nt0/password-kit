#!/usr/bin/env node

/**
 * Breach Checker Demo Script
 *
 * This script demonstrates the breach checking functionality
 * with real HIBP API calls (requires internet connection).
 *
 * Run with: node demo-breach-checker.js
 */

import { checkPasswordBreach, clearBreachCache } from './dist/index.js';

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function header(text) {
  log('\n' + '='.repeat(60), 'cyan');
  log(`  ${text}`, 'bright');
  log('='.repeat(60), 'cyan');
}

function formatResult(result) {
  const parts = [];

  parts.push(`Checked: ${result.checked}`);
  parts.push(`Breached: ${result.breached ?? 'N/A'}`);

  if (result.count !== undefined) {
    parts.push(`Count: ${result.count}`);
  }
  if (result.cached !== undefined) {
    parts.push(`Cached: ${result.cached}`);
  }
  if (result.offline !== undefined) {
    parts.push(`Offline: ${result.offline}`);
  }

  return parts.join(', ');
}

async function testPassword(password, description, options = {}) {
  log(`\nTesting: ${description}`, 'blue');
  log(`Password: "${password}"`, 'yellow');

  const startTime = Date.now();

  try {
    const result = await checkPasswordBreach(password, options);
    const duration = Date.now() - startTime;

    log(`Result: ${formatResult(result)}`, 'cyan');
    log(`Duration: ${duration}ms`, 'cyan');

    if (result.breached) {
      log(`⚠️  BREACH DETECTED! Found ${result.count || '?'} times`, 'red');
    } else if (result.checked) {
      log('✅ Not found in breaches', 'green');
    } else {
      log('ℹ️  Could not check (offline or error)', 'yellow');
    }

    return result;
  } catch (error) {
    log(`❌ Error: ${error.message}`, 'red');
    throw error;
  }
}

async function runDemo() {
  log('\n╔════════════════════════════════════════════════════════╗', 'bright');
  log('║     TrustVault Password Breach Checker Demo           ║', 'bright');
  log('║     Using HIBP API with k-Anonymity Protocol          ║', 'bright');
  log('╚════════════════════════════════════════════════════════╝', 'bright');

  try {
    // Test 1: Common breached password
    header('Test 1: Known Breached Password');
    log('This password is in the top 10 most common passwords', 'yellow');
    await testPassword('password', 'Common password');

    // Test 2: Another common one
    header('Test 2: Another Known Breach');
    log('This is also a very common password', 'yellow');
    await testPassword('123456', 'Sequential numbers');

    // Test 3: Strong unique password
    header('Test 3: Strong Unique Password');
    log('This password is unlikely to be in any breach database', 'yellow');
    await testPassword(
      'Tr!Val$2024#SecP@ss',
      'Strong random password'
    );

    // Test 4: Cache demonstration
    header('Test 4: Cache Performance');
    log('Checking the same password again to demonstrate caching', 'yellow');
    log('This should be instant (cached from Test 1)', 'yellow');
    await testPassword('password', 'Cached password check');

    // Test 5: Offline mode
    header('Test 5: Offline Mode (Cache Only)');
    log('This demonstrates checking without network access', 'yellow');
    await testPassword(
      'newPasswordNeverChecked',
      'New password in offline mode',
      { allowNetwork: false }
    );

    // Test 6: With timeout
    header('Test 6: Timeout Handling');
    log('This demonstrates timeout handling (1ms timeout)', 'yellow');
    await testPassword(
      'anotherNewPassword',
      'Password with very short timeout',
      { timeout: 1 }
    );

    // Test 7: Real-world example
    header('Test 7: Real-World Password Examples');

    const passwords = [
      { pwd: 'qwerty123', desc: 'Keyboard pattern + numbers' },
      { pwd: 'letmein', desc: 'Common phrase' },
      { pwd: 'dragon', desc: 'Common word' },
    ];

    for (const { pwd, desc } of passwords) {
      await testPassword(pwd, desc);
    }

    // Summary
    header('Summary');
    log('✅ All tests completed successfully!', 'green');
    log('\nKey Features Demonstrated:', 'bright');
    log('  • k-Anonymity protocol (only 5-char hash prefix sent)', 'cyan');
    log('  • LRU cache with instant lookups', 'cyan');
    log('  • Offline mode support', 'cyan');
    log('  • Timeout handling', 'cyan');
    log('  • Real breach detection', 'cyan');

    log('\nSecurity Notes:', 'bright');
    log('  • Passwords are NEVER sent to the server', 'green');
    log('  • Only SHA-1 prefix (5 chars) is transmitted', 'green');
    log('  • All matching is done locally on your device', 'green');
    log('  • HTTPS-only communication', 'green');

    // Cache info
    header('Cache Management');
    log('Clearing cache...', 'yellow');
    await clearBreachCache();
    log('✅ Cache cleared successfully', 'green');
    log('Note: In production, cache persists for 24 hours', 'cyan');

  } catch (error) {
    log(`\n❌ Demo failed: ${error.message}`, 'red');
    console.error(error);
    process.exit(1);
  }

  log('\n' + '='.repeat(60), 'cyan');
  log('Demo completed!', 'bright');
  log('='.repeat(60) + '\n', 'cyan');
}

// Run the demo
runDemo().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
