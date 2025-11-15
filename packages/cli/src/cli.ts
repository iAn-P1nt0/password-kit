#!/usr/bin/env node

/**
 * TrustVault Password Generator CLI
 * 
 * Secure password and passphrase generation from the command line
 */

import { Command } from 'commander';
import chalk, { ChalkInstance } from 'chalk';
import clipboardy from 'clipboardy';
import ora from 'ora';
import {
  generatePassword,
  generatePassphrase,
  analyzePasswordStrength,
  quickStrengthCheck,
  checkPasswordBreach,
  type QuickStrengthResult,
} from '@trustvault/password-utils';

const program = new Command();

// Version from package.json
program
  .name('tvpg')
  .description('🔐 TrustVault Password Generator - Secure passwords from the terminal')
  .version('1.0.0');

/**
 * Generate Password Command
 */
program
  .command('generate')
  .alias('gen')
  .alias('g')
  .description('Generate a secure random password')
  .option('-l, --length <number>', 'Password length (8-128)', '16')
  .option('-c, --count <number>', 'Number of passwords to generate', '1')
  .option('--no-uppercase', 'Exclude uppercase letters')
  .option('--no-lowercase', 'Exclude lowercase letters')
  .option('--no-numbers', 'Exclude numbers')
  .option('--no-symbols', 'Exclude symbols')
  .option('--no-ambiguous', 'Exclude ambiguous characters (l, 1, O, 0, etc.)')
  .option('--no-copy', 'Do not copy to clipboard')
  .option('--json', 'Output as JSON')
  .option('-q, --quiet', 'Minimal output (password only)')
  .action(async (options) => {
    try {
      const length = parseInt(options.length, 10);
      const count = parseInt(options.count, 10);

      if (isNaN(length) || length < 8 || length > 128) {
        console.error(chalk.red('Error: Length must be between 8 and 128'));
        process.exit(1);
      }

      if (isNaN(count) || count < 1 || count > 100) {
        console.error(chalk.red('Error: Count must be between 1 and 100'));
        process.exit(1);
      }

      const results = [];

      for (let i = 0; i < count; i++) {
        const result = generatePassword({
          length,
          includeUppercase: options.uppercase !== false,
          includeLowercase: options.lowercase !== false,
          includeNumbers: options.numbers !== false,
          includeSymbols: options.symbols !== false,
          excludeAmbiguous: options.ambiguous === false,
        });

        results.push(result);

        if (!options.quiet && !options.json) {
          console.log();
          console.log(chalk.bold.cyan('Generated Password:'));
          console.log(chalk.bold.white(result.password));
          console.log();
          
          const strengthColor = getStrengthColor(result.strength);
          console.log(chalk.gray('Strength:'), strengthColor(result.strength));
          console.log(chalk.gray('Entropy: '), chalk.white(`${result.entropy.toFixed(1)} bits`));
          console.log(chalk.gray('Length:  '), chalk.white(`${result.password.length} characters`));
        } else if (options.quiet) {
          console.log(result.password);
        }
      }

      // Copy first password to clipboard
      if (options.copy && results.length > 0) {
        try {
          await clipboardy.write(results[0]!.password);
          if (!options.quiet && !options.json) {
            console.log();
            console.log(chalk.green('✓'), 'Copied to clipboard');
            console.log(chalk.gray('  (Auto-clears in 30 seconds)'));
          }

          // Clear clipboard after 30 seconds
          setTimeout(() => {
            clipboardy.write('').catch(() => {
              // Ignore errors on cleanup
            });
          }, 30000);
        } catch (error) {
          if (!options.quiet && !options.json) {
            console.log(chalk.yellow('⚠'), 'Could not copy to clipboard');
          }
        }
      }

      // JSON output
      if (options.json) {
        console.log(JSON.stringify(count === 1 ? results[0] : results, null, 2));
      }

    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

/**
 * Generate Passphrase Command
 */
program
  .command('passphrase')
  .alias('phrase')
  .alias('p')
  .description('Generate a memorable passphrase')
  .option('-w, --words <number>', 'Number of words (3-10)', '5')
  .option('-s, --separator <type>', 'Separator: dash, space, none', 'dash')
  .option('-c, --capitalize <type>', 'Capitalize: none, first, all, random', 'first')
  .option('-n, --number', 'Include a random number')
  .option('--no-copy', 'Do not copy to clipboard')
  .option('--json', 'Output as JSON')
  .option('-q, --quiet', 'Minimal output (passphrase only)')
  .action(async (options) => {
    try {
      const wordCount = parseInt(options.words, 10);

      if (isNaN(wordCount) || wordCount < 3 || wordCount > 10) {
        console.error(chalk.red('Error: Word count must be between 3 and 10'));
        process.exit(1);
      }

      const result = generatePassphrase({
        wordCount,
        separator: options.separator as 'dash' | 'space' | 'symbol' | 'none',
        capitalize: options.capitalize as 'none' | 'first' | 'all' | 'random',
        includeNumbers: options.number === true,
      });

      if (!options.quiet && !options.json) {
        console.log();
        console.log(chalk.bold.cyan('Generated Passphrase:'));
        console.log(chalk.bold.white(result.password));
        console.log();
        
        const strengthColor = getStrengthColor(result.strength);
        console.log(chalk.gray('Strength:'), strengthColor(result.strength));
        console.log(chalk.gray('Entropy: '), chalk.white(`${result.entropy.toFixed(1)} bits`));
        console.log(chalk.gray('Words:   '), chalk.white(`${wordCount} words`));
      } else if (options.quiet) {
        console.log(result.password);
      }

      // Copy to clipboard
      if (options.copy) {
        try {
          await clipboardy.write(result.password);
          if (!options.quiet && !options.json) {
            console.log();
            console.log(chalk.green('✓'), 'Copied to clipboard');
            console.log(chalk.gray('  (Auto-clears in 30 seconds)'));
          }

          // Clear after 30 seconds
          setTimeout(() => {
            clipboardy.write('').catch(() => {});
          }, 30000);
        } catch (error) {
          if (!options.quiet && !options.json) {
            console.log(chalk.yellow('⚠'), 'Could not copy to clipboard');
          }
        }
      }

      // JSON output
      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      }

    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

/**
 * Analyze Password Strength Command
 */
program
  .command('analyze')
  .alias('check')
  .alias('a')
  .description('Analyze password strength')
  .argument('<password>', 'Password to analyze')
  .option('--json', 'Output as JSON')
  .action(async (password: string, options) => {
    try {
      const spinner = ora('Analyzing password strength...').start();
      
      const result = await analyzePasswordStrength(password);
      
      spinner.stop();

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      console.log();
      console.log(chalk.bold.cyan('Password Strength Analysis'));
      console.log();
      
      const strengthColor = getStrengthColor(result.strength);
      console.log(chalk.gray('Overall Score:'), strengthColor(`${result.score}/100`));
      console.log(chalk.gray('Strength:     '), strengthColor(result.strength));
      console.log(chalk.gray('Entropy:      '), chalk.white(`${result.entropy} bits`));
      console.log(chalk.gray('Crack Time:   '), chalk.white(result.crackTime));
      
      if (result.feedback.warning) {
        console.log();
        console.log(chalk.yellow('⚠ Warning:'), result.feedback.warning);
      }

      if (result.feedback.suggestions.length > 0) {
        console.log();
        console.log(chalk.cyan('💡 Suggestions:'));
        result.feedback.suggestions.forEach(suggestion => {
          console.log(chalk.gray('  •'), suggestion);
        });
      }

      if (result.weaknesses.length > 0) {
        console.log();
        console.log(chalk.red('🔍 Weaknesses:'));
        result.weaknesses.forEach(weakness => {
          console.log(chalk.gray('  •'), weakness);
        });
      }

      console.log();

    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

/**
 * Quick Strength Check Command
 */
program
  .command('quick')
  .alias('q')
  .description('Quick password strength check (no dependencies loaded)')
  .argument('<password>', 'Password to check')
  .option('--json', 'Output as JSON')
  .action((password: string, options) => {
    try {
      const result = quickStrengthCheck(password);

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      console.log();
      const strengthColor = getStrengthColor(result.strength);
      console.log(chalk.gray('Score:   '), strengthColor(`${result.score}/100`));
      console.log(chalk.gray('Strength:'), strengthColor(result.strength));
      console.log(chalk.gray('Feedback:'), getQuickFeedback(result));
      console.log();

    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

/**
 * Breach Check Command
 */
program
  .command('breach')
  .alias('b')
  .description('Check if password has been breached (HIBP)')
  .argument('<password>', 'Password to check')
  .option('--no-network', 'Cache-only mode (offline)')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '5000')
  .option('--json', 'Output as JSON')
  .action(async (password: string, options) => {
    try {
      const spinner = ora('Checking password against breach database...').start();
      
      const result = await checkPasswordBreach(password, {
        allowNetwork: options.network,
        timeout: parseInt(options.timeout, 10),
      });
      
      spinner.stop();

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      console.log();
      
      if (result.breached) {
        console.log(chalk.red.bold('⚠ PASSWORD BREACHED!'));
        console.log();
        console.log(chalk.red(`This password has been found in ${result.count} data breaches.`));
        console.log(chalk.yellow('Do NOT use this password!'));
      } else if (result.checked) {
        console.log(chalk.green.bold('✓ Password Not Found in Breaches'));
        console.log();
        console.log(chalk.gray('This password has not been found in known breaches.'));
        if (result.cached) {
          console.log(chalk.gray('(Result from cache)'));
        }
      } else if (result.offline) {
        console.log(chalk.yellow('⚠ Offline - Could Not Check'));
        console.log();
        console.log(chalk.gray('Network request disabled or unavailable.'));
        console.log(chalk.gray('Try again with network connection.'));
      } else {
        console.log(chalk.yellow('⚠ Could Not Complete Check'));
      }

      console.log();

    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

/**
 * Interactive Mode Command
 */
program
  .command('interactive')
  .alias('i')
  .description('Interactive password generator')
  .action(async () => {
    console.log(chalk.cyan.bold('\n🔐 TrustVault Password Generator\n'));
    console.log(chalk.gray('Interactive mode coming soon...'));
    console.log(chalk.gray('Use --help to see available commands\n'));
  });

/**
 * Helper function to get color for strength level
 */
function getStrengthColor(strength: string): ChalkInstance {
  switch (strength) {
    case 'weak':
      return chalk.red;
    case 'medium':
      return chalk.yellow;
    case 'strong':
      return chalk.cyan;
    case 'very-strong':
      return chalk.green;
    default:
      return chalk.white;
  }
}

function getQuickFeedback(result: QuickStrengthResult): string {
  if (result.score < 30) {
    return 'Too short or predictable; add length and variety.';
  }

  if (result.score < 50) {
    return 'Add uppercase, numbers, and symbols to strengthen it.';
  }

  if (result.score < 70) {
    return 'Pretty good—consider a longer password for extra safety.';
  }

  return 'Excellent entropy for quick checks.';
}

// Parse arguments
program.parse();
