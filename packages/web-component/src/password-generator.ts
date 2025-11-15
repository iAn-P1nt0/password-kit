/**
 * <password-generator> Web Component
 * 
 * A framework-agnostic custom element for generating secure passwords
 * 
 * @example
 * ```html
 * <password-generator 
 *   length="20" 
 *   include-symbols="true"
 *   auto-generate="false">
 * </password-generator>
 * ```
 */

import { generatePassword, type PasswordGeneratorOptions } from '@trustvault/password-utils';

const template = document.createElement('template');
template.innerHTML = `
  <style>
    :host {
      display: block;
      font-family: system-ui, -apple-system, sans-serif;
      max-width: 500px;
    }

    .container {
      padding: 1.5rem;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
      background: #fff;
    }

    .title {
      margin: 0 0 1rem 0;
      font-size: 1.25rem;
      font-weight: 600;
      color: #333;
    }

    .password-display {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }

    .password-input {
      flex: 1;
      padding: 0.75rem;
      font-family: 'Courier New', monospace;
      font-size: 1rem;
      border: 2px solid #e0e0e0;
      border-radius: 4px;
      background: #f9f9f9;
    }

    .password-input:focus {
      outline: none;
      border-color: #4CAF50;
    }

    .btn {
      padding: 0.75rem 1rem;
      font-size: 0.875rem;
      font-weight: 500;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-primary {
      background: #4CAF50;
      color: white;
    }

    .btn-primary:hover:not(:disabled) {
      background: #45a049;
    }

    .btn-secondary {
      background: #2196F3;
      color: white;
    }

    .btn-secondary:hover:not(:disabled) {
      background: #0b7dda;
    }

    .options {
      display: grid;
      gap: 1rem;
      margin-bottom: 1rem;
    }

    .option-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .option-label {
      font-size: 0.875rem;
      color: #666;
    }

    .slider-container {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex: 1;
      max-width: 200px;
    }

    .slider {
      flex: 1;
      height: 4px;
      border-radius: 2px;
      background: #e0e0e0;
      outline: none;
      -webkit-appearance: none;
    }

    .slider::-webkit-slider-thumb {
      -webkit-appearance: none;
      appearance: none;
      width: 16px;
      height: 16px;
      border-radius: 50%;
      background: #4CAF50;
      cursor: pointer;
    }

    .slider::-moz-range-thumb {
      width: 16px;
      height: 16px;
      border-radius: 50%;
      background: #4CAF50;
      cursor: pointer;
      border: none;
    }

    .slider-value {
      font-size: 0.875rem;
      font-weight: 600;
      color: #333;
      min-width: 2rem;
      text-align: right;
    }

    .checkbox-label {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.875rem;
      color: #666;
      cursor: pointer;
      user-select: none;
    }

    .checkbox {
      width: 18px;
      height: 18px;
      cursor: pointer;
    }

    .actions {
      display: flex;
      gap: 0.5rem;
    }

    .info {
      margin-top: 1rem;
      padding: 0.75rem;
      background: #f5f5f5;
      border-radius: 4px;
      font-size: 0.875rem;
      color: #666;
    }

    .info-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 0.25rem;
    }

    .info-row:last-child {
      margin-bottom: 0;
    }

    .info-label {
      font-weight: 500;
    }

    .strength-weak { color: #f44336; }
    .strength-medium { color: #ff9800; }
    .strength-strong { color: #4CAF50; }
    .strength-very-strong { color: #2196F3; }

    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border-width: 0;
    }

    @media (prefers-color-scheme: dark) {
      .container {
        background: #1e1e1e;
        border-color: #333;
      }

      .title {
        color: #fff;
      }

      .password-input {
        background: #2d2d2d;
        border-color: #444;
        color: #fff;
      }

      .option-label,
      .checkbox-label {
        color: #ccc;
      }

      .slider-value {
        color: #fff;
      }

      .info {
        background: #2d2d2d;
        color: #ccc;
      }
    }
  </style>

  <div class="container">
    <h2 class="title">Password Generator</h2>
    
    <div class="password-display">
      <input 
        type="text" 
        class="password-input" 
        id="password-output"
        readonly
        aria-label="Generated password"
        aria-live="polite"
        placeholder="Click Generate to create password"
      />
    </div>

    <div class="options">
      <div class="option-row">
        <label class="option-label" for="length-slider">Password Length</label>
        <div class="slider-container">
          <input 
            type="range" 
            class="slider" 
            id="length-slider"
            min="8" 
            max="128" 
            value="16"
            aria-label="Password length"
          />
          <span class="slider-value" id="length-value" aria-live="polite">16</span>
        </div>
      </div>

      <div class="option-row">
        <label class="checkbox-label">
          <input type="checkbox" class="checkbox" id="uppercase" checked />
          Uppercase (A-Z)
        </label>
      </div>

      <div class="option-row">
        <label class="checkbox-label">
          <input type="checkbox" class="checkbox" id="lowercase" checked />
          Lowercase (a-z)
        </label>
      </div>

      <div class="option-row">
        <label class="checkbox-label">
          <input type="checkbox" class="checkbox" id="numbers" checked />
          Numbers (0-9)
        </label>
      </div>

      <div class="option-row">
        <label class="checkbox-label">
          <input type="checkbox" class="checkbox" id="symbols" checked />
          Symbols (!@#$...)
        </label>
      </div>
    </div>

    <div class="actions">
      <button class="btn btn-primary" id="generate-btn" aria-label="Generate new password">
        Generate
      </button>
      <button class="btn btn-secondary" id="copy-btn" aria-label="Copy password to clipboard" disabled>
        Copy
      </button>
    </div>

    <div class="info" id="info" role="status" aria-live="polite">
      <div class="info-row">
        <span class="info-label">Strength:</span>
        <span id="strength">-</span>
      </div>
      <div class="info-row">
        <span class="info-label">Entropy:</span>
        <span id="entropy">-</span>
      </div>
    </div>

    <!-- Screen reader announcements -->
    <div class="sr-only" role="status" aria-live="assertive" id="sr-announcements"></div>
  </div>
`;

/**
 * PasswordGeneratorElement
 * 
 * Custom element for generating secure passwords with configurable options
 */
export class PasswordGeneratorElement extends HTMLElement {
  private readonly root: ShadowRoot;
  private password: string = '';

  // Element references
  private passwordOutput!: HTMLInputElement;
  private lengthSlider!: HTMLInputElement;
  private lengthValue!: HTMLSpanElement;
  private uppercaseCheckbox!: HTMLInputElement;
  private lowercaseCheckbox!: HTMLInputElement;
  private numbersCheckbox!: HTMLInputElement;
  private symbolsCheckbox!: HTMLInputElement;
  private generateBtn!: HTMLButtonElement;
  private copyBtn!: HTMLButtonElement;
  private strengthDisplay!: HTMLSpanElement;
  private entropyDisplay!: HTMLSpanElement;
  private srAnnouncements!: HTMLDivElement;

  private readonly onLengthInput: (event: Event) => void;
  private readonly onGenerateClick: (event: MouseEvent) => void;
  private readonly onCopyClick: (event: MouseEvent) => void;
  private readonly onKeyDownHandler: (event: KeyboardEvent) => void;

  static get observedAttributes(): string[] {
    return [
      'length',
      'include-uppercase',
      'include-lowercase',
      'include-numbers',
      'include-symbols',
      'auto-generate',
    ];
  }

  constructor() {
    super();
    this.root = this.attachShadow({ mode: 'open' });
    this.root.appendChild(template.content.cloneNode(true));

    this.onLengthInput = this.handleLengthChange.bind(this);
    this.onGenerateClick = this.generate.bind(this);
    this.onCopyClick = this.copyToClipboard.bind(this);
    this.onKeyDownHandler = this.handleKeyDown.bind(this);
  }

  connectedCallback(): void {
    this.initializeElements();
    this.setupEventListeners();
    this.syncAttributesToUI();

    // Auto-generate if specified
    if (this.hasAttribute('auto-generate') && this.getAttribute('auto-generate') !== 'false') {
      this.generate();
    }
  }

  disconnectedCallback(): void {
    // Cleanup listeners
    this.removeEventListeners();
  }

  public attributeChangedCallback(_name: string, oldValue: string | null, newValue: string | null): void {
    if (oldValue !== newValue) {
      this.syncAttributesToUI();
    }
  }

  private initializeElements(): void {
    this.passwordOutput = this.root.getElementById('password-output') as HTMLInputElement;
    this.lengthSlider = this.root.getElementById('length-slider') as HTMLInputElement;
    this.lengthValue = this.root.getElementById('length-value') as HTMLSpanElement;
    this.uppercaseCheckbox = this.root.getElementById('uppercase') as HTMLInputElement;
    this.lowercaseCheckbox = this.root.getElementById('lowercase') as HTMLInputElement;
    this.numbersCheckbox = this.root.getElementById('numbers') as HTMLInputElement;
    this.symbolsCheckbox = this.root.getElementById('symbols') as HTMLInputElement;
    this.generateBtn = this.root.getElementById('generate-btn') as HTMLButtonElement;
    this.copyBtn = this.root.getElementById('copy-btn') as HTMLButtonElement;
    this.strengthDisplay = this.root.getElementById('strength') as HTMLSpanElement;
    this.entropyDisplay = this.root.getElementById('entropy') as HTMLSpanElement;
    this.srAnnouncements = this.root.getElementById('sr-announcements') as HTMLDivElement;
  }

  private setupEventListeners(): void {
    this.lengthSlider.addEventListener('input', this.onLengthInput);
    this.generateBtn.addEventListener('click', this.onGenerateClick);
    this.copyBtn.addEventListener('click', this.onCopyClick);

    // Keyboard shortcuts
    this.addEventListener('keydown', this.onKeyDownHandler);
  }

  private removeEventListeners(): void {
    this.lengthSlider.removeEventListener('input', this.onLengthInput);
    this.generateBtn.removeEventListener('click', this.onGenerateClick);
    this.copyBtn.removeEventListener('click', this.onCopyClick);
    this.removeEventListener('keydown', this.onKeyDownHandler);
  }

  private handleLengthChange(e: Event): void {
    const target = e.target as HTMLInputElement;
    this.lengthValue.textContent = target.value;
    this.setAttribute('length', target.value);
  }

  private handleKeyDown(e: KeyboardEvent): void {
    // Ctrl/Cmd + G: Generate
    if ((e.ctrlKey || e.metaKey) && e.key === 'g') {
      e.preventDefault();
      this.generate();
    }
    // Ctrl/Cmd + C: Copy (when password field focused)
    if ((e.ctrlKey || e.metaKey) && e.key === 'c' && this.password) {
      if (document.activeElement === this.passwordOutput) {
        this.copyToClipboard();
      }
    }
  }

  private syncAttributesToUI(): void {
    if (!this.lengthSlider || !this.lengthValue) {
      return;
    }

    // Sync length
    const length = parseInt(this.getAttribute('length') ?? '16', 10);
    this.lengthSlider.value = String(length);
    this.lengthValue.textContent = String(length);

    // Sync checkboxes
    if (!this.uppercaseCheckbox || !this.lowercaseCheckbox || !this.numbersCheckbox || !this.symbolsCheckbox) {
      return;
    }
    this.uppercaseCheckbox.checked = this.getAttribute('include-uppercase') !== 'false';
    this.lowercaseCheckbox.checked = this.getAttribute('include-lowercase') !== 'false';
    this.numbersCheckbox.checked = this.getAttribute('include-numbers') !== 'false';
    this.symbolsCheckbox.checked = this.getAttribute('include-symbols') !== 'false';
  }

  private getOptions(): PasswordGeneratorOptions {
    return {
      length: parseInt(this.lengthSlider.value, 10),
      includeUppercase: this.uppercaseCheckbox.checked,
      includeLowercase: this.lowercaseCheckbox.checked,
      includeNumbers: this.numbersCheckbox.checked,
      includeSymbols: this.symbolsCheckbox.checked,
      excludeAmbiguous: false,
    };
  }

  private announce(message: string): void {
    this.srAnnouncements.textContent = message;
    // Clear after announcement
    setTimeout(() => {
      this.srAnnouncements.textContent = '';
    }, 1000);
  }

  /**
   * Generate a new password
   * Public method that can be called programmatically
   */
  public generate(): void {
    try {
      const options = this.getOptions();
      const result = generatePassword(options);

      this.password = result.password;
      this.passwordOutput.value = this.password;
      this.copyBtn.disabled = false;

      // Update info display
      this.strengthDisplay.textContent = result.strength;
      this.strengthDisplay.className = `strength-${result.strength}`;
      this.entropyDisplay.textContent = `${result.entropy.toFixed(1)} bits`;

      // Announce to screen readers
      this.announce(`Password generated. Strength: ${result.strength}. ${result.entropy.toFixed(0)} bits of entropy.`);

      // Dispatch custom event
      this.dispatchEvent(
        new CustomEvent('password-generated', {
          detail: { ...result },
          bubbles: true,
          composed: true,
        })
      );

      // Focus password field for easy copying
      this.passwordOutput.focus();
      this.passwordOutput.select();
    } catch (error) {
      console.error('Failed to generate password:', error);
      this.announce('Failed to generate password. Please try again.');
    }
  }

  /**
   * Copy password to clipboard
   * Public method that can be called programmatically
   */
  public async copyToClipboard(): Promise<void> {
    if (!this.password) {
      return;
    }

    try {
      await navigator.clipboard.writeText(this.password);
      
      // Visual feedback
      const originalText = this.copyBtn.textContent;
      this.copyBtn.textContent = 'Copied!';
      this.copyBtn.style.background = '#4CAF50';

      setTimeout(() => {
        this.copyBtn.textContent = originalText;
        this.copyBtn.style.background = '';
      }, 2000);

      // Announce to screen readers
      this.announce('Password copied to clipboard');

      // Dispatch custom event
      this.dispatchEvent(
        new CustomEvent('password-copied', {
          detail: { password: this.password },
          bubbles: true,
          composed: true,
        })
      );
    } catch (error) {
      console.error('Failed to copy password:', error);
      this.announce('Failed to copy password');
    }
  }

  /**
   * Get the current password
   */
  public getPassword(): string {
    return this.password;
  }

  /**
   * Clear the current password
   */
  public clear(): void {
    this.password = '';
    this.passwordOutput.value = '';
    this.copyBtn.disabled = true;
    this.strengthDisplay.textContent = '-';
    this.entropyDisplay.textContent = '-';
    this.announce('Password cleared');
  }
}

// Register the custom element
if (!customElements.get('password-generator')) {
  customElements.define('password-generator', PasswordGeneratorElement);
}

// Export for TypeScript
declare global {
  interface HTMLElementTagNameMap {
    'password-generator': PasswordGeneratorElement;
  }
}
