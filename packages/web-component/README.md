# password-generator-element

Web Component for password generation - framework agnostic, works anywhere.

[![npm version](https://img.shields.io/npm/v/password-generator-element.svg)](https://www.npmjs.com/package/password-generator-element)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/iAn-P1nt0/password-kit/blob/main/LICENSE)

## Features

✅ **Framework Agnostic** - Works with React, Vue, Angular, or vanilla JS  
✅ **Shadow DOM** - Fully encapsulated styles  
✅ **Accessible** - WCAG 2.1 Level AA compliant  
✅ **Keyboard Shortcuts** - Ctrl+G to generate, native copy support  
✅ **Customizable** - Configurable via attributes or JavaScript  
✅ **Events** - Custom events for integration  
✅ **Dark Mode** - Automatic dark mode support  
✅ **TypeScript** - Full type definitions  
✅ **Small Bundle** - ~8KB gzipped  

## Installation

```bash
npm install password-generator-element
```

```bash
yarn add password-generator-element
```

```bash
pnpm add password-generator-element
```

## Quick Start

### Vanilla HTML

```html
<!DOCTYPE html>
<html>
<head>
  <script type="module">
    import 'password-generator-element';
  </script>
</head>
<body>
  <password-generator></password-generator>
</body>
</html>
```

### With Options

```html
<password-generator 
  length="20"
  include-uppercase="true"
  include-lowercase="true"
  include-numbers="true"
  include-symbols="true"
  auto-generate="false">
</password-generator>
```

### React

```tsx
import 'password-generator-element';

function App() {
  const handleGenerated = (e: CustomEvent) => {
    console.log('Password generated:', e.detail.password);
    console.log('Strength:', e.detail.strength);
    console.log('Entropy:', e.detail.entropy);
  };

  return (
    <password-generator
      length="24"
      onPasswordGenerated={handleGenerated}
    />
  );
}
```

### Vue 3

```vue
<template>
  <password-generator 
    length="20"
    @password-generated="handleGenerated"
  />
</template>

<script setup>
import 'password-generator-element';

const handleGenerated = (e) => {
  console.log('Password:', e.detail.password);
};
</script>
```

### Angular

```typescript
// app.module.ts
import { CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import 'password-generator-element';

@NgModule({
  schemas: [CUSTOM_ELEMENTS_SCHEMA]
})
export class AppModule {}

// component.html
<password-generator 
  length="20"
  (password-generated)="onGenerated($event)">
</password-generator>
```

## API Reference

### Attributes

All attributes are optional:

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `length` | number | `16` | Password length (8-128) |
| `include-uppercase` | boolean | `true` | Include uppercase letters |
| `include-lowercase` | boolean | `true` | Include lowercase letters |
| `include-numbers` | boolean | `true` | Include numbers |
| `include-symbols` | boolean | `true` | Include symbols |
| `auto-generate` | boolean | `false` | Generate on mount |

### Properties

Access via JavaScript:

```javascript
const generator = document.querySelector('password-generator');

// Get current password
const password = generator.getPassword();

// Generate new password
generator.generate();

// Copy to clipboard
await generator.copyToClipboard();

// Clear password
generator.clear();
```

### Methods

#### `generate(): void`
Generate a new password with current options.

```javascript
generator.generate();
```

#### `copyToClipboard(): Promise<void>`
Copy current password to clipboard.

```javascript
await generator.copyToClipboard();
```

#### `getPassword(): string`
Get the current password value.

```javascript
const password = generator.getPassword();
```

#### `clear(): void`
Clear the current password.

```javascript
generator.clear();
```

### Events

Listen to custom events for integration:

#### `password-generated`
Fired when a new password is generated.

```javascript
generator.addEventListener('password-generated', (e) => {
  console.log(e.detail.password);   // "Kp9$mNz2@Qw5Xr8T"
  console.log(e.detail.strength);   // "very-strong"
  console.log(e.detail.entropy);    // 95.2
});
```

**Detail Object:**
```typescript
{
  password: string;
  strength: 'weak' | 'medium' | 'strong' | 'very-strong';
  entropy: number;
}
```

#### `password-copied`
Fired when password is copied to clipboard.

```javascript
generator.addEventListener('password-copied', (e) => {
  console.log('Copied:', e.detail.password);
});
```

## Keyboard Shortcuts

- **Ctrl+G** / **Cmd+G** - Generate new password
- **Ctrl+C** / **Cmd+C** - Copy password (when input focused)
- **Tab** - Navigate controls
- **Space/Enter** - Activate buttons

## Styling

The component uses Shadow DOM, so styles are encapsulated. Customize via CSS custom properties:

```css
password-generator {
  /* Override component styles */
  --primary-color: #4CAF50;
  --secondary-color: #2196F3;
  --border-color: #e0e0e0;
  --border-radius: 8px;
  --padding: 1.5rem;
}
```

## Accessibility

- ✅ WCAG 2.1 Level AA compliant
- ✅ Full keyboard navigation
- ✅ Screen reader announcements
- ✅ ARIA labels and live regions
- ✅ Focus management
- ✅ High contrast support

## Advanced Usage

### Programmatic Control

```javascript
const generator = document.querySelector('password-generator');

// Generate with specific length
generator.setAttribute('length', '32');
generator.generate();

// Listen for generation
generator.addEventListener('password-generated', (e) => {
  // Auto-copy strong passwords
  if (e.detail.entropy > 80) {
    generator.copyToClipboard();
  }
});

// Validate before submission
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = generator.getPassword();
  
  if (!password) {
    alert('Please generate a password');
    return;
  }
  
  // Proceed with form submission
});
```

### Dynamic Options

```javascript
// Create element dynamically
const generator = document.createElement('password-generator');
generator.setAttribute('length', '24');
generator.setAttribute('auto-generate', 'true');
document.body.appendChild(generator);

// Update options
generator.addEventListener('click', () => {
  const length = Math.floor(Math.random() * (32 - 16 + 1)) + 16;
  generator.setAttribute('length', String(length));
  generator.generate();
});
```

### Integration with Forms

```html
<form id="signup-form">
  <label for="username">Username</label>
  <input type="text" id="username" required />
  
  <label>Password</label>
  <password-generator id="pwd-gen" auto-generate="true"></password-generator>
  
  <input type="hidden" name="password" id="password-input" />
  
  <button type="submit">Sign Up</button>
</form>

<script type="module">
  import '@trustvault/password-generator-element';
  
  const form = document.getElementById('signup-form');
  const generator = document.getElementById('pwd-gen');
  const hiddenInput = document.getElementById('password-input');
  
  // Sync password to hidden input
  generator.addEventListener('password-generated', (e) => {
    hiddenInput.value = e.detail.password;
  });
  
  // Validate on submit
  form.addEventListener('submit', (e) => {
    const password = generator.getPassword();
    if (!password) {
      e.preventDefault();
      alert('Please generate a password');
    }
  });
</script>
```

## TypeScript Support

Full TypeScript definitions included:

```typescript
import type { PasswordGeneratorElement } from 'password-generator-element';

const generator = document.querySelector('password-generator') as PasswordGeneratorElement;

generator.generate();
const password: string = generator.getPassword();

// Event types
generator.addEventListener('password-generated', (e: CustomEvent<{
  password: string;
  strength: string;
  entropy: number;
}>) => {
  console.log(e.detail.password);
});
```

## Browser Compatibility

- Chrome 67+ (Custom Elements V1)
- Firefox 63+
- Safari 10.1+
- Edge 79+

For older browsers, use polyfills:
```html
<script src="https://unpkg.com/@webcomponents/webcomponentsjs@2.8.0/webcomponents-loader.js"></script>
```

## Bundle Size

- Minified: ~15 KB
- Minified + Gzipped: ~8 KB

## Security

- Uses Web Crypto API for secure random generation
- No external network requests
- No tracking or analytics
- Open source and auditable

## Examples

See the [examples directory](https://github.com/iAn-P1nt0/password-kit/tree/main/examples) for more:

- Basic usage
- Framework integrations (React, Vue, Angular)
- Custom styling
- Form integration
- Password manager UI

## Related Packages

- [password-kit](https://www.npmjs.com/package/password-kit) - Core library
- [password-kit-react](https://www.npmjs.com/package/password-kit-react) - React hooks
- [password-kit-vue](https://www.npmjs.com/package/password-kit-vue) - Vue composables

## License

Apache-2.0

## Contributing

See [CONTRIBUTING.md](https://github.com/iAn-P1nt0/password-kit/blob/main/CONTRIBUTING.md)

## Support

- 📖 [Documentation](https://github.com/iAn-P1nt0/password-kit)
- 🐛 [Issue Tracker](https://github.com/iAn-P1nt0/password-kit/issues)
- 💬 [Discussions](https://github.com/iAn-P1nt0/password-kit/discussions)
