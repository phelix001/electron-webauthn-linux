# electron-webauthn-linux

WebAuthn/FIDO2 passkey support for Electron apps on Linux. Zero npm dependencies.

Chromium on Linux has no platform authenticator — `navigator.credentials.create()` and `.get()` silently fail. This library fixes that by routing WebAuthn calls through a native Rust backend (1Password's passkey-rs) for software passkeys, with optional hardware FIDO2 USB key support via libfido2.

## How It Works

```
Web Page (navigator.credentials.create / .get)
    ↓  monkey-patched
Injected Page Script
    ↓  IPC
Preload Bridge (contextBridge)
    ↓  ipcRenderer.invoke
Main Process IPC Handlers
    ↓
AuthenticatorManager
    ├─ Software Backend (passkey-rs → SQLite)
    └─ Hardware Backend (fido2-tools CLI)
```

1. A page script overrides `navigator.credentials.create()` and `.get()`
2. Calls are serialized and sent to the main process via IPC
3. The main process delegates to the appropriate authenticator backend
4. Responses are reconstructed as proper `PublicKeyCredential` objects in the page

## Installation

```bash
npm install electron-webauthn-linux
```

**Requirements:**
- Linux (x86_64 or aarch64)
- Node.js >= 18.0.0
- Electron >= 25.0.0
- For hardware USB keys: `libfido2` and `fido2-tools` system packages

## Quick Start

### Main Process

```javascript
const { app, BrowserWindow } = require('electron');
const { setupWebAuthn } = require('electron-webauthn-linux');
const { setupWebAuthnBridge, webauthnPageScript } = require('electron-webauthn-linux/dist/preload');

app.whenReady().then(async () => {
  // 1. Initialize the authenticator backends
  await setupWebAuthn({
    storagePath: app.getPath('userData'),  // where to store the SQLite credential DB
    enableHardwareKeys: true,              // probe for USB FIDO2 devices
  });

  // 2. Create your BrowserWindow
  const win = new BrowserWindow({
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
    },
  });

  // 3. Inject the page script after navigation
  win.webContents.on('did-finish-load', () => {
    win.webContents.executeJavaScript(webauthnPageScript);
  });

  win.loadURL('https://webauthn.io');
});
```

### Preload Script

```javascript
const { setupWebAuthnBridge } = require('electron-webauthn-linux/dist/preload');

// Exposes window.electronWebAuthn with create/get/hasCredentials methods
setupWebAuthnBridge();
```

## API

### Main Process Exports

```typescript
import {
  setupWebAuthn,
  teardownWebAuthn,
  getAuthenticatorManager,
  hasStoredCredentials,
} from 'electron-webauthn-linux';
```

| Function | Description |
|----------|-------------|
| `setupWebAuthn(options?)` | Initialize backends and register IPC handlers. Call once at app startup. |
| `teardownWebAuthn()` | Remove IPC handlers and clean up. |
| `getAuthenticatorManager()` | Get the `AuthenticatorManager` instance (or `null` if not initialized). |
| `hasStoredCredentials(rpId?)` | Check if any passkeys are stored, optionally filtered by relying party ID. |

#### `SetupOptions`

```typescript
{
  storagePath?: string;         // Directory for the SQLite credential database
                                // Default: app.getPath('userData')

  enableHardwareKeys?: boolean; // Whether to probe for hardware FIDO2 USB devices
                                // Default: true
}
```

### Preload Exports

```typescript
import {
  setupWebAuthnBridge,
  getWebAuthnPageScript,
  webauthnPageScript,
} from 'electron-webauthn-linux/dist/preload';
```

| Export | Description |
|--------|-------------|
| `setupWebAuthnBridge()` | Register the IPC bridge on `window.electronWebAuthn` via `contextBridge`. Call in your preload script. |
| `webauthnPageScript` | String of JavaScript to inject into page context. Patches `navigator.credentials`. |
| `getWebAuthnPageScript()` | Returns the page script string (same as above). |

### IPC Channels

These are registered automatically by `setupWebAuthn()`:

| Channel | Direction | Purpose |
|---------|-----------|---------|
| `webauthn:create` | renderer → main | Credential registration |
| `webauthn:get` | renderer → main | Authentication / assertion |
| `webauthn:hasCredentials` | renderer → main | Check if credentials exist for an RP |

## Authenticator Backends

### Software (passkey-rs)

The default backend. Uses 1Password's [passkey-rs](https://github.com/nickel-org/nickel.rs) Rust crates compiled as a native Node addon via napi-rs.

- Credentials stored in a local SQLite database
- EC2 (NIST P-256) keys, COSE algorithm -7
- CBOR/COSE serialized key material
- Supports discoverable (resident) credentials
- User verification always reports `true` (no biometric hardware on Linux)

**Storage location:** `{storagePath}/webauthn_credentials.db`

### Hardware (fido2-tools)

Optional backend for USB FIDO2 security keys (YubiKey, SoloKey, etc.).

Requires system packages:
```bash
# Debian/Ubuntu
sudo apt install libfido2-dev fido2-tools

# Fedora
sudo dnf install libfido2-devel fido2-tools

# Arch
sudo pacman -S libfido2
```

The backend discovers connected devices via `fido2-token -L` and delegates operations to `fido2-cred` (registration) and `fido2-assert` (authentication).

## Browser Compatibility Patches

The injected page script applies several patches to make WebAuthn work across sites:

- **`navigator.credentials.create/get`** — Intercepted and routed through the native backend
- **`PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`** — Returns `true`
- **`PublicKeyCredential.isConditionalMediationAvailable()`** — Returns `false`
- **`navigator.userAgentData`** — Adds "Google Chrome" brand entry (required by Google's WebAuthn implementation)

## Webview Support

For `<webview>` tags, inject the bridge and page script via the webview's preload and `executeJavaScript`:

```javascript
const webview = document.querySelector('webview');

webview.addEventListener('did-finish-load', () => {
  webview.executeJavaScript(webauthnPageScript);
});
```

See `examples/basic-webview/` for a complete working example.

## Project Structure

```
src/
├── index.ts                    # Main entry — setupWebAuthn(), exports
├── preload.ts                  # Preload bridge + page injection script
├── authenticators/
│   ├── types.ts                # AuthenticatorBackend interface
│   ├── passkey-rs.ts           # Software backend (Rust native addon)
│   └── hardware.ts             # Hardware backend (fido2-tools CLI)
├── main/
│   ├── authenticator-manager.ts  # Backend discovery and delegation
│   ├── ipc-handlers.ts          # IPC channel registration
│   └── dialog.ts                # Authenticator selection UI
├── helpers/
│   ├── serialization.ts        # Base64url encode/decode
│   ├── client-data.ts          # ClientDataJSON generation
│   └── credential.ts           # Response object reconstruction
└── native/
    ├── Cargo.toml              # Rust crate config
    └── src/
        ├── lib.rs              # napi-rs JS bindings
        ├── authenticator.rs    # WebAuthn backend wrapper
        └── storage.rs          # SQLite credential store
```

## Building from Source

```bash
# Install dependencies
npm install

# Build everything (Rust native addon + TypeScript)
npm run build

# Or build separately
npm run build:rs        # Rust native addon (release)
npm run build:rs:debug  # Rust native addon (debug)
npm run build:ts        # TypeScript compilation

# Watch mode for TypeScript
npm run dev

# Run tests
npm test
```

**Rust toolchain required** for building the native addon. Install via [rustup](https://rustup.rs/).

## Running the Example

```bash
cd examples/basic-webview
npx electron main.js
```

Opens a simple browser pointed at webauthn.io where you can test passkey registration and authentication.

## How Credentials Are Stored

The software backend stores credentials in SQLite with this schema:

| Column | Type | Description |
|--------|------|-------------|
| `id` | BLOB (PK) | Credential ID |
| `rp_id` | TEXT | Relying party identifier |
| `user_handle` | BLOB | WebAuthn user handle |
| `username` | TEXT | User name |
| `user_display` | TEXT | Display name |
| `key_cbor` | BLOB | CBOR-serialized COSE public/private key |
| `counter` | INTEGER | Signature counter |
| `created_at` | INTEGER | Unix timestamp |

Credentials are indexed by `rp_id` for fast lookups during authentication.

## License

Apache-2.0
