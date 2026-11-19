/**
 * electron-webauthn-linux
 *
 * WebAuthn/passkey support for Electron apps on Linux.
 * Uses 1Password's passkey-rs Rust crates compiled via napi-rs.
 *
 * Usage:
 *   import { setupWebAuthn } from 'electron-webauthn-linux';
 *
 *   // In main process, after app.whenReady()
 *   setupWebAuthn();
 */

import { app } from 'electron';
import { AuthenticatorManager } from './main/authenticator-manager';
import { showPinDialog } from './main/pin-dialog';
import { registerWebAuthnHandlers, removeWebAuthnHandlers } from './main/ipc-handlers';

export { setupWebAuthnBridge, getWebAuthnPageScript, webauthnPageScript } from './preload';
export { AuthenticatorManager } from './main/authenticator-manager';
export type {
  AuthenticatorBackend,
  CreateOptions,
  CreateResult,
  GetOptions,
  GetResult,
} from './authenticators/types';

export interface SetupOptions {
  /** Path to store credentials. Defaults to app.getPath('userData'). */
  storagePath?: string;

  /** Enable hardware FIDO2 key support (requires fido2-tools). Default: true. */
  enableHardwareKeys?: boolean;

  /** Custom FIDO2 PIN prompt for hardware keys. Default: built-in Electron dialog. */
  pinProvider?: (rpId: string) => Promise<string | null>;
}

let manager: AuthenticatorManager | null = null;

/**
 * Set up WebAuthn support in the Electron main process.
 * Call this once after app.whenReady().
 *
 * This:
 * 1. Initializes the passkey-rs native authenticator backend
 * 2. Optionally probes for hardware key support
 * 3. Registers ipcMain.handle('webauthn:create') and ipcMain.handle('webauthn:get')
 *
 * After calling this, inject the preload bridge and page script into your webviews:
 *
 *   // In preload script:
 *   import { setupWebAuthnBridge } from 'electron-webauthn-linux';
 *   setupWebAuthnBridge();
 *
 *   // In webview/page context:
 *   import { getWebAuthnPageScript } from 'electron-webauthn-linux';
 *   webview.executeJavaScript(getWebAuthnPageScript());
 */
export async function setupWebAuthn(options?: SetupOptions): Promise<void> {
  // Only meaningful on Linux; on other platforms, Electron handles WebAuthn natively
  if (process.platform !== 'linux') {
    console.log('[electron-webauthn-linux] Not Linux, skipping WebAuthn setup');
    return;
  }

  const storagePath = options?.storagePath || app.getPath('userData');
  const enableHardwareKeys = options?.enableHardwareKeys ?? true;

  manager = new AuthenticatorManager({
    storagePath,
    enableHardwareKeys,
    pinProvider:
      options?.pinProvider ??
      ((rpId) => {
        const { BrowserWindow } = require('electron') as typeof import('electron');
        return showPinDialog(BrowserWindow.getFocusedWindow(), rpId);
      }),
  });

  await manager.initialize();
  registerWebAuthnHandlers(manager);

  console.log('[electron-webauthn-linux] WebAuthn support initialized');
}

/**
 * Tear down WebAuthn support. Removes IPC handlers.
 */
export function teardownWebAuthn(): void {
  removeWebAuthnHandlers();
  manager = null;
}

/**
 * Get the current AuthenticatorManager instance.
 * Returns null if setupWebAuthn() hasn't been called.
 */
export function getAuthenticatorManager(): AuthenticatorManager | null {
  return manager;
}

/**
 * Check if there are stored credentials, optionally for a specific rpId.
 * If no rpId is provided, checks if there are credentials for ANY site.
 * Returns false if setupWebAuthn() hasn't been called.
 *
 * Use this in the main process to decide whether to inject the WebAuthn
 * page script into webviews. When the store is empty, skip injection so
 * sites use their normal sign-in flow without dead-end passkey prompts.
 */
export async function hasStoredCredentials(rpId?: string): Promise<boolean> {
  if (!manager) return false;
  try {
    const backends = await manager.getAvailableBackendsForGet(rpId || '');
    if (backends.length > 0) return true;
    // If no rpId specified, also check if the software backend has ANY creds
    if (!rpId) {
      const allBackends = await manager.getAvailableBackendsForCreate();
      for (const b of allBackends) {
        // hasCredentials('') should check all rpIds for software backend
        if (b.type === 'software') {
          const has = await b.hasCredentials('');
          if (has) return true;
        }
      }
    }
  } catch {
    // ignore
  }
  return false;
}
