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
