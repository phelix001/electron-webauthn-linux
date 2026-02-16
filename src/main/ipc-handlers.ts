/**
 * IPC handlers for WebAuthn operations.
 * Registers ipcMain.handle('webauthn:create') and ipcMain.handle('webauthn:get').
 */

import { ipcMain, BrowserWindow } from 'electron';
import type { AuthenticatorManager } from './authenticator-manager';
import type { CreateOptions, GetOptions } from '../authenticators/types';
import { showAuthenticatorDialog } from './dialog';

/**
 * Register WebAuthn IPC handlers on the main process.
 */
export function registerWebAuthnHandlers(manager: AuthenticatorManager): void {
  ipcMain.handle(
    'webauthn:create',
    async (event, serializedOptions: CreateOptions) => {
      // Extract the origin from the sender for security
      const senderOrigin = event.senderFrame?.origin || event.sender.getURL();
      const origin = serializedOptions.origin || senderOrigin;

      const options: CreateOptions = {
        ...serializedOptions,
        origin,
      };

      // Check available backends
      const backends = await manager.getAvailableBackendsForCreate();

      if (backends.length === 0) {
        throw new Error('No WebAuthn authenticator available');
      }

      // Show selection dialog if multiple backends
      let selectedBackend = backends[0];
      if (backends.length > 1) {
        const parentWindow = BrowserWindow.fromWebContents(event.sender);
        const chosen = await showAuthenticatorDialog(
          parentWindow,
          backends,
          'create',
        );
        if (!chosen) {
          throw new DOMException('The operation was cancelled.', 'NotAllowedError');
        }
        selectedBackend = chosen;
      }

      return manager.createCredential(options, selectedBackend);
    },
  );

  ipcMain.handle(
    'webauthn:get',
    async (event, serializedOptions: GetOptions) => {
      const senderOrigin = event.senderFrame?.origin || event.sender.getURL();
      const origin = serializedOptions.origin || senderOrigin;

      const options: GetOptions = {
        ...serializedOptions,
        origin,
      };

      // Check available backends that have matching credentials
      const backends = await manager.getAvailableBackendsForGet(
        options.rpId,
        options.allowCredentials?.map((c) => c.id),
      );

      if (backends.length === 0) {
        // No backend has matching credentials.
        // Only fall back to hardware backends (which can't report credentials
        // upfront), not software backends that already confirmed they have none.
        const allBackends = await manager.getAvailableBackendsForCreate();
        const hardwareBackends = allBackends.filter(
          (b) => b.type === 'hardware',
        );

        if (hardwareBackends.length === 0) {
          // No hardware keys available and software store is empty - fail fast
          throw new Error(
            'NoCredentials: No passkeys found for this site.',
          );
        }

        // Only try hardware backends as a fallback
        let selectedBackend = hardwareBackends[0];
        if (hardwareBackends.length > 1) {
          const parentWindow = BrowserWindow.fromWebContents(event.sender);
          const chosen = await showAuthenticatorDialog(
            parentWindow,
            hardwareBackends,
            'get',
          );
          if (!chosen) {
            throw new Error('NotAllowed: The operation was cancelled.');
          }
          selectedBackend = chosen;
        }

        return manager.getAssertion(options, selectedBackend);
      }

      // Show selection dialog if multiple backends have matching credentials
      let selectedBackend = backends[0];
      if (backends.length > 1) {
        const parentWindow = BrowserWindow.fromWebContents(event.sender);
        const chosen = await showAuthenticatorDialog(
          parentWindow,
          backends,
          'get',
        );
        if (!chosen) {
          throw new DOMException('The operation was cancelled.', 'NotAllowedError');
        }
        selectedBackend = chosen;
      }

      return manager.getAssertion(options, selectedBackend);
    },
  );

  ipcMain.handle(
    'webauthn:hasCredentials',
    async (_event, rpId: string) => {
      const backends = await manager.getAvailableBackendsForGet(rpId);
      return backends.length > 0;
    },
  );
}

/**
 * Remove the WebAuthn IPC handlers.
 */
export function removeWebAuthnHandlers(): void {
  ipcMain.removeHandler('webauthn:create');
  ipcMain.removeHandler('webauthn:get');
  ipcMain.removeHandler('webauthn:hasCredentials');
}
