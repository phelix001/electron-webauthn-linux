/**
 * Webview preload script — sets up the IPC bridge for WebAuthn.
 *
 * NOTE: Cannot require() arbitrary modules in sandboxed preloads.
 * Must inline the contextBridge setup using only 'electron' imports.
 */
const { contextBridge, ipcRenderer } = require('electron');

console.log('[electron-webauthn-linux] Preload script running');

try {
  contextBridge.exposeInMainWorld('electronWebAuthn', {
    create: (options) => ipcRenderer.invoke('webauthn:create', options),
    get: (options) => ipcRenderer.invoke('webauthn:get', options),
    hasCredentials: (rpId) => ipcRenderer.invoke('webauthn:hasCredentials', rpId),
  });
  console.log('[electron-webauthn-linux] contextBridge exposed electronWebAuthn');
} catch (err) {
  console.error('[electron-webauthn-linux] Failed to expose contextBridge:', err);
}
