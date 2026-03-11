/**
 * Minimal Electron app demonstrating electron-webauthn-linux.
 *
 * Usage:
 *   cd examples/basic-webview
 *   npx electron main.js
 *
 * This loads webauthn.io in a webview with passkey support enabled.
 */

const { app, BrowserWindow, session } = require('electron');
const path = require('path');

// In a real app you'd do:
//   const { setupWebAuthn, getWebAuthnPageScript } = require('electron-webauthn-linux');
// For this example, we load from the parent package:
const { setupWebAuthn, getWebAuthnPageScript } = require('../../dist/index');

let mainWindow;

async function createWindow() {
  // Set up WebAuthn before creating windows
  await setupWebAuthn({
    storagePath: path.join(app.getPath('userData'), 'webauthn-example'),
    enableHardwareKeys: true,
  });

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      webviewTag: true,
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  // Inject the webview preload before it attaches (sets up contextBridge IPC)
  mainWindow.webContents.on('will-attach-webview', (_event, webPreferences, _params) => {
    webPreferences.preload = path.join(__dirname, 'preload.js');
    console.log('[WebAuthn] Setting webview preload:', webPreferences.preload);
  });

  // Inject WebAuthn page script into webview sessions (patches navigator.credentials)
  mainWindow.webContents.on('did-attach-webview', (_event, webviewContents) => {
    // Forward webview console messages to main process stdout
    webviewContents.on('console-message', (_e, level, message, line, sourceId) => {
      const prefix = ['LOG', 'WARN', 'ERR'][level] || 'LOG';
      console.log(`[webview:${prefix}] ${message}`);
    });

    webviewContents.on('did-finish-load', () => {
      console.log('[WebAuthn] Webview finished loading, injecting page script...');
      const pageScript = getWebAuthnPageScript();
      webviewContents.executeJavaScript(pageScript)
        .then((result) => {
          console.log('[WebAuthn] Page script injected successfully');
        })
        .catch((err) => {
          console.error('[WebAuthn] Failed to inject page script:', err.message);
        });
    });
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  app.quit();
});
