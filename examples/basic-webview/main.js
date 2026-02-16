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

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  // Inject WebAuthn page script into webview sessions
  mainWindow.webContents.on('did-attach-webview', (_event, webviewContents) => {
    webviewContents.on('did-finish-load', () => {
      const pageScript = getWebAuthnPageScript();
      webviewContents.executeJavaScript(pageScript).catch((err) => {
        console.error('[WebAuthn] Failed to inject page script:', err.message);
      });
    });
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  app.quit();
});
