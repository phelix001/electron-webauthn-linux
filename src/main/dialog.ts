/**
 * Authenticator selection dialog.
 * Shows a minimal Electron BrowserWindow when multiple authenticators are available.
 */

import type { BrowserWindow as BrowserWindowType } from 'electron';
import type { AuthenticatorBackend } from '../authenticators/types';

let dialogWindow: BrowserWindowType | null = null;

interface DialogChoice {
  backend: AuthenticatorBackend;
  index: number;
}

/**
 * Show a dialog for the user to select an authenticator.
 * Returns the selected backend, or null if cancelled.
 */
export async function showAuthenticatorDialog(
  parentWindow: BrowserWindowType | null,
  backends: AuthenticatorBackend[],
  operation: 'create' | 'get',
): Promise<AuthenticatorBackend | null> {
  // If only one backend, no need for dialog
  if (backends.length === 1) return backends[0];
  if (backends.length === 0) return null;

  const { BrowserWindow } = require('electron') as typeof import('electron');

  return new Promise<AuthenticatorBackend | null>((resolve) => {
    dialogWindow = new BrowserWindow({
      width: 400,
      height: 300,
      parent: parentWindow || undefined,
      modal: !!parentWindow,
      resizable: false,
      minimizable: false,
      maximizable: false,
      title: operation === 'create' ? 'Create Passkey' : 'Sign In',
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
      },
      show: false,
    });

    const operationText =
      operation === 'create' ? 'Create a new passkey' : 'Sign in with a passkey';

    const backendButtons = backends
      .map(
        (b, i) => `
        <button class="backend-btn" data-index="${i}">
          <span class="icon">${b.type === 'software' ? '🔑' : '🔒'}</span>
          <span class="name">${escapeHtml(b.name)}</span>
        </button>
      `,
      )
      .join('');

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      padding: 24px;
      background: #1e1e2e;
      color: #cdd6f4;
      user-select: none;
    }
    h2 { font-size: 16px; margin-bottom: 16px; color: #cdd6f4; }
    p { font-size: 13px; margin-bottom: 16px; color: #a6adc8; }
    .backend-btn {
      display: flex;
      align-items: center;
      width: 100%;
      padding: 12px 16px;
      margin-bottom: 8px;
      border: 1px solid #45475a;
      border-radius: 8px;
      background: #313244;
      color: #cdd6f4;
      cursor: pointer;
      font-size: 14px;
      transition: background 0.15s;
    }
    .backend-btn:hover { background: #45475a; }
    .backend-btn:active { background: #585b70; }
    .icon { font-size: 20px; margin-right: 12px; }
    .cancel-btn {
      display: block;
      width: 100%;
      margin-top: 12px;
      padding: 8px;
      border: none;
      border-radius: 6px;
      background: transparent;
      color: #a6adc8;
      cursor: pointer;
      font-size: 13px;
    }
    .cancel-btn:hover { color: #cdd6f4; background: #313244; }
  </style>
</head>
<body>
  <h2>${escapeHtml(operationText)}</h2>
  <p>Choose an authenticator:</p>
  ${backendButtons}
  <button class="cancel-btn" id="cancel">Cancel</button>
  <script>
    document.querySelectorAll('.backend-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-index'));
        // Post message back to main process via window title hack
        // (since we have sandbox enabled and no preload)
        document.title = 'SELECTED:' + idx;
      });
    });
    document.getElementById('cancel').addEventListener('click', () => {
      document.title = 'CANCELLED';
    });
  </script>
</body>
</html>`;

    dialogWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);

    dialogWindow.once('ready-to-show', () => {
      dialogWindow?.show();
    });

    // Watch for title changes as our IPC mechanism (sandboxed window)
    const checkTitle = setInterval(() => {
      if (!dialogWindow || dialogWindow.isDestroyed()) {
        clearInterval(checkTitle);
        resolve(null);
        return;
      }

      const title = dialogWindow.getTitle();
      if (title.startsWith('SELECTED:')) {
        clearInterval(checkTitle);
        const idx = parseInt(title.replace('SELECTED:', ''));
        dialogWindow.close();
        dialogWindow = null;
        resolve(backends[idx] || null);
      } else if (title === 'CANCELLED') {
        clearInterval(checkTitle);
        dialogWindow.close();
        dialogWindow = null;
        resolve(null);
      }
    }, 100);

    dialogWindow.on('closed', () => {
      clearInterval(checkTitle);
      dialogWindow = null;
      resolve(null);
    });
  });
}

/**
 * Ask the user to plug in a security key. Resolves true on "Retry", false on cancel/close.
 */
export async function showInsertKeyDialog(
  parentWindow: BrowserWindowType | null,
): Promise<boolean> {
  const { BrowserWindow } = require('electron') as typeof import('electron');

  return new Promise<boolean>((resolve) => {
    const win = new BrowserWindow({
      width: 400,
      height: 220,
      parent: parentWindow || undefined,
      modal: !!parentWindow,
      resizable: false,
      minimizable: false,
      maximizable: false,
      title: 'Insert Security Key',
      webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true },
      show: false,
    });

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
      body { font-family: sans-serif; padding: 24px; background: #1e1e2e; color: #cdd6f4; user-select: none; }
      h2 { font-size: 16px; margin-bottom: 12px; } p { font-size: 13px; color: #a6adc8; margin-bottom: 20px; }
      button { padding: 8px 16px; margin-right: 8px; border: 1px solid #45475a; border-radius: 6px;
        background: #313244; color: #cdd6f4; cursor: pointer; font-size: 13px; }
      button:hover { background: #45475a; }
    </style></head><body>
      <h2>Insert your security key</h2>
      <p>No FIDO2 security key was found. Plug it in, then choose Retry.</p>
      <button id="retry">Retry</button><button id="cancel">Cancel</button>
      <script>
        document.getElementById('retry').addEventListener('click', () => { document.title = 'RETRY'; });
        document.getElementById('cancel').addEventListener('click', () => { document.title = 'CANCELLED'; });
      </script></body></html>`;

    let result = false;
    win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
    win.once('ready-to-show', () => win.show());

    const timer = setInterval(() => {
      if (win.isDestroyed()) return;
      const title = win.getTitle();
      if (title === 'RETRY' || title === 'CANCELLED') {
        result = title === 'RETRY';
        win.close();
      }
    }, 100);

    // Resolves on every exit path (button, window X, destroy).
    win.on('closed', () => {
      clearInterval(timer);
      resolve(result);
    });
  });
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
