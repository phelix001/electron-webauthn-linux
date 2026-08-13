/**
 * Authenticator selection dialog.
 * Shows a minimal Electron BrowserWindow when multiple authenticators are available.
 */

import type { BrowserWindow as BrowserWindowType } from 'electron';
import type { AuthenticatorBackend } from '../authenticators/types';

let dialogWindow: BrowserWindowType | null = null;

export interface HardwareKeyDialog {
  readonly signal: AbortSignal;
  getPin(previousError?: 'pin-invalid'): Promise<string | null>;
  close(): void;
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

export function showHardwareKeyDialog(
  parentWindow: BrowserWindowType | null,
  operation: 'create' | 'get',
  rpId: string,
  requiresPin: boolean,
): HardwareKeyDialog {
  const { BrowserWindow } = require('electron') as typeof import('electron');
  const abortController = new AbortController();
  let finished = false;
  let pinResolved = false;
  let resolvePin: (pin: string | null) => void = () => {};

  const hardwareWindow = new BrowserWindow({
    width: 420,
    height: requiresPin ? 260 : 210,
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
    operation === 'create' ? 'Create a passkey' : 'Sign in with your passkey';
  const escapedRpId = escapeHtml(rpId);

  const pinForm = requiresPin
    ? `
      <form id="pin-form">
        <label for="pin">Security key PIN</label>
        <input id="pin" type="password" autocomplete="off" autofocus />
        <button class="primary" type="submit">Continue</button>
      </form>
    `
    : '';

  const initialStatus = requiresPin
    ? 'Enter your security key PIN. You will be prompted to touch the key next.'
    : 'Touch your security key when it starts flashing.';

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      padding: 24px;
      background: #202124;
      color: #f1f3f4;
      user-select: none;
    }
    h2 { font-size: 18px; font-weight: 600; margin-bottom: 8px; }
    .rp { font-size: 13px; color: #bdc1c6; margin-bottom: 18px; overflow-wrap: anywhere; }
    .status {
      min-height: 42px;
      margin-bottom: 16px;
      padding: 12px;
      border: 1px solid #5f6368;
      border-radius: 8px;
      background: #292a2d;
      font-size: 14px;
      line-height: 1.3;
    }
    label {
      display: block;
      margin-bottom: 6px;
      color: #bdc1c6;
      font-size: 12px;
      font-weight: 600;
    }
    input {
      width: 100%;
      height: 36px;
      margin-bottom: 12px;
      padding: 6px 8px;
      border: 1px solid #5f6368;
      border-radius: 6px;
      background: #171717;
      color: #f1f3f4;
      font-size: 15px;
    }
    .primary {
      width: 100%;
      height: 36px;
      border: 0;
      border-radius: 6px;
      background: #8ab4f8;
      color: #202124;
      cursor: pointer;
      font-size: 14px;
      font-weight: 600;
    }
    .cancel {
      display: block;
      width: 100%;
      height: 32px;
      margin-top: 10px;
      border: 0;
      border-radius: 6px;
      background: transparent;
      color: #bdc1c6;
      cursor: pointer;
      font-size: 13px;
    }
    .cancel:hover { background: #303134; color: #f1f3f4; }
  </style>
</head>
<body>
  <h2>${escapeHtml(operationText)}</h2>
  <div class="rp">${escapedRpId}</div>
  <div class="status" id="status">${escapeHtml(initialStatus)}</div>
  ${pinForm}
  <button class="cancel" id="cancel">Cancel</button>
  <script>
    var submitted = false;
    var form = document.getElementById('pin-form');
    var statusEl = document.getElementById('status');
    var pinInput = document.getElementById('pin');

    window.__showPinPrompt = function(message) {
      submitted = false;
      if (form) form.style.display = '';
      if (pinInput) {
        pinInput.value = '';
        pinInput.focus();
      }
      statusEl.textContent = message || 'Enter your security key PIN.';
    };

    if (form) {
      form.addEventListener('submit', function(event) {
        event.preventDefault();
        if (submitted) return;
        submitted = true;
        var pin = pinInput.value;
        document.title = 'PIN:' + encodeURIComponent(pin);
        form.style.display = 'none';
        statusEl.textContent = 'Touch your security key when it starts flashing.';
      });
    }

    document.getElementById('cancel').addEventListener('click', function() {
      document.title = 'CANCELLED';
    });
  </script>
</body>
</html>`;

  hardwareWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
  hardwareWindow.once('ready-to-show', () => {
    hardwareWindow.show();
  });

  const checkTitle = setInterval(() => {
    if (hardwareWindow.isDestroyed()) {
      clearInterval(checkTitle);
      if (!pinResolved) {
        pinResolved = true;
        resolvePin(null);
      }
      return;
    }

    const title = hardwareWindow.getTitle();
    if (title.startsWith('PIN:')) {
      hardwareWindow.setTitle(operation === 'create' ? 'Create Passkey' : 'Sign In');
      if (!pinResolved) {
        pinResolved = true;
        resolvePin(decodeURIComponent(title.slice(4)));
      }
    } else if (title === 'CANCELLED') {
      clearInterval(checkTitle);
      if (!pinResolved) {
        pinResolved = true;
        resolvePin(null);
      }
      abortController.abort();
      hardwareWindow.close();
    }
  }, 100);

  hardwareWindow.on('closed', () => {
    clearInterval(checkTitle);
    if (!pinResolved) {
      pinResolved = true;
      resolvePin(null);
    }
    if (!finished) abortController.abort();
  });

  return {
    signal: abortController.signal,
    getPin: (previousError?: 'pin-invalid') => {
      if (!requiresPin) return Promise.resolve(null);
      if (hardwareWindow.isDestroyed()) return Promise.resolve(null);

      const message = previousError === 'pin-invalid'
        ? 'Incorrect PIN. Enter your security key PIN again.'
        : 'Enter your security key PIN.';

      pinResolved = false;
      hardwareWindow.webContents.executeJavaScript(
        `window.__showPinPrompt(${JSON.stringify(message)})`,
      ).catch(() => undefined);

      return new Promise<string | null>((resolve) => {
        resolvePin = resolve;
      });
    },
    close: () => {
      finished = true;
      if (!hardwareWindow.isDestroyed()) {
        hardwareWindow.close();
      }
    },
  };
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
