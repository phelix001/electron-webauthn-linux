/**
 * FIDO2 PIN prompt. Shows a small modal window and resolves with the PIN,
 * or null if the user cancels. The PIN is read via executeJavaScript, never
 * through the window title, so it is not visible in the title bar or taskbar.
 */

import type { BrowserWindow as BrowserWindowType } from 'electron';

export async function showPinDialog(
  parentWindow: BrowserWindowType | null,
  rpId: string,
): Promise<string | null> {
  const { BrowserWindow } = require('electron') as typeof import('electron');

  return new Promise<string | null>((resolve) => {
    let settled = false;
    const win = new BrowserWindow({
      width: 400,
      height: 240,
      parent: parentWindow || undefined,
      modal: !!parentWindow,
      resizable: false,
      minimizable: false,
      maximizable: false,
      title: 'Security Key PIN',
      webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true },
      show: false,
    });
    win.setMenu(null);

    const finish = (pin: string | null) => {
      if (settled) return;
      settled = true;
      clearInterval(poll);
      if (!win.isDestroyed()) win.close();
      resolve(pin);
    };

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:24px;background:#1e1e2e;color:#cdd6f4}
      h2{font-size:16px;margin-bottom:8px} p{font-size:13px;margin-bottom:14px;color:#a6adc8}
      input{width:100%;padding:10px;border:1px solid #45475a;border-radius:6px;background:#313244;color:#cdd6f4;font-size:14px}
      .row{display:flex;gap:8px;margin-top:14px}
      button{flex:1;padding:9px;border:none;border-radius:6px;cursor:pointer;font-size:13px;background:#313244;color:#cdd6f4}
      #ok{background:#89b4fa;color:#1e1e2e}
    </style></head><body>
      <h2>Enter your security key PIN</h2>
      <p>${escapeHtml(rpId)} is asking you to verify with your security key.</p>
      <input id="pin" type="password" autocomplete="off" autofocus>
      <div class="row"><button id="cancel">Cancel</button><button id="ok">OK</button></div>
      <script>
        const pin = document.getElementById('pin');
        const submit = () => { if (pin.value.length > 0) document.title = 'SUBMITTED'; };
        document.getElementById('ok').addEventListener('click', submit);
        document.getElementById('cancel').addEventListener('click', () => { document.title = 'CANCELLED'; });
        pin.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') submit();
          if (e.key === 'Escape') document.title = 'CANCELLED';
        });
      </script></body></html>`;

    win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
    win.once('ready-to-show', () => win.show());

    const poll = setInterval(async () => {
      if (win.isDestroyed()) return;
      const title = win.getTitle();
      if (title === 'CANCELLED') return finish(null);
      if (title === 'SUBMITTED') {
        try {
          const value = await win.webContents.executeJavaScript(
            'document.getElementById("pin").value',
          );
          finish(typeof value === 'string' && value.length > 0 ? value : null);
        } catch {
          finish(null);
        }
      }
    }, 100);

    win.on('closed', () => finish(null));
  });
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
