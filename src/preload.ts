/**
 * Preload script injection for WebAuthn support.
 *
 * This module provides two things:
 * 1. A preload script string to inject into webview page contexts that monkey-patches
 *    navigator.credentials.create/get
 * 2. An IPC bridge setup function for the preload's isolated world
 */

/**
 * JavaScript string to inject into the page context (via executeJavaScript or inject-js).
 * This monkey-patches navigator.credentials.create/get to route through IPC.
 *
 * The injected code expects `window.electronWebAuthn` to be available (exposed via contextBridge).
 */
export const webauthnPageScript = `
(function() {
  'use strict';

  // Only patch if we're on Linux and the electronWebAuthn bridge exists
  if (!window.electronWebAuthn) return;

  // Save originals (they're stubs on Electron Linux anyway)
  const originalCreate = navigator.credentials?.create?.bind(navigator.credentials);
  const originalGet = navigator.credentials?.get?.bind(navigator.credentials);

  function bufferToBase64url(buffer) {
    if (!buffer) return null;
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer || buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
  }

  function base64urlToBuffer(str) {
    if (!str) return null;
    const padded = str.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function serializeCredentialCreationOptions(options) {
    const pubKey = options.publicKey;
    if (!pubKey) return null;

    return {
      origin: window.location.origin,
      rpId: pubKey.rp?.id || window.location.hostname,
      rpName: pubKey.rp?.name || '',
      userId: bufferToBase64url(pubKey.user.id),
      userName: pubKey.user.name || '',
      userDisplayName: pubKey.user.displayName || '',
      challenge: bufferToBase64url(pubKey.challenge),
      pubKeyCredParams: (pubKey.pubKeyCredParams || []).map(function(p) {
        return { type: p.type, alg: p.alg };
      }),
      excludeCredentials: (pubKey.excludeCredentials || []).map(function(c) {
        return { type: c.type, id: bufferToBase64url(c.id) };
      }),
      authenticatorSelection: pubKey.authenticatorSelection ? {
        residentKey: pubKey.authenticatorSelection.residentKey,
        userVerification: pubKey.authenticatorSelection.userVerification,
        authenticatorAttachment: pubKey.authenticatorSelection.authenticatorAttachment,
      } : undefined,
      timeout: pubKey.timeout,
    };
  }

  function serializeCredentialRequestOptions(options) {
    const pubKey = options.publicKey;
    if (!pubKey) return null;

    return {
      origin: window.location.origin,
      rpId: pubKey.rpId || window.location.hostname,
      challenge: bufferToBase64url(pubKey.challenge),
      allowCredentials: (pubKey.allowCredentials || []).map(function(c) {
        return { type: c.type, id: bufferToBase64url(c.id) };
      }),
      userVerification: pubKey.userVerification,
      timeout: pubKey.timeout,
    };
  }

  function reconstructCreateResponse(result) {
    var rawId = base64urlToBuffer(result.rawId);
    var clientDataJSON = base64urlToBuffer(result.clientDataJson);
    var attestationObject = base64urlToBuffer(result.attestationObject);
    var authenticatorData = base64urlToBuffer(result.authenticatorData);
    var publicKey = result.publicKey ? base64urlToBuffer(result.publicKey) : null;

    var response = {
      clientDataJSON: clientDataJSON,
      attestationObject: attestationObject,
      getAuthenticatorData: function() { return authenticatorData; },
      getPublicKey: function() { return publicKey; },
      getPublicKeyAlgorithm: function() { return result.publicKeyAlgorithm; },
      getTransports: function() { return result.transports || []; },
    };

    if (typeof AuthenticatorAttestationResponse !== 'undefined') {
      Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
    }

    var credential = {
      id: result.credentialId,
      rawId: rawId,
      response: response,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      getClientExtensionResults: function() { return {}; },
    };

    if (typeof PublicKeyCredential !== 'undefined') {
      Object.setPrototypeOf(credential, PublicKeyCredential.prototype);
    }

    return credential;
  }

  function reconstructGetResponse(result) {
    var rawId = base64urlToBuffer(result.rawId);
    var clientDataJSON = base64urlToBuffer(result.clientDataJson);
    var authenticatorData = base64urlToBuffer(result.authenticatorData);
    var signature = base64urlToBuffer(result.signature);
    var userHandle = result.userHandle ? base64urlToBuffer(result.userHandle) : null;

    var response = {
      clientDataJSON: clientDataJSON,
      authenticatorData: authenticatorData,
      signature: signature,
      userHandle: userHandle,
    };

    if (typeof AuthenticatorAssertionResponse !== 'undefined') {
      Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
    }

    var credential = {
      id: result.credentialId,
      rawId: rawId,
      response: response,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      getClientExtensionResults: function() { return {}; },
    };

    if (typeof PublicKeyCredential !== 'undefined') {
      Object.setPrototypeOf(credential, PublicKeyCredential.prototype);
    }

    return credential;
  }

  // Monkey-patch navigator.credentials.create
  if (navigator.credentials) {
    navigator.credentials.create = async function(options) {
      if (!options || !options.publicKey) {
        // Not a WebAuthn request, delegate to original
        if (originalCreate) return originalCreate(options);
        throw new DOMException('Not supported', 'NotSupportedError');
      }

      try {
        var serialized = serializeCredentialCreationOptions(options);
        var result = await window.electronWebAuthn.create(serialized);
        return reconstructCreateResponse(result);
      } catch (err) {
        // Map to proper DOMException using case-insensitive matching
        var msg = (err && err.message) ? err.message.toLowerCase() : '';
        if (msg.includes('cancelled') || msg.includes('notallowed')) {
          throw new DOMException(err.message, 'NotAllowedError');
        }
        if (msg.includes('not supported')) {
          throw new DOMException(err.message, 'NotSupportedError');
        }
        throw new DOMException(
          err?.message || 'WebAuthn operation failed',
          'NotAllowedError'
        );
      }
    };

    // Monkey-patch navigator.credentials.get
    navigator.credentials.get = async function(options) {
      if (!options || !options.publicKey) {
        // Not a WebAuthn request, delegate to original
        if (originalGet) return originalGet(options);
        throw new DOMException('Not supported', 'NotSupportedError');
      }

      // Check if we have any stored credentials for this site.
      // If not, reject immediately so the site skips to password/other methods.
      // Do NOT fall through to the original handler - on Electron Linux it hangs
      // (Chromium shows its own passkey UI that never completes).
      var rpId = options.publicKey.rpId || window.location.hostname;
      if (window.electronWebAuthn.hasCredentials) {
        try {
          var hasCreds = await window.electronWebAuthn.hasCredentials(rpId);
          if (!hasCreds) {
            console.log('[electron-webauthn-linux] No stored credentials for ' + rpId + ', rejecting immediately');
            throw new DOMException('No credentials available for this site.', 'NotAllowedError');
          }
        } catch (checkErr) {
          if (checkErr instanceof DOMException) throw checkErr;
          console.warn('[electron-webauthn-linux] hasCredentials check failed:', checkErr?.message);
          throw new DOMException('No credentials available for this site.', 'NotAllowedError');
        }
      }

      try {
        var serialized = serializeCredentialRequestOptions(options);
        var result = await window.electronWebAuthn.get(serialized);
        return reconstructGetResponse(result);
      } catch (err) {
        // Map to proper DOMException using case-insensitive matching
        var msg = (err && err.message) ? err.message.toLowerCase() : '';
        console.warn('[electron-webauthn-linux] credentials.get failed:', err?.message);
        if (msg.includes('cancelled') || msg.includes('notallowed')) {
          throw new DOMException(err.message, 'NotAllowedError');
        }
        if (msg.includes('notfound') || msg.includes('not found') || msg.includes('nocredentials') || msg.includes('no passkeys')) {
          throw new DOMException(err.message, 'NotAllowedError');
        }
        throw new DOMException(
          err?.message || 'WebAuthn operation failed',
          'NotAllowedError'
        );
      }
    };
  }

  // Always report platform authenticator as available.
  // This is needed for sites to offer passkey creation, and some sites
  // (like Google) use it as a security signal - returning false can trigger
  // "browser not secure" errors. The hasCredentials check in credentials.get()
  // handles the case where there are no stored credentials.
  if (typeof PublicKeyCredential !== 'undefined') {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async function() {
      return true;
    };

    // Patch isConditionalMediationAvailable if it exists
    if (PublicKeyCredential.isConditionalMediationAvailable) {
      PublicKeyCredential.isConditionalMediationAvailable = async function() {
        return false; // We don't support conditional UI yet
      };
    }
  }

  console.log('[electron-webauthn-linux] WebAuthn support enabled');
})();
`;

/**
 * Setup the IPC bridge in a preload script context.
 * Call this from your Electron preload script.
 *
 * Usage in preload.ts:
 *   import { setupWebAuthnBridge } from 'electron-webauthn-linux/preload';
 *   setupWebAuthnBridge();
 */
export function setupWebAuthnBridge(): void {
  const { contextBridge, ipcRenderer } = require('electron');

  contextBridge.exposeInMainWorld('electronWebAuthn', {
    create: (options: any) => ipcRenderer.invoke('webauthn:create', options),
    get: (options: any) => ipcRenderer.invoke('webauthn:get', options),
  });
}

/**
 * Get the webauthn page injection script as a string.
 * This is useful for injecting into webviews via executeJavaScript.
 */
export function getWebAuthnPageScript(): string {
  return webauthnPageScript;
}
