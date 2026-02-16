/**
 * Reconstruct PublicKeyCredential objects from IPC response data.
 * Used in renderer/page context where WebAuthn DOM types may be available.
 *
 * Note: The actual reconstruction for webview injection is done inline
 * in the preload.ts page script. This module is provided for direct use
 * in Electron renderer processes that have DOM types available.
 */

import { base64urlDecode, bufferToArrayBuffer } from './serialization';

export interface CreateResult {
  credentialId: string;
  rawId: string;
  attestationObject: string;
  clientDataJson: string;
  type: string;
  authenticatorData: string;
  transports: string[];
  publicKey: string | null;
  publicKeyAlgorithm: number;
}

export interface GetResult {
  credentialId: string;
  rawId: string;
  authenticatorData: string;
  clientDataJson: string;
  signature: string;
  userHandle: string | null;
  type: string;
}

/**
 * Reconstruct a credential-like object from a registration response.
 * Returns a plain object with the correct shape.
 */
export function reconstructCreatedCredential(result: CreateResult): any {
  const rawId = bufferToArrayBuffer(base64urlDecode(result.rawId));
  const clientDataJSON = bufferToArrayBuffer(base64urlDecode(result.clientDataJson));
  const attestationObject = bufferToArrayBuffer(base64urlDecode(result.attestationObject));
  const authenticatorData = bufferToArrayBuffer(base64urlDecode(result.authenticatorData));
  const publicKey = result.publicKey
    ? bufferToArrayBuffer(base64urlDecode(result.publicKey))
    : null;

  const response = {
    clientDataJSON,
    attestationObject,
    getAuthenticatorData: () => authenticatorData,
    getPublicKey: () => publicKey,
    getPublicKeyAlgorithm: () => result.publicKeyAlgorithm,
    getTransports: () => result.transports,
  };

  // Set prototype if available in this context (renderer with DOM types)
  const globalAny = globalThis as any;
  if (globalAny.AuthenticatorAttestationResponse) {
    Object.setPrototypeOf(response, globalAny.AuthenticatorAttestationResponse.prototype);
  }

  const credential = {
    id: result.credentialId,
    rawId,
    response,
    type: result.type,
    authenticatorAttachment: 'platform',
    getClientExtensionResults: () => ({}),
    toJSON: () => ({
      id: result.credentialId,
      rawId: result.rawId,
      type: result.type,
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: result.clientDataJson,
        attestationObject: result.attestationObject,
        authenticatorData: result.authenticatorData,
        transports: result.transports,
        publicKey: result.publicKey,
        publicKeyAlgorithm: result.publicKeyAlgorithm,
      },
      clientExtensionResults: {},
    }),
  };

  if (globalAny.PublicKeyCredential) {
    Object.setPrototypeOf(credential, globalAny.PublicKeyCredential.prototype);
  }

  return credential;
}

/**
 * Reconstruct a credential-like object from an assertion response.
 */
export function reconstructAssertedCredential(result: GetResult): any {
  const rawId = bufferToArrayBuffer(base64urlDecode(result.rawId));
  const clientDataJSON = bufferToArrayBuffer(base64urlDecode(result.clientDataJson));
  const authenticatorData = bufferToArrayBuffer(base64urlDecode(result.authenticatorData));
  const signature = bufferToArrayBuffer(base64urlDecode(result.signature));
  const userHandle = result.userHandle
    ? bufferToArrayBuffer(base64urlDecode(result.userHandle))
    : null;

  const response = {
    clientDataJSON,
    authenticatorData,
    signature,
    userHandle,
  };

  const globalAny = globalThis as any;
  if (globalAny.AuthenticatorAssertionResponse) {
    Object.setPrototypeOf(response, globalAny.AuthenticatorAssertionResponse.prototype);
  }

  const credential = {
    id: result.credentialId,
    rawId,
    response,
    type: result.type,
    authenticatorAttachment: 'platform',
    getClientExtensionResults: () => ({}),
    toJSON: () => ({
      id: result.credentialId,
      rawId: result.rawId,
      type: result.type,
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: result.clientDataJson,
        authenticatorData: result.authenticatorData,
        signature: result.signature,
        userHandle: result.userHandle,
      },
      clientExtensionResults: {},
    }),
  };

  if (globalAny.PublicKeyCredential) {
    Object.setPrototypeOf(credential, globalAny.PublicKeyCredential.prototype);
  }

  return credential;
}
