/**
 * Base64url encode/decode and Buffer<->ArrayBuffer utilities.
 * All binary data crosses IPC as base64url-encoded strings.
 */

const BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function base64urlEncode(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  return Buffer.from(bytes).toString('base64url');
}

export function base64urlDecode(str: string): Buffer {
  // Handle both base64url and standard base64
  const normalized = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(normalized, 'base64');
}

export function bufferToArrayBuffer(buf: Buffer): ArrayBuffer {
  // Create a proper ArrayBuffer copy to avoid SharedArrayBuffer issues
  const ab = new ArrayBuffer(buf.byteLength);
  const view = new Uint8Array(ab);
  view.set(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
  return ab;
}

export function arrayBufferToBuffer(ab: ArrayBuffer): Buffer {
  return Buffer.from(ab);
}

/**
 * Serialize PublicKeyCredentialCreationOptions for IPC transport.
 * Converts all ArrayBuffer/Uint8Array fields to base64url strings.
 */
export function serializeCreationOptions(options: any): any {
  const pubKey = options.publicKey || options;

  return {
    rp: {
      id: pubKey.rp?.id,
      name: pubKey.rp?.name || '',
    },
    user: {
      id: base64urlEncode(pubKey.user.id),
      name: pubKey.user.name || '',
      displayName: pubKey.user.displayName || '',
    },
    challenge: base64urlEncode(pubKey.challenge),
    pubKeyCredParams: (pubKey.pubKeyCredParams || []).map((p: any) => ({
      type: p.type,
      alg: p.alg,
    })),
    timeout: pubKey.timeout,
    excludeCredentials: (pubKey.excludeCredentials || []).map((c: any) => ({
      type: c.type,
      id: base64urlEncode(c.id),
      transports: c.transports,
    })),
    authenticatorSelection: pubKey.authenticatorSelection
      ? {
          authenticatorAttachment: pubKey.authenticatorSelection.authenticatorAttachment,
          residentKey: pubKey.authenticatorSelection.residentKey,
          requireResidentKey: pubKey.authenticatorSelection.requireResidentKey,
          userVerification: pubKey.authenticatorSelection.userVerification,
        }
      : undefined,
    attestation: pubKey.attestation,
    extensions: pubKey.extensions,
  };
}

/**
 * Serialize PublicKeyCredentialRequestOptions for IPC transport.
 */
export function serializeRequestOptions(options: any): any {
  const pubKey = options.publicKey || options;

  return {
    challenge: base64urlEncode(pubKey.challenge),
    timeout: pubKey.timeout,
    rpId: pubKey.rpId,
    allowCredentials: (pubKey.allowCredentials || []).map((c: any) => ({
      type: c.type,
      id: base64urlEncode(c.id),
      transports: c.transports,
    })),
    userVerification: pubKey.userVerification,
    extensions: pubKey.extensions,
  };
}
