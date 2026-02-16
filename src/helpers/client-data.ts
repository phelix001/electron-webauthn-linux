/**
 * Generate spec-compliant clientDataJSON.
 *
 * Note: When using passkey-rs via the Client, clientDataJSON is generated
 * internally by the Rust code. This helper is provided for the hardware
 * key backend which doesn't use passkey-rs.
 */

import { base64urlEncode } from './serialization';

export type ClientDataType = 'webauthn.create' | 'webauthn.get';

export interface CollectedClientData {
  type: ClientDataType;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
}

/**
 * Generate clientDataJSON as a UTF-8 encoded string.
 * The JSON key ordering must be exactly as specified in the WebAuthn spec.
 */
export function generateClientDataJSON(
  type: ClientDataType,
  challenge: ArrayBuffer | Uint8Array,
  origin: string,
  crossOrigin?: boolean,
): string {
  const data: CollectedClientData = {
    type,
    challenge: base64urlEncode(challenge),
    origin,
  };

  if (crossOrigin !== undefined) {
    data.crossOrigin = crossOrigin;
  }

  return JSON.stringify(data);
}

/**
 * Generate clientDataJSON and return it as a Buffer.
 */
export function generateClientDataJSONBuffer(
  type: ClientDataType,
  challenge: ArrayBuffer | Uint8Array,
  origin: string,
  crossOrigin?: boolean,
): Buffer {
  return Buffer.from(generateClientDataJSON(type, challenge, origin, crossOrigin), 'utf-8');
}
