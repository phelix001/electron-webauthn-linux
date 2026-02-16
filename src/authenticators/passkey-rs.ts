/**
 * passkey-rs native addon backend.
 * Wraps the Rust napi-rs addon that uses 1Password's passkey-rs crates.
 */

import type {
  AuthenticatorBackend,
  CreateOptions,
  CreateResult,
  GetOptions,
  GetResult,
} from './types';

// The native addon is loaded at runtime from the built .node file.
// Type definitions for the native module functions.
interface NativeAddon {
  initialize(storagePath: string): void;
  createCredential(options: {
    origin: string;
    rpId: string;
    rpName: string;
    userId: string;
    userName: string;
    userDisplayName: string;
    challenge: string;
    pubKeyCredParams: Array<{ type: string; alg: number }>;
    excludeCredentials?: Array<{ id: string; type: string }>;
    authenticatorSelection?: {
      residentKey?: string;
      userVerification?: string;
      authenticatorAttachment?: string;
    };
    timeout?: number;
  }): Promise<{
    credentialId: string;
    rawId: string;
    attestationObject: string;
    clientDataJson: string;
    type: string;
    authenticatorData: string;
    transports: string[];
    publicKey: string | null;
    publicKeyAlgorithm: number;
  }>;
  getAssertion(options: {
    origin: string;
    rpId: string;
    challenge: string;
    allowCredentials?: Array<{ id: string; type: string }>;
    userVerification?: string;
    timeout?: number;
  }): Promise<{
    credentialId: string;
    rawId: string;
    authenticatorData: string;
    clientDataJson: string;
    signature: string;
    userHandle: string | null;
    type: string;
  }>;
  listStoredCredentials(rpId?: string): Promise<
    Array<{
      credentialId: string;
      rpId: string;
      userHandle: string | null;
      userName: string | null;
      userDisplayName: string | null;
      createdAt: number;
    }>
  >;
}

let native: NativeAddon | null = null;

function loadNativeAddon(): NativeAddon {
  if (native) return native;

  try {
    // Try loading the platform-specific native addon
    // napi-rs generates files like webauthn-native.linux-x64-gnu.node
    native = require('../native/webauthn-native.node') as NativeAddon;
  } catch {
    try {
      // Fallback: try the build output directory
      native = require('../../target/release/libwebauthn_native.node') as NativeAddon;
    } catch {
      throw new Error(
        'Failed to load webauthn-native addon. Ensure the Rust addon is built: npm run build:rs',
      );
    }
  }

  return native!;
}

export class PasskeyRsBackend implements AuthenticatorBackend {
  readonly name = 'Software Passkey (passkey-rs)';
  readonly type = 'software' as const;

  private initialized = false;
  private storagePath: string;

  constructor(storagePath: string) {
    this.storagePath = storagePath;
  }

  async isAvailable(): Promise<boolean> {
    try {
      this.ensureInitialized();
      return true;
    } catch {
      return false;
    }
  }

  async hasCredentials(rpId: string, credentialIds?: string[]): Promise<boolean> {
    try {
      this.ensureInitialized();
      const creds = await loadNativeAddon().listStoredCredentials(rpId);
      if (!credentialIds || credentialIds.length === 0) {
        return creds.length > 0;
      }
      return creds.some((c) => credentialIds.includes(c.credentialId));
    } catch {
      return false;
    }
  }

  async createCredential(options: CreateOptions): Promise<CreateResult> {
    this.ensureInitialized();
    const addon = loadNativeAddon();

    const result = await addon.createCredential({
      origin: options.origin,
      rpId: options.rpId,
      rpName: options.rpName,
      userId: options.userId,
      userName: options.userName,
      userDisplayName: options.userDisplayName,
      challenge: options.challenge,
      pubKeyCredParams: options.pubKeyCredParams,
      excludeCredentials: options.excludeCredentials,
      authenticatorSelection: options.authenticatorSelection,
      timeout: options.timeout,
    });

    return {
      credentialId: result.credentialId,
      rawId: result.rawId,
      attestationObject: result.attestationObject,
      clientDataJson: result.clientDataJson,
      type: result.type,
      authenticatorData: result.authenticatorData,
      transports: result.transports,
      publicKey: result.publicKey,
      publicKeyAlgorithm: result.publicKeyAlgorithm,
    };
  }

  async getAssertion(options: GetOptions): Promise<GetResult> {
    this.ensureInitialized();
    const addon = loadNativeAddon();

    const result = await addon.getAssertion({
      origin: options.origin,
      rpId: options.rpId,
      challenge: options.challenge,
      allowCredentials: options.allowCredentials,
      userVerification: options.userVerification,
      timeout: options.timeout,
    });

    return {
      credentialId: result.credentialId,
      rawId: result.rawId,
      authenticatorData: result.authenticatorData,
      clientDataJson: result.clientDataJson,
      signature: result.signature,
      userHandle: result.userHandle,
      type: result.type,
    };
  }

  private ensureInitialized(): void {
    if (this.initialized) return;

    const addon = loadNativeAddon();
    addon.initialize(this.storagePath);
    this.initialized = true;
  }
}
