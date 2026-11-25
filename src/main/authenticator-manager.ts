/**
 * Discovers and delegates to available authenticator backends.
 */

import type {
  AuthenticatorBackend,
  CreateOptions,
  CreateResult,
  GetOptions,
  GetResult,
} from '../authenticators/types';
import { PasskeyRsBackend } from '../authenticators/passkey-rs';
import { HardwareKeyBackend, type PinProvider } from '../authenticators/hardware';

export interface AuthenticatorManagerOptions {
  storagePath: string;
  enableHardwareKeys?: boolean;
  /** Collects the FIDO2 PIN for hardware keys. Defaults to an Electron dialog. */
  pinProvider?: PinProvider;
}

export class AuthenticatorManager {
  private backends: AuthenticatorBackend[] = [];
  private initialized = false;

  constructor(private options: AuthenticatorManagerOptions) {}

  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Always add the software passkey backend
    const softwareBackend = new PasskeyRsBackend(this.options.storagePath);
    if (await softwareBackend.isAvailable()) {
      this.backends.push(softwareBackend);
    }

    // Optionally add hardware key backend
    if (this.options.enableHardwareKeys !== false) {
      const hardwareBackend = new HardwareKeyBackend(this.options.pinProvider);
      // Register on tools alone: a key may be plugged in later, so presence is checked per call.
      if (await hardwareBackend.hasTools()) {
        this.backends.push(hardwareBackend);
      }
    }

    this.initialized = true;
  }

  /**
   * Get available backends for a create operation.
   * For creation, all available backends can be used.
   */
  async getAvailableBackendsForCreate(): Promise<AuthenticatorBackend[]> {
    await this.initialize();
    const live = await Promise.all(this.backends.map((b) => b.isAvailable()));
    return this.backends.filter((_, i) => live[i]);
  }

  /** True if hardware keys are supported here (tools installed), whether or not a key is plugged in. */
  async hasHardwareSupport(): Promise<boolean> {
    await this.initialize();
    return this.backends.some((b) => b.type === 'hardware');
  }

  /**
   * Get available backends for a get operation.
   * Only backends that have matching credentials should be returned.
   */
  async getAvailableBackendsForGet(
    rpId: string,
    credentialIds?: string[],
  ): Promise<AuthenticatorBackend[]> {
    await this.initialize();

    const results = await Promise.all(
      this.backends.map(async (b) => ({
        backend: b,
        has: await b.hasCredentials(rpId, credentialIds),
      })),
    );

    return results.filter((r) => r.has).map((r) => r.backend);
  }

  /**
   * Create a credential using the best available backend.
   * If multiple backends are available, the caller should use selectBackend() first.
   */
  async createCredential(
    options: CreateOptions,
    backend?: AuthenticatorBackend,
  ): Promise<CreateResult> {
    const target = backend || (await this.getDefaultBackend());
    return target.createCredential(options);
  }

  /**
   * Get an assertion using the best available backend.
   */
  async getAssertion(
    options: GetOptions,
    backend?: AuthenticatorBackend,
  ): Promise<GetResult> {
    const target =
      backend ||
      (await this.getBestBackendForGet(
        options.rpId,
        options.allowCredentials?.map((c) => c.id),
      ));
    return target.getAssertion(options);
  }

  private async getDefaultBackend(): Promise<AuthenticatorBackend> {
    await this.initialize();
    if (this.backends.length === 0) {
      throw new Error('No WebAuthn authenticator backends available');
    }
    // Prefer software backend
    return this.backends.find((b) => b.type === 'software') || this.backends[0];
  }

  private async getBestBackendForGet(
    rpId: string,
    credentialIds?: string[],
  ): Promise<AuthenticatorBackend> {
    const available = await this.getAvailableBackendsForGet(rpId, credentialIds);
    if (available.length === 0) {
      // Fall back to default which will likely produce an error
      return this.getDefaultBackend();
    }
    // Prefer software backend when it has matching credentials
    return available.find((b) => b.type === 'software') || available[0];
  }
}
