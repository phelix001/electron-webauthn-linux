/**
 * Common interface for all authenticator backends.
 */

export interface AuthenticatorBackend {
  readonly name: string;
  readonly type: 'software' | 'hardware';

  /** Check if this backend is available on the current system. */
  isAvailable(): Promise<boolean>;

  /** Check if this backend has credentials matching the given rpId and optional credential IDs. */
  hasCredentials(rpId: string, credentialIds?: string[]): Promise<boolean>;

  /**
   * Create a credential (registration).
   * Returns base64url-encoded response fields.
   */
  createCredential(options: CreateOptions): Promise<CreateResult>;

  /**
   * Get an assertion (authentication).
   * Returns base64url-encoded response fields.
   */
  getAssertion(options: GetOptions): Promise<GetResult>;
}

export interface HardwareUserVerificationRequest {
  operation: 'create' | 'get' | 'credential-management';
  rpId: string;
  reason: 'user-verification' | 'resident-credential';
  previousError?: 'pin-invalid';
}

export interface HardwareUserVerificationResult {
  pin?: string;
}

export type HardwareUserVerificationHandler = (
  request: HardwareUserVerificationRequest,
) => Promise<HardwareUserVerificationResult | null>;

export interface CreateOptions {
  origin: string;
  rpId: string;
  rpName: string;
  userId: string; // base64url
  userName: string;
  userDisplayName: string;
  challenge: string; // base64url
  pubKeyCredParams: Array<{ type: string; alg: number }>;
  excludeCredentials?: Array<{ id: string; type: string }>;
  authenticatorSelection?: {
    residentKey?: string;
    userVerification?: string;
    authenticatorAttachment?: string;
  };
  timeout?: number;
  hardwareUserVerification?: HardwareUserVerificationHandler;
  hardwareAbortSignal?: AbortSignal;
}

export interface GetOptions {
  origin: string;
  rpId: string;
  challenge: string; // base64url
  allowCredentials?: Array<{ id: string; type: string }>;
  userVerification?: string;
  timeout?: number;
  hardwareUserVerification?: HardwareUserVerificationHandler;
  hardwareAbortSignal?: AbortSignal;
}

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
  authenticatorAttachment?: string;
}
