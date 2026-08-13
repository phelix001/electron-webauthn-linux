/**
 * Hardware FIDO2 key backend via libfido2 CLI tools.
 * Requires fido2-tools package (fido2-token, fido2-cred, fido2-assert).
 */

import { execFile, spawn } from 'child_process';
import { createHash } from 'crypto';
import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { promisify } from 'util';

import { base64urlDecode, base64urlEncode } from '../helpers/serialization';
import { generateClientDataJSONBuffer } from '../helpers/client-data';
import type {
  AuthenticatorBackend,
  CreateOptions,
  CreateResult,
  GetOptions,
  GetResult,
  HardwareUserVerificationHandler,
} from './types';

const execFileAsync = promisify(execFile);

/** Run a command with controlled stdin and return stdout. */
function spawnWithStdin(
  cmd: string,
  args: string[],
  stdin: string,
  timeout: number,
  signal?: AbortSignal,
): Promise<{ stdout: string }> {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, {
      detached: true,
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout,
    });
    let stdout = '';
    let stderr = '';
    let settled = false;

    const cleanupAbort = signal
      ? () => signal.removeEventListener('abort', abort)
      : () => {};

    const settle = (callback: () => void) => {
      if (settled) return;
      settled = true;
      cleanupAbort();
      callback();
    };

    const abort = () => {
      if (proc.pid && process.platform !== 'win32') {
        try {
          process.kill(-proc.pid, 'SIGTERM');
        } catch {
          proc.kill('SIGTERM');
        }
      } else {
        proc.kill('SIGTERM');
      }
      settle(() => reject(new Error('NotAllowed: The operation was cancelled.')));
    };

    if (signal?.aborted) {
      abort();
      return;
    }

    signal?.addEventListener('abort', abort, { once: true });

    proc.stdout.on('data', (data: Buffer) => { stdout += data.toString(); });
    proc.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });

    proc.on('close', (code) => {
      if (code === 0) {
        settle(() => resolve({ stdout }));
      } else {
        settle(() => reject(new Error(`${cmd} exited with code ${code}: ${stderr}`)));
      }
    });

    proc.on('error', (error) => settle(() => reject(error)));

    proc.stdin.write(stdin);
    proc.stdin.end();
  });
}

async function spawnWithInputFile(
  cmd: string,
  args: string[],
  input: string,
  stdin: string,
  timeout: number,
  signal?: AbortSignal,
): Promise<{ stdout: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'electron-webauthn-linux-'));
  const inputFile = join(dir, 'input');

  try {
    await writeFile(inputFile, input, { mode: 0o600 });
    const commandArgs = args.length > 0
      ? [...args.slice(0, -1), '-i', inputFile, args[args.length - 1]]
      : ['-i', inputFile];

    return await spawnWithStdin(
      cmd,
      commandArgs,
      stdin,
      timeout,
      signal,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function commandExists(cmd: string): Promise<boolean> {
  try {
    await execFileAsync('which', [cmd]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Discover connected FIDO2 USB devices.
 * Returns an array of device paths.
 */
async function discoverDevices(): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync('fido2-token', ['-L']);
    return stdout
      .trim()
      .split('\n')
      .filter((line) => line.length > 0)
      .map((line) => line.split(':')[0].trim())
      .filter((path) => path.length > 0);
  } catch {
    return [];
  }
}

function base64ToBase64url(value: string): string {
  return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function normalizeCredentialManagerUserId(value: string): string {
  return base64ToBase64url(value.replace(/^\(/, '').replace(/\)$/, ''));
}

function cborEncodeUnsigned(value: number): Buffer {
  if (value < 24) return Buffer.from([value]);
  if (value <= 0xff) return Buffer.from([0x18, value]);
  if (value <= 0xffff) {
    const encoded = Buffer.alloc(3);
    encoded[0] = 0x19;
    encoded.writeUInt16BE(value, 1);
    return encoded;
  }
  const encoded = Buffer.alloc(5);
  encoded[0] = 0x1a;
  encoded.writeUInt32BE(value, 1);
  return encoded;
}

function cborWithMajorType(encoded: Buffer, majorType: number): Buffer {
  const tagged = Buffer.from(encoded);
  tagged[0] |= majorType << 5;
  return tagged;
}

function cborEncodeInteger(value: number): Buffer {
  if (value >= 0) return cborEncodeUnsigned(value);

  return cborWithMajorType(cborEncodeUnsigned(-1 - value), 1);
}

function cborEncodeBytes(value: Buffer): Buffer {
  return Buffer.concat([cborWithMajorType(cborEncodeUnsigned(value.length), 2), value]);
}

function cborEncodeText(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8');
  return Buffer.concat([cborWithMajorType(cborEncodeUnsigned(bytes.length), 3), bytes]);
}

function cborEncodeMap(entries: Array<[string, Buffer]>): Buffer {
  return Buffer.concat([
    cborWithMajorType(cborEncodeUnsigned(entries.length), 5),
    ...entries.flatMap(([key, value]) => [cborEncodeText(key), value]),
  ]);
}

function unwrapCborByteString(buffer: Buffer): Buffer {
  if (buffer.length < 1) return buffer;

  const majorType = buffer[0] >> 5;
  const additionalInfo = buffer[0] & 0x1f;

  if (majorType !== 2) return buffer;

  let offset = 1;
  let length = additionalInfo;

  if (additionalInfo === 24) {
    if (buffer.length < 2) return buffer;
    length = buffer[1];
    offset = 2;
  } else if (additionalInfo === 25) {
    if (buffer.length < 3) return buffer;
    length = buffer.readUInt16BE(1);
    offset = 3;
  } else if (additionalInfo === 26) {
    if (buffer.length < 5) return buffer;
    length = buffer.readUInt32BE(1);
    offset = 5;
  } else if (additionalInfo >= 27) {
    return buffer;
  }

  if (buffer.length !== offset + length) return buffer;

  return buffer.subarray(offset);
}

function extractCredentialId(authData: Buffer): Buffer {
  const credentialIdLengthOffset = 53;
  const credentialIdOffset = 55;

  if (authData.length < credentialIdOffset) {
    throw new Error('Authenticator data is too short to contain a credential id');
  }

  const credentialIdLength = authData.readUInt16BE(credentialIdLengthOffset);
  const credentialIdEnd = credentialIdOffset + credentialIdLength;

  if (credentialIdLength === 0 || authData.length < credentialIdEnd) {
    throw new Error('Authenticator data contains an invalid credential id length');
  }

  return authData.subarray(credentialIdOffset, credentialIdEnd);
}

function parseMakeCredentialOutput(stdout: string): {
  attestationObject: Buffer;
  authData: Buffer;
  credentialId: Buffer;
} {
  const lines = stdout.trim().split('\n');
  if (lines.length < 6) {
    throw new Error('Unexpected fido2-cred output format');
  }

  const format = lines[2];
  const authData = unwrapCborByteString(Buffer.from(lines[3], 'base64'));
  const credentialId = Buffer.from(lines[4], 'base64');
  const signature = Buffer.from(lines[5], 'base64');
  const certificate = lines.length >= 7 ? Buffer.from(lines[6], 'base64') : null;

  const attStmtEntries: Array<[string, Buffer]> = [
    ['alg', cborEncodeInteger(-7)],
    ['sig', cborEncodeBytes(signature)],
  ];

  if (certificate) {
    attStmtEntries.unshift(['x5c', Buffer.concat([Buffer.from([0x81]), cborEncodeBytes(certificate)])]);
  }

  return {
    attestationObject: cborEncodeMap([
      ['fmt', cborEncodeText(format)],
      ['authData', cborEncodeBytes(authData)],
      ['attStmt', cborEncodeMap(attStmtEntries)],
    ]),
    authData,
    credentialId: credentialId.length > 0 ? credentialId : extractCredentialId(authData),
  };
}

function parseGetAssertionOutput(stdout: string): {
  authData: Buffer;
  signature: Buffer;
  userHandle: string | null;
} {
  const lines = stdout.trim().split('\n');
  if (lines.length < 4) {
    throw new Error('Unexpected fido2-assert output format');
  }

  return {
    authData: unwrapCborByteString(Buffer.from(lines[2], 'base64')),
    signature: Buffer.from(lines[3], 'base64'),
    userHandle: lines.length >= 5
      ? base64urlEncode(Buffer.from(lines[4], 'base64'))
      : null,
  };
}

async function listResidentCredentials(
  device: string,
  rpId: string,
  pin: string | null,
  signal?: AbortSignal,
): Promise<Array<{ credentialId: string; userId: string }>> {
  try {
    const { stdout } = await spawnWithStdin(
      'fido2-token',
      ['-L', '-k', rpId, device],
      pin ? `${pin}\n` : '',
      60_000,
      signal,
    );

    return stdout
      .trim()
      .split('\n')
      .map((line) => {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 5 || !/^\d+:$/.test(parts[0])) return null;

        // Format: "00: <credential-id> <display name...> <user-id> <alg> <flags>"
        // Display names may contain spaces, so parse stable fields from both ends.
        return {
          credentialId: base64ToBase64url(parts[1]),
          userId: normalizeCredentialManagerUserId(parts[parts.length - 3]),
        };
      })
      .filter((credential): credential is { credentialId: string; userId: string } => Boolean(credential));
  } catch {
    return [];
  }
}

async function requestHardwarePin(
  handler: HardwareUserVerificationHandler | undefined,
  operation: 'create' | 'get' | 'credential-management',
  rpId: string,
  reason: 'user-verification' | 'resident-credential',
  previousError?: 'pin-invalid',
): Promise<string | null> {
  if (!handler) return null;

  const result = await handler({ operation, rpId, reason, previousError });
  return result?.pin || null;
}

function isInvalidPinError(error: unknown): boolean {
  return error instanceof Error && error.message.includes('FIDO_ERR_PIN_INVALID');
}

async function runWithPinRetries(
  run: (pin: string | null) => Promise<{ stdout: string }>,
  getPin: (previousError?: 'pin-invalid') => Promise<string | null>,
  needsPin: boolean,
): Promise<{ stdout: string; pin: string | null }> {
  let previousError: 'pin-invalid' | undefined;
  let lastError: unknown;

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const pin = needsPin ? await getPin(previousError) : null;

    try {
      const result = await run(pin);
      return { ...result, pin };
    } catch (error) {
      if (!needsPin || !isInvalidPinError(error)) throw error;

      previousError = 'pin-invalid';
      lastError = error;
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error('FIDO2 operation failed after invalid PIN attempts');
}

export class HardwareKeyBackend implements AuthenticatorBackend {
  readonly name = 'Hardware Security Key (FIDO2)';
  readonly type = 'hardware' as const;

  private toolsAvailable: boolean | null = null;

  async isAvailable(): Promise<boolean> {
    if (this.toolsAvailable !== null) return this.toolsAvailable;

    const [hasCred, hasAssert, hasToken] = await Promise.all([
      commandExists('fido2-cred'),
      commandExists('fido2-assert'),
      commandExists('fido2-token'),
    ]);

    this.toolsAvailable = hasCred && hasAssert && hasToken;

    if (!this.toolsAvailable) return false;

    // Also check if any devices are connected
    const devices = await discoverDevices();
    return devices.length > 0;
  }

  async hasCredentials(_rpId: string, _credentialIds?: string[]): Promise<boolean> {
    // Hardware keys don't expose credential lists; we check device presence.
    const devices = await discoverDevices();
    return devices.length > 0;
  }

  async createCredential(options: CreateOptions): Promise<CreateResult> {
    const devices = await discoverDevices();
    if (devices.length === 0) {
      throw new Error('No FIDO2 hardware device found');
    }

    const device = devices[0];
    const challengeBytes = base64urlDecode(options.challenge);
    const clientDataJSON = generateClientDataJSONBuffer(
      'webauthn.create',
      challengeBytes,
      options.origin,
    );
    const clientDataHash = createHash('sha256').update(clientDataJSON).digest();

    // Build fido2-cred input:
    // Line 1: clientDataHash (base64)
    // Line 2: relying party id
    // Line 3: user name
    // Line 4: user id (base64)
    const input = [
      clientDataHash.toString('base64'),
      options.rpId,
      options.userName,
      Buffer.from(base64urlDecode(options.userId)).toString('base64'),
    ].join('\n') + '\n';

    const args = ['-M']; // -M = make credential

    // Add resident key flag if requested
    if (options.authenticatorSelection?.residentKey === 'required') {
      args.push('-r');
    }

    // Add user verification flag
    if (
      options.authenticatorSelection?.userVerification === 'required' ||
      options.authenticatorSelection?.userVerification === 'preferred'
    ) {
      args.push('-v');
    }

    args.push(device);

    const needsPin =
      options.authenticatorSelection?.residentKey === 'required' ||
      options.authenticatorSelection?.userVerification === 'required' ||
      options.authenticatorSelection?.userVerification === 'preferred';
    const { stdout } = await runWithPinRetries(
      (pin) => spawnWithInputFile(
        'fido2-cred',
        args,
        input,
        pin ? `${pin}\n` : '',
        (options.timeout || 60) * 1000,
        options.hardwareAbortSignal,
      ),
      (previousError) => requestHardwarePin(
        options.hardwareUserVerification,
        'create',
        options.rpId,
        options.authenticatorSelection?.residentKey === 'required'
          ? 'resident-credential'
          : 'user-verification',
        previousError,
      ),
      needsPin,
    );

    // Parse fido2-cred output (base64-encoded lines):
    // Line 1: client data hash (base64)
    // Line 2: relying party id
    // Line 3: format (e.g., "packed")
    // Line 4: CBOR encoded authenticator data (base64)
    // Line 5: credential id (base64)
    // Line 6: attestation signature (base64)
    // Line 7: attestation certificate (optional, base64)
    const parsed = parseMakeCredentialOutput(stdout);

    return {
      credentialId: base64urlEncode(parsed.credentialId),
      rawId: base64urlEncode(parsed.credentialId),
      attestationObject: base64urlEncode(parsed.attestationObject),
      clientDataJson: base64urlEncode(clientDataJSON),
      type: 'public-key',
      authenticatorData: base64urlEncode(parsed.authData),
      transports: ['usb'],
      publicKey: null,
      publicKeyAlgorithm: -7, // ES256
    };
  }

  async getAssertion(options: GetOptions): Promise<GetResult> {
    const devices = await discoverDevices();
    if (devices.length === 0) {
      throw new Error('No FIDO2 hardware device found');
    }

    const device = devices[0];
    const challengeBytes = base64urlDecode(options.challenge);
    const clientDataJSON = generateClientDataJSONBuffer(
      'webauthn.get',
      challengeBytes,
      options.origin,
    );
    const clientDataHash = createHash('sha256').update(clientDataJSON).digest();

    // Build fido2-assert input:
    // Line 1: clientDataHash (base64)
    // Line 2: relying party id
    // Optional: credential id (base64) for each allowed credential.
    // If the RP sends no allowCredentials, use resident/discoverable lookup.
    const inputLines = [clientDataHash.toString('base64'), options.rpId];

    if (options.allowCredentials && options.allowCredentials.length > 0) {
      for (const cred of options.allowCredentials) {
        inputLines.push(Buffer.from(base64urlDecode(cred.id)).toString('base64'));
      }
    }

    const input = inputLines.join('\n') + '\n';

    const args = ['-G']; // -G = get assertion

    if (!options.allowCredentials || options.allowCredentials.length === 0) {
      args.push('-r');
    }

    if (
      options.userVerification === 'required' ||
      options.userVerification === 'preferred'
    ) {
      args.push('-t', 'pin=true');
    }

    args.push(device);

    const needsResidentCredential = !options.allowCredentials || options.allowCredentials.length === 0;
    const needsPin =
      needsResidentCredential ||
      options.userVerification === 'required' ||
      options.userVerification === 'preferred';
    const { stdout, pin } = await runWithPinRetries(
      (currentPin) => spawnWithInputFile(
        'fido2-assert',
        args,
        input,
        currentPin ? `${currentPin}\n` : '',
        (options.timeout || 60) * 1000,
        options.hardwareAbortSignal,
      ),
      (previousError) => requestHardwarePin(
        options.hardwareUserVerification,
        'get',
        options.rpId,
        needsResidentCredential ? 'resident-credential' : 'user-verification',
        previousError,
      ),
      needsPin,
    );

    // Parse fido2-assert output (base64-encoded lines):
    // Line 1: client data hash (base64)
    // Line 2: relying party id
    // Line 3: CBOR encoded authenticator data (base64)
    // Line 4: signature (base64)
    // Line 5: user id (base64, for discoverable creds)
    const parsed = parseGetAssertionOutput(stdout);
    let credentialId = options.allowCredentials?.[0]?.id || '';

    if (!credentialId && parsed.userHandle) {
      const residentCredentials = await listResidentCredentials(
        device,
        options.rpId,
        pin,
        options.hardwareAbortSignal,
      );
      const matchingCredential = residentCredentials.find((credential) => credential.userId === parsed.userHandle);

      if (matchingCredential) {
        credentialId = matchingCredential.credentialId;
      } else if (residentCredentials.length === 1) {
        credentialId = residentCredentials[0].credentialId;
      }
    }

    if (!credentialId) {
      throw new Error('Unable to resolve resident credential id for assertion');
    }

    return {
      credentialId,
      rawId: credentialId,
      authenticatorData: base64urlEncode(parsed.authData),
      clientDataJson: base64urlEncode(clientDataJSON),
      signature: base64urlEncode(parsed.signature),
      userHandle: parsed.userHandle,
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
    };
  }
}

export const __hardwareInternals = {
  parseGetAssertionOutput,
  parseMakeCredentialOutput,
  unwrapCborByteString,
};
