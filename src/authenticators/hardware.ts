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
} from './types';

const execFileAsync = promisify(execFile);

/**
 * Run a command and return stdout. `stdin` carries only the PIN (or nothing).
 * The process is detached (setsid) so it has no controlling tty: libfido2 tools
 * use a tty for the PIN when one exists, otherwise stdin.
 */
function runTool(
  cmd: string,
  args: string[],
  stdin: string,
  timeout: number,
): Promise<{ stdout: string }> {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, { timeout, detached: true });
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data: Buffer) => { stdout += data.toString(); });
    proc.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });

    proc.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout });
      } else {
        reject(new Error(`${cmd} exited with code ${code}: ${stderr}`));
      }
    });

    proc.on('error', reject);

    proc.stdin.write(stdin);
    proc.stdin.end();
  });
}

/** Write the tool's input to a private temp file (-i), so stdin stays free for the PIN. */
async function withInputFile<T>(input: string, fn: (path: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'webauthn-fido2-'));
  try {
    const file = join(dir, 'input');
    await writeFile(file, input, { mode: 0o600 });
    return await fn(file);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** True if a client PIN is set on the device (`options: ..., clientPin, ...`). */
async function deviceHasPin(device: string): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync('fido2-token', ['-I', device]);
    return /^options:.*(^|[\s,:])clientPin(\s|,|$)/m.test(stdout);
  } catch {
    return false;
  }
}

export type PinProvider = (rpId: string) => Promise<string | null>;

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

export class HardwareKeyBackend implements AuthenticatorBackend {
  readonly name = 'Hardware Security Key (FIDO2)';
  readonly type = 'hardware' as const;

  private toolsAvailable: boolean | null = null;

  constructor(private pinProvider?: PinProvider) {}

  /**
   * Decide whether to pass -v and, if the key has a PIN, collect it.
   * 'required' always asks for UV; 'preferred' only when a PIN is set.
   */
  private async resolveUv(
    device: string,
    rpId: string,
    userVerification: string | undefined,
  ): Promise<{ uv: boolean; pin: string }> {
    if (userVerification !== 'required' && userVerification !== 'preferred') {
      return { uv: false, pin: '' };
    }
    const hasPin = await deviceHasPin(device);
    if (!hasPin) {
      return { uv: userVerification === 'required', pin: '' };
    }
    if (!this.pinProvider) {
      throw new Error('Security key requires a PIN but no PIN prompt is configured');
    }
    const pin = await this.pinProvider(rpId);
    if (!pin) throw new Error('PIN entry cancelled');
    return { uv: true, pin: pin + '\n' };
  }

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
    // Line 1: clientDataHash (hex)
    // Line 2: relying party id
    // Line 3: user name
    // Line 4: user id (hex)
    const userIdHex = Buffer.from(base64urlDecode(options.userId)).toString('hex');
    const input = [
      clientDataHash.toString('hex'),
      options.rpId,
      options.userName,
      userIdHex,
    ].join('\n') + '\n';

    const args = ['-M', '-h']; // -M = make credential, -h = hmac-secret (most keys support this)

    // Add resident key flag if requested
    if (options.authenticatorSelection?.residentKey === 'required') {
      args.push('-r');
    }

    const { uv, pin } = await this.resolveUv(
      device,
      options.rpId,
      options.authenticatorSelection?.userVerification,
    );
    if (uv) args.push('-v');

    const { stdout } = await withInputFile(input, (file) =>
      runTool('fido2-cred', [...args, '-i', file, device], pin, (options.timeout || 60) * 1000),
    );

    // Parse fido2-cred output (base64-encoded lines):
    // Line 1: format (e.g., "packed")
    // Line 2: authenticator data (base64)
    // Line 3: CBOR attestation cert (base64)
    // Line 4: CBOR attestation sig (base64)
    // Line 5: credential id (base64, if -r flag used)
    const lines = stdout.trim().split('\n');
    if (lines.length < 4) {
      throw new Error('Unexpected fido2-cred output format');
    }

    const authData = Buffer.from(lines[1], 'base64');
    const credId = lines.length >= 5
      ? Buffer.from(lines[4], 'base64')
      : authData.subarray(55, 55 + authData[53] * 256 + authData[54]); // Extract from authData

    return {
      credentialId: base64urlEncode(credId),
      rawId: base64urlEncode(credId),
      attestationObject: base64urlEncode(Buffer.from(lines.slice(1).join('\n'), 'base64')),
      clientDataJson: base64urlEncode(clientDataJSON),
      type: 'public-key',
      authenticatorData: base64urlEncode(authData),
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
    // Line 1: clientDataHash (hex)
    // Line 2: relying party id
    // Optional: credential id (hex) for each allowed credential
    const inputLines = [clientDataHash.toString('hex'), options.rpId];

    if (options.allowCredentials && options.allowCredentials.length > 0) {
      for (const cred of options.allowCredentials) {
        inputLines.push(Buffer.from(base64urlDecode(cred.id)).toString('hex'));
      }
    }

    const input = inputLines.join('\n') + '\n';

    const args = ['-G', '-h']; // -G = get assertion

    const { uv, pin } = await this.resolveUv(device, options.rpId, options.userVerification);
    if (uv) args.push('-v');

    const { stdout } = await withInputFile(input, (file) =>
      runTool('fido2-assert', [...args, '-i', file, device], pin, (options.timeout || 60) * 1000),
    );

    // Parse fido2-assert output (base64-encoded lines):
    // Line 1: authenticator data (base64)
    // Line 2: signature (base64)
    // Line 3: credential id (base64, for discoverable creds)
    // Line 4: user id (base64, for discoverable creds)
    const lines = stdout.trim().split('\n');
    if (lines.length < 2) {
      throw new Error('Unexpected fido2-assert output format');
    }

    const authData = Buffer.from(lines[0], 'base64');
    const signature = Buffer.from(lines[1], 'base64');
    const credentialId = lines.length >= 3
      ? base64urlEncode(Buffer.from(lines[2], 'base64'))
      : options.allowCredentials?.[0]?.id || '';
    const userHandle = lines.length >= 4
      ? base64urlEncode(Buffer.from(lines[3], 'base64'))
      : null;

    return {
      credentialId,
      rawId: credentialId,
      authenticatorData: base64urlEncode(authData),
      clientDataJson: base64urlEncode(clientDataJSON),
      signature: base64urlEncode(signature),
      userHandle,
      type: 'public-key',
    };
  }
}
