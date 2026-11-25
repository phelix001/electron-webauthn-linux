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

/**
 * libfido2 prints authenticator data CBOR-wrapped (a CBOR byte string). Unwrap it
 * and check the leading rpIdHash so a mis-parse fails loudly instead of yielding garbage.
 */
function unwrapAuthData(wrapped: Buffer, rpId: string): Buffer {
  const major = wrapped[0] >> 5;
  const info = wrapped[0] & 0x1f;
  let offset: number;
  let len: number;
  if (major !== 2) throw new Error('Unexpected authenticator data encoding from fido2 tool');
  if (info < 24) { len = info; offset = 1; }
  else if (info === 24) { len = wrapped[1]; offset = 2; }
  else if (info === 25) { len = wrapped.readUInt16BE(1); offset = 3; }
  else throw new Error('Unexpected authenticator data length encoding from fido2 tool');
  const raw = wrapped.subarray(offset, offset + len);
  const expected = createHash('sha256').update(rpId).digest();
  if (raw.length < 37 || !raw.subarray(0, 32).equals(expected)) {
    throw new Error('Authenticator data rpIdHash does not match the relying party');
  }
  return raw;
}

/** Minimal CBOR encoder: text, byte strings, integers, arrays and string-keyed maps. */
function cborEncode(v: unknown): Buffer {
  const head = (major: number, n: number): Buffer => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(n, 1);
    return b;
  };
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === 'string') {
    const b = Buffer.from(v, 'utf8');
    return Buffer.concat([head(3, b.length), b]);
  }
  if (typeof v === 'number' && Number.isInteger(v)) {
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cborEncode)]);
  if (v && typeof v === 'object') {
    const entries = Object.entries(v as Record<string, unknown>);
    return Buffer.concat([
      head(5, entries.length),
      ...entries.flatMap(([k, val]) => [cborEncode(k), cborEncode(val)]),
    ]);
  }
  throw new Error('cborEncode: unsupported value');
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

  /** True if the libfido2 tools are installed (cached; says nothing about a key being plugged in). */
  async hasTools(): Promise<boolean> {
    if (this.toolsAvailable !== null) return this.toolsAvailable;

    const [hasCred, hasAssert, hasToken] = await Promise.all([
      commandExists('fido2-cred'),
      commandExists('fido2-assert'),
      commandExists('fido2-token'),
    ]);

    this.toolsAvailable = hasCred && hasAssert && hasToken;
    return this.toolsAvailable;
  }

  /** Tools installed AND a key currently plugged in (checked live on every call). */
  async isAvailable(): Promise<boolean> {
    if (!(await this.hasTools())) return false;
    return (await discoverDevices()).length > 0;
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

    // fido2-cred(1) INPUT FORMAT (-M): base64 client data hash, rp id, user name, base64 user id.
    const input = [
      clientDataHash.toString('base64'),
      options.rpId,
      options.userName,
      Buffer.from(base64urlDecode(options.userId)).toString('base64'),
    ].join('\n') + '\n';

    const args = ['-M', '-h']; // -M = make credential, -h = hmac-secret

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

    // fido2-cred(1) OUTPUT FORMAT: client data hash, rp id, format, CBOR authenticator data,
    // credential id, attestation signature, attestation certificate (optional).
    const lines = stdout.trim().split('\n');
    if (lines.length < 6) {
      throw new Error('Unexpected fido2-cred output format');
    }

    const fmt = lines[2];
    const authData = unwrapAuthData(Buffer.from(lines[3], 'base64'), options.rpId);
    const credId = Buffer.from(lines[4], 'base64');
    const sig = Buffer.from(lines[5], 'base64');
    const cert = lines[6] ? Buffer.from(lines[6], 'base64') : null;

    // attStmt per WebAuthn attestation statement formats (packed / fido-u2f / none).
    // shortcut: packed alg assumed ES256 (-7), as every shipping FIDO2 key signs with it; upgrade when a key reports otherwise.
    let attStmt: Record<string, unknown> = {};
    if (fmt === 'packed') {
      attStmt = { alg: -7, sig, ...(cert ? { x5c: [cert] } : {}) };
    } else if (fmt === 'fido-u2f') {
      attStmt = { sig, ...(cert ? { x5c: [cert] } : {}) };
    } else if (fmt !== 'none') {
      throw new Error(`Unsupported attestation format from security key: ${fmt}`);
    }
    const attestationObject = cborEncode({ fmt, attStmt, authData });

    return {
      credentialId: base64urlEncode(credId),
      rawId: base64urlEncode(credId),
      attestationObject: base64urlEncode(attestationObject),
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

    const { uv, pin } = await this.resolveUv(device, options.rpId, options.userVerification);
    const args = ['-G'];
    if (uv) args.push('-v');

    // fido2-assert(1) takes at most one (non-resident) credential id per run, so try each
    // allowed credential in turn; no allowCredentials means a resident (discoverable) credential.
    const allowed = options.allowCredentials?.map((c) => c.id) ?? [];
    const candidates: Array<string | null> = allowed.length > 0 ? allowed : [null];
    const timeoutMs = (options.timeout || 60) * 1000;

    let lastError: unknown = new Error('No matching credential on the security key');
    for (const credId of candidates) {
      // INPUT FORMAT (-G): base64 client data hash, rp id, base64 credential id if not resident.
      const input = [
        clientDataHash.toString('base64'),
        options.rpId,
        ...(credId ? [Buffer.from(base64urlDecode(credId)).toString('base64')] : []),
      ].join('\n') + '\n';

      let stdout: string;
      try {
        ({ stdout } = await withInputFile(input, (file) =>
          runTool('fido2-assert', [...args, '-i', file, device], pin, timeoutMs),
        ));
      } catch (err) {
        lastError = err;
        if (/FIDO_ERR_NO_CREDENTIALS/.test(String((err as Error).message))) continue;
        throw err;
      }

      // OUTPUT FORMAT: client data hash, rp id, CBOR authenticator data, signature,
      // user id (resident credentials only).
      const lines = stdout.trim().split('\n');
      if (lines.length < 4) {
        throw new Error('Unexpected fido2-assert output format');
      }

      const authData = unwrapAuthData(Buffer.from(lines[2], 'base64'), options.rpId);
      const signature = Buffer.from(lines[3], 'base64');
      const userHandle = lines.length >= 5 && lines[4]
        ? base64urlEncode(Buffer.from(lines[4], 'base64'))
        : null;
      // shortcut: fido2-assert does not print the credential id for resident credentials; empty then, upgrade via fido2-token -L -k if needed.
      const credentialId = credId ?? '';

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
    throw lastError;
  }
}
