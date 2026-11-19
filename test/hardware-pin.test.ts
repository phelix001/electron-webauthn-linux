/**
 * Spec: libfido2 tools (fido2-assert(1), fido2-cred(1)) read the PIN from the
 * tty if present, otherwise from stdin; `-i file` reads the request from a file
 * instead of stdin. Source: man pages shipped with fido2-tools 1.16.
 * Behavioral test: real spawned processes against fake fido2-* scripts on PATH.
 */
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { HardwareKeyBackend } from '../src/authenticators/hardware';
import { base64urlEncode } from '../src/helpers/serialization';

// Fake tools are created by test/fake-fido2-setup.js (jest globalSetup).
const dir = process.env.FAKE_FIDO2_DIR as string;
const log = join(dir, 'assert.log');
const pinFlag = join(dir, 'pinflag');

const opts = {
  origin: 'https://example.com',
  rpId: 'example.com',
  challenge: base64urlEncode(Buffer.from('chal')),
  allowCredentials: [{ id: base64urlEncode(Buffer.from('cred')), type: 'public-key' }],
  userVerification: 'preferred',
};

const setPin = (v: boolean) => writeFileSync(pinFlag, v ? 'clientPin' : 'noclientPin');

test('PIN-protected key: PIN reaches the tool on stdin, request goes via -i', async () => {
  setPin(true);
  const provider = jest.fn().mockResolvedValue('1234');
  const res = await new HardwareKeyBackend(provider).getAssertion(opts);
  expect(provider).toHaveBeenCalledWith('example.com');
  expect(res.signature).toBe(base64urlEncode(Buffer.from('sig')));
  const l = readFileSync(log, 'utf8');
  expect(l).toMatch(/ARGS: .* -v .*-i /);
  expect(l).toContain('PIN: 1234');
});

test('wrong PIN is surfaced as an error, not success', async () => {
  setPin(true);
  await expect(new HardwareKeyBackend(async () => '0000').getAssertion(opts)).rejects.toThrow(
    /exited with code 3/,
  );
});

test('cancelled PIN prompt rejects and never runs the tool', async () => {
  setPin(true);
  writeFileSync(log, '');
  await expect(new HardwareKeyBackend(async () => null).getAssertion(opts)).rejects.toThrow(
    /PIN entry cancelled/,
  );
  expect(readFileSync(log, 'utf8')).toBe('');
});

test('no PIN set on key + preferred UV: no prompt, no -v', async () => {
  setPin(false);
  const provider = jest.fn();
  await new HardwareKeyBackend(provider).getAssertion(opts);
  expect(provider).not.toHaveBeenCalled();
  expect(readFileSync(log, 'utf8')).not.toMatch(/ -v /);
});

test('PIN needed but no provider configured fails closed', async () => {
  setPin(true);
  await expect(new HardwareKeyBackend().getAssertion(opts)).rejects.toThrow(/no PIN prompt/);
});

test('createCredential: base64 input, output parsed per fido2-cred(1), attestationObject is valid CBOR', async () => {
  setPin(true);
  const res = await new HardwareKeyBackend(async () => '1234').createCredential({
    origin: 'https://example.com',
    rpId: 'example.com',
    rpName: 'x',
    userId: base64urlEncode(Buffer.from('u1')),
    userName: 'u',
    userDisplayName: 'u',
    challenge: base64urlEncode(Buffer.from('chal')),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { userVerification: 'required' },
  });
  expect(Buffer.from(res.credentialId, 'base64url').toString()).toBe('credid');
  const att = Buffer.from(res.attestationObject, 'base64url');
  expect(att[0]).toBe(0xa3); // map(3): fmt, attStmt, authData
  expect(att.includes(Buffer.from('packed'))).toBe(true);
  expect(Buffer.from(res.authenticatorData, 'base64url').length).toBe(37);
});

test('authenticator data with the wrong rpIdHash is rejected', async () => {
  setPin(false);
  await expect(
    new HardwareKeyBackend().getAssertion({ ...opts, rpId: 'evil.example' }),
  ).rejects.toThrow(/rpIdHash/);
});
