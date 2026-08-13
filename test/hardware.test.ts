import { base64urlEncode } from '../src/helpers/serialization';
import { __hardwareInternals } from '../src/authenticators/hardware';

function makeAuthData(credentialId: Buffer): Buffer {
  const authData = Buffer.alloc(55 + credentialId.length);
  authData[32] = 0x41;
  authData.writeUInt16BE(credentialId.length, 53);
  credentialId.copy(authData, 55);
  return authData;
}

function cborByteString(value: Buffer): Buffer {
  if (value.length < 24) {
    return Buffer.concat([Buffer.from([0x40 | value.length]), value]);
  }

  return Buffer.concat([Buffer.from([0x58, value.length]), value]);
}

describe('HardwareKeyBackend fido2 CLI parsing', () => {
  it('parses fido2-cred output using documented line order', () => {
    const credentialId = Buffer.from([1, 2, 3, 4]);
    const authData = makeAuthData(credentialId);
    const signature = Buffer.from([0x30, 0x44, 0xaa]);
    const cert = Buffer.from([0x30, 0x82, 0xbb]);

    const parsed = __hardwareInternals.parseMakeCredentialOutput([
      Buffer.from('client-data-hash').toString('base64'),
      'example.com',
      'packed',
      authData.toString('base64'),
      credentialId.toString('base64'),
      signature.toString('base64'),
      cert.toString('base64'),
    ].join('\n'));

    expect(parsed.authData).toEqual(authData);
    expect(parsed.credentialId).toEqual(credentialId);
    expect(parsed.attestationObject[0]).toBe(0xa3);
    expect(parsed.attestationObject.includes(Buffer.from('packed'))).toBe(true);
  });

  it('falls back to the credential id embedded in authData', () => {
    const credentialId = Buffer.from([5, 6, 7, 8]);
    const authData = makeAuthData(credentialId);

    const parsed = __hardwareInternals.parseMakeCredentialOutput([
      Buffer.from('client-data-hash').toString('base64'),
      'example.com',
      'packed',
      authData.toString('base64'),
      Buffer.alloc(0).toString('base64'),
      Buffer.from([0x30, 0x44]).toString('base64'),
    ].join('\n'));

    expect(parsed.credentialId).toEqual(credentialId);
  });

  it('parses fido2-assert output and unwraps CBOR encoded authData', () => {
    const authData = Buffer.from([0xaa, 0xbb, 0xcc]);
    const signature = Buffer.from([0x30, 0x45]);
    const userHandle = Buffer.from([9, 8, 7]);

    const parsed = __hardwareInternals.parseGetAssertionOutput([
      Buffer.from('client-data-hash').toString('base64'),
      'example.com',
      cborByteString(authData).toString('base64'),
      signature.toString('base64'),
      userHandle.toString('base64'),
    ].join('\n'));

    expect(parsed.authData).toEqual(authData);
    expect(parsed.signature).toEqual(signature);
    expect(parsed.userHandle).toBe(base64urlEncode(userHandle));
  });
});
