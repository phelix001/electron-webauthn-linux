import {
  base64urlEncode,
  base64urlDecode,
  bufferToArrayBuffer,
  serializeCreationOptions,
  serializeRequestOptions,
} from '../src/helpers/serialization';

describe('base64url', () => {
  it('should encode a simple buffer', () => {
    const buf = Buffer.from('hello world');
    const encoded = base64urlEncode(buf);
    expect(encoded).toBe('aGVsbG8gd29ybGQ');
  });

  it('should decode a base64url string', () => {
    const decoded = base64urlDecode('aGVsbG8gd29ybGQ');
    expect(decoded.toString()).toBe('hello world');
  });

  it('should round-trip binary data', () => {
    const original = Buffer.from([0x00, 0x01, 0xff, 0xfe, 0x80, 0x7f]);
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);
    expect(Buffer.compare(original, decoded)).toBe(0);
  });

  it('should handle empty input', () => {
    const encoded = base64urlEncode(Buffer.alloc(0));
    expect(encoded).toBe('');
    const decoded = base64urlDecode('');
    expect(decoded.length).toBe(0);
  });

  it('should not include padding characters', () => {
    const buf = Buffer.from('a');
    const encoded = base64urlEncode(buf);
    expect(encoded).not.toContain('=');
  });

  it('should use url-safe characters', () => {
    // Data that would produce + and / in standard base64
    const buf = Buffer.from([0xfb, 0xff, 0xfe]);
    const encoded = base64urlEncode(buf);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
  });
});

describe('bufferToArrayBuffer', () => {
  it('should convert Buffer to ArrayBuffer', () => {
    const buf = Buffer.from([1, 2, 3]);
    const ab = bufferToArrayBuffer(buf);
    expect(ab).toBeInstanceOf(ArrayBuffer);
    expect(ab.byteLength).toBe(3);
    const view = new Uint8Array(ab);
    expect(view[0]).toBe(1);
    expect(view[1]).toBe(2);
    expect(view[2]).toBe(3);
  });
});

describe('serializeCreationOptions', () => {
  it('should serialize creation options with base64url encoding', () => {
    const options = {
      publicKey: {
        rp: { id: 'example.com', name: 'Example' },
        user: {
          id: new Uint8Array([1, 2, 3]),
          name: 'testuser',
          displayName: 'Test User',
        },
        challenge: new Uint8Array([10, 20, 30]),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: 60000,
        excludeCredentials: [],
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
      },
    };

    const serialized = serializeCreationOptions(options);

    expect(serialized.rp.id).toBe('example.com');
    expect(serialized.rp.name).toBe('Example');
    expect(serialized.user.name).toBe('testuser');
    expect(serialized.user.displayName).toBe('Test User');
    expect(typeof serialized.user.id).toBe('string'); // base64url
    expect(typeof serialized.challenge).toBe('string'); // base64url
    expect(serialized.pubKeyCredParams).toHaveLength(1);
    expect(serialized.pubKeyCredParams[0].alg).toBe(-7);
  });
});

describe('serializeRequestOptions', () => {
  it('should serialize request options with base64url encoding', () => {
    const options = {
      publicKey: {
        rpId: 'example.com',
        challenge: new Uint8Array([10, 20, 30]),
        allowCredentials: [
          { type: 'public-key', id: new Uint8Array([100, 200]) },
        ],
        userVerification: 'preferred',
        timeout: 60000,
      },
    };

    const serialized = serializeRequestOptions(options);

    expect(serialized.rpId).toBe('example.com');
    expect(typeof serialized.challenge).toBe('string');
    expect(serialized.allowCredentials).toHaveLength(1);
    expect(typeof serialized.allowCredentials[0].id).toBe('string');
    expect(serialized.userVerification).toBe('preferred');
  });
});
