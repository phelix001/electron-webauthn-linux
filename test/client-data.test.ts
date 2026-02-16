import {
  generateClientDataJSON,
  generateClientDataJSONBuffer,
} from '../src/helpers/client-data';

describe('generateClientDataJSON', () => {
  it('should produce valid JSON with correct key ordering', () => {
    const challenge = new Uint8Array([10, 20, 30]);
    const json = generateClientDataJSON('webauthn.create', challenge, 'https://example.com');
    const parsed = JSON.parse(json);

    expect(parsed.type).toBe('webauthn.create');
    expect(parsed.challenge).toBeDefined();
    expect(typeof parsed.challenge).toBe('string');
    expect(parsed.origin).toBe('https://example.com');
    expect(parsed.crossOrigin).toBeUndefined();
  });

  it('should include crossOrigin when specified', () => {
    const challenge = new Uint8Array([1]);
    const json = generateClientDataJSON('webauthn.get', challenge, 'https://example.com', true);
    const parsed = JSON.parse(json);

    expect(parsed.crossOrigin).toBe(true);
  });

  it('should not include crossOrigin when not specified', () => {
    const challenge = new Uint8Array([1]);
    const json = generateClientDataJSON('webauthn.get', challenge, 'https://example.com');
    expect(json).not.toContain('crossOrigin');
  });

  it('should base64url-encode the challenge', () => {
    const challenge = new Uint8Array([0xfb, 0xff, 0xfe]);
    const json = generateClientDataJSON('webauthn.create', challenge, 'https://example.com');
    const parsed = JSON.parse(json);

    // Should not contain standard base64 chars + or /
    expect(parsed.challenge).not.toContain('+');
    expect(parsed.challenge).not.toContain('/');
    expect(parsed.challenge).not.toContain('=');
  });
});

describe('generateClientDataJSONBuffer', () => {
  it('should return a Buffer with UTF-8 encoded JSON', () => {
    const challenge = new Uint8Array([10, 20, 30]);
    const buf = generateClientDataJSONBuffer('webauthn.create', challenge, 'https://example.com');

    expect(buf).toBeInstanceOf(Buffer);
    const json = buf.toString('utf-8');
    const parsed = JSON.parse(json);
    expect(parsed.type).toBe('webauthn.create');
    expect(parsed.origin).toBe('https://example.com');
  });
});
