import {
  reconstructCreatedCredential,
  reconstructAssertedCredential,
} from '../src/helpers/credential';
import { base64urlEncode } from '../src/helpers/serialization';

describe('reconstructCreatedCredential', () => {
  const mockResult = {
    credentialId: 'test-cred-id',
    rawId: base64urlEncode(Buffer.from([1, 2, 3, 4])),
    attestationObject: base64urlEncode(Buffer.from([0xa1, 0x01, 0x02])),
    clientDataJson: base64urlEncode(Buffer.from('{"type":"webauthn.create"}')),
    type: 'public-key',
    authenticatorData: base64urlEncode(Buffer.from([0x00, 0x01, 0x02])),
    transports: ['internal'],
    publicKey: base64urlEncode(Buffer.from([0x04, 0x05, 0x06])),
    publicKeyAlgorithm: -7,
  };

  it('should reconstruct credential with correct id and type', () => {
    const cred = reconstructCreatedCredential(mockResult);
    expect(cred.id).toBe('test-cred-id');
    expect(cred.type).toBe('public-key');
  });

  it('should have rawId as ArrayBuffer', () => {
    const cred = reconstructCreatedCredential(mockResult);
    expect(cred.rawId).toBeInstanceOf(ArrayBuffer);
    expect(cred.rawId.byteLength).toBe(4);
  });

  it('should have response with clientDataJSON as ArrayBuffer', () => {
    const cred = reconstructCreatedCredential(mockResult);
    expect(cred.response.clientDataJSON).toBeInstanceOf(ArrayBuffer);
  });

  it('should have response with attestationObject as ArrayBuffer', () => {
    const cred = reconstructCreatedCredential(mockResult);
    expect(cred.response.attestationObject).toBeInstanceOf(ArrayBuffer);
  });

  it('should have getAuthenticatorData method', () => {
    const cred = reconstructCreatedCredential(mockResult);
    const authData = cred.response.getAuthenticatorData();
    expect(authData).toBeInstanceOf(ArrayBuffer);
  });

  it('should have getPublicKey method', () => {
    const cred = reconstructCreatedCredential(mockResult);
    const pk = cred.response.getPublicKey();
    expect(pk).toBeInstanceOf(ArrayBuffer);
  });

  it('should handle null publicKey', () => {
    const result = { ...mockResult, publicKey: null };
    const cred = reconstructCreatedCredential(result);
    expect(cred.response.getPublicKey()).toBeNull();
  });

  it('should have getPublicKeyAlgorithm method', () => {
    const cred = reconstructCreatedCredential(mockResult);
    expect(cred.response.getPublicKeyAlgorithm()).toBe(-7);
  });

  it('should have getTransports method', () => {
    const cred = reconstructCreatedCredential(mockResult);
    expect(cred.response.getTransports()).toEqual(['internal']);
  });

  it('should have getClientExtensionResults method', () => {
    const cred = reconstructCreatedCredential(mockResult);
    expect(cred.getClientExtensionResults()).toEqual({});
  });

  it('should have toJSON method', () => {
    const cred = reconstructCreatedCredential(mockResult);
    const json = cred.toJSON();
    expect(json.id).toBe('test-cred-id');
    expect(json.type).toBe('public-key');
    expect(json.response.attestationObject).toBe(mockResult.attestationObject);
    expect(json.response.clientDataJSON).toBe(mockResult.clientDataJson);
  });
});

describe('reconstructAssertedCredential', () => {
  const mockResult = {
    credentialId: 'test-cred-id',
    rawId: base64urlEncode(Buffer.from([1, 2, 3, 4])),
    authenticatorData: base64urlEncode(Buffer.from([0x00, 0x01, 0x02])),
    clientDataJson: base64urlEncode(Buffer.from('{"type":"webauthn.get"}')),
    signature: base64urlEncode(Buffer.from([0x30, 0x44])),
    userHandle: base64urlEncode(Buffer.from([0xaa, 0xbb])),
    type: 'public-key',
  };

  it('should reconstruct credential with correct id and type', () => {
    const cred = reconstructAssertedCredential(mockResult);
    expect(cred.id).toBe('test-cred-id');
    expect(cred.type).toBe('public-key');
  });

  it('should have rawId as ArrayBuffer', () => {
    const cred = reconstructAssertedCredential(mockResult);
    expect(cred.rawId).toBeInstanceOf(ArrayBuffer);
    expect(cred.rawId.byteLength).toBe(4);
  });

  it('should have response with authenticatorData as ArrayBuffer', () => {
    const cred = reconstructAssertedCredential(mockResult);
    expect(cred.response.authenticatorData).toBeInstanceOf(ArrayBuffer);
  });

  it('should have response with signature as ArrayBuffer', () => {
    const cred = reconstructAssertedCredential(mockResult);
    expect(cred.response.signature).toBeInstanceOf(ArrayBuffer);
  });

  it('should have response with userHandle as ArrayBuffer', () => {
    const cred = reconstructAssertedCredential(mockResult);
    expect(cred.response.userHandle).toBeInstanceOf(ArrayBuffer);
  });

  it('should handle null userHandle', () => {
    const result = { ...mockResult, userHandle: null };
    const cred = reconstructAssertedCredential(result);
    expect(cred.response.userHandle).toBeNull();
  });

  it('should have getClientExtensionResults method', () => {
    const cred = reconstructAssertedCredential(mockResult);
    expect(cred.getClientExtensionResults()).toEqual({});
  });

  it('should have toJSON method', () => {
    const cred = reconstructAssertedCredential(mockResult);
    const json = cred.toJSON();
    expect(json.id).toBe('test-cred-id');
    expect(json.response.signature).toBe(mockResult.signature);
    expect(json.response.userHandle).toBe(mockResult.userHandle);
  });
});
