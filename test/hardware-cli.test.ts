import { EventEmitter } from 'events';

const mockExecFile = jest.fn();
const mockSpawn = jest.fn();

jest.mock('child_process', () => ({
  execFile: mockExecFile,
  spawn: mockSpawn,
}));

import { HardwareKeyBackend } from '../src/authenticators/hardware';
import { base64urlEncode } from '../src/helpers/serialization';

function nextTick(callback: () => void): void {
  process.nextTick(callback);
}

function makeAuthData(): Buffer {
  return Buffer.from([0xaa, 0xbb, 0xcc]);
}

describe('HardwareKeyBackend CLI invocation', () => {
  beforeEach(() => {
    mockExecFile.mockReset();
    mockSpawn.mockReset();

    mockExecFile.mockImplementation((cmd: string, args: string[], callback: Function) => {
      if (cmd === 'fido2-token' && args[0] === '-L') {
        callback(null, { stdout: '/dev/hidraw0: vendor product\n', stderr: '' });
        return;
      }

      callback(new Error(`unexpected execFile call: ${cmd}`), { stdout: '', stderr: '' });
    });
  });

  it('uses an input file for fido2-assert and reuses one PIN for resident lookup', async () => {
    const stdinWrites: string[] = [];
    const spawnCalls: Array<{ cmd: string; args: string[]; options: Record<string, unknown> }> = [];
    const userHandle = Buffer.from([1, 2, 3]);
    const credentialId = Buffer.from([4, 5, 6]);

    mockSpawn.mockImplementation((cmd: string, args: string[], options: Record<string, unknown>) => {
      spawnCalls.push({ cmd, args, options });

      const proc = new EventEmitter() as EventEmitter & {
        stdout: EventEmitter;
        stderr: EventEmitter;
        stdin: { write: (value: string) => void; end: () => void };
        kill: () => void;
      };

      proc.stdout = new EventEmitter();
      proc.stderr = new EventEmitter();
      proc.stdin = {
        write: (value: string) => {
          stdinWrites.push(value);
        },
        end: () => {
          nextTick(() => {
            if (cmd === 'fido2-assert') {
              proc.stdout.emit('data', Buffer.from([
                Buffer.from('hash').toString('base64'),
                'example.com',
                makeAuthData().toString('base64'),
                Buffer.from([0x30, 0x44]).toString('base64'),
                userHandle.toString('base64'),
              ].join('\n')));
            } else if (cmd === 'fido2-token') {
              proc.stdout.emit(
                'data',
                Buffer.from(`00: ${credentialId.toString('base64')} Test User ${userHandle.toString('base64')} es256 rk\n`),
              );
            }

            proc.emit('close', 0);
          });
        },
      };
      proc.kill = jest.fn();

      return proc;
    });

    const backend = new HardwareKeyBackend();
    const result = await backend.getAssertion({
      origin: 'https://example.com',
      rpId: 'example.com',
      challenge: base64urlEncode(Buffer.from('challenge')),
      userVerification: 'required',
      hardwareUserVerification: async () => ({ pin: '123456' }),
    });

    expect(result.credentialId).toBe(base64urlEncode(credentialId));
    expect(stdinWrites).toEqual(['123456\n', '123456\n']);

    const assertCall = spawnCalls.find((call) => call.cmd === 'fido2-assert');
    expect(assertCall?.args).toContain('-i');
    expect(assertCall?.args.at(-1)).toBe('/dev/hidraw0');
    expect(assertCall?.args).toContain('-t');
    expect(assertCall?.args).toContain('pin=true');
    expect(assertCall?.options.detached).toBe(true);
    expect(assertCall?.options.stdio).toEqual(['pipe', 'pipe', 'pipe']);

    const tokenCall = spawnCalls.find((call) => call.cmd === 'fido2-token');
    expect(tokenCall?.args).toEqual(['-L', '-k', 'example.com', '/dev/hidraw0']);
    expect(tokenCall?.options.detached).toBe(true);
    expect(tokenCall?.options.stdio).toEqual(['pipe', 'pipe', 'pipe']);
  });

  it('retries the PIN prompt when fido2-assert reports an invalid PIN', async () => {
    const stdinWrites: string[] = [];
    const promptRequests: Array<{ previousError?: string }> = [];
    const userHandle = Buffer.from([1, 2, 3]);
    const credentialId = Buffer.from([4, 5, 6]);
    let assertAttempts = 0;

    mockSpawn.mockImplementation((cmd: string) => {
      const proc = new EventEmitter() as EventEmitter & {
        stdout: EventEmitter;
        stderr: EventEmitter;
        stdin: { write: (value: string) => void; end: () => void };
        kill: () => void;
      };

      proc.stdout = new EventEmitter();
      proc.stderr = new EventEmitter();
      proc.stdin = {
        write: (value: string) => {
          stdinWrites.push(value);
        },
        end: () => {
          nextTick(() => {
            if (cmd === 'fido2-assert') {
              assertAttempts += 1;

              if (assertAttempts === 1) {
                proc.stderr.emit(
                  'data',
                  Buffer.from('fido2-assert: fido_dev_get_assert: FIDO_ERR_PIN_INVALID\n'),
                );
                proc.emit('close', 1);
                return;
              }

              proc.stdout.emit('data', Buffer.from([
                Buffer.from('hash').toString('base64'),
                'example.com',
                makeAuthData().toString('base64'),
                Buffer.from([0x30, 0x44]).toString('base64'),
                userHandle.toString('base64'),
              ].join('\n')));
            } else if (cmd === 'fido2-token') {
              proc.stdout.emit(
                'data',
                Buffer.from(`00: ${credentialId.toString('base64')} Test User ${userHandle.toString('base64')} es256 rk\n`),
              );
            }

            proc.emit('close', 0);
          });
        },
      };
      proc.kill = jest.fn();

      return proc;
    });

    const backend = new HardwareKeyBackend();
    const result = await backend.getAssertion({
      origin: 'https://example.com',
      rpId: 'example.com',
      challenge: base64urlEncode(Buffer.from('challenge')),
      userVerification: 'required',
      hardwareUserVerification: async (request) => {
        promptRequests.push({ previousError: request.previousError });
        return { pin: request.previousError ? '654321' : '123456' };
      },
    });

    expect(result.credentialId).toBe(base64urlEncode(credentialId));
    expect(assertAttempts).toBe(2);
    expect(stdinWrites).toEqual(['123456\n', '654321\n', '654321\n']);
    expect(promptRequests).toEqual([
      { previousError: undefined },
      { previousError: 'pin-invalid' },
    ]);
  });
});
