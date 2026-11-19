// Jest globalSetup: runs in the real process (Jest sandboxes process.env in tests,
// so child processes would not see a PATH change made there). Creates fake
// fido2-token/-cred/-assert scripts and prepends them to PATH.
const { chmodSync, mkdtempSync, writeFileSync } = require('fs');
const { tmpdir } = require('os');
const { join } = require('path');

module.exports = async () => {
  const dir = mkdtempSync(join(tmpdir(), 'fake-fido2-'));
  const log = join(dir, 'assert.log');
  const pinFlag = join(dir, 'pinflag');
  const script = (name, body) => {
    const p = join(dir, name);
    writeFileSync(p, `#!/bin/bash\n${body}\n`);
    chmodSync(p, 0o755);
  };
  script('fido2-token', `[ "$1" = "-L" ] && { echo "/dev/hidraw9: vendor=0x1, product=0x2 (Fake)"; exit 0; }
[ "$1" = "-I" ] && { echo "options: rk, up, $(cat ${pinFlag})"; exit 0; }
exit 1`);
  script('fido2-cred', 'exit 1');
  // Logs argv, requires the -i request file, reads the PIN from stdin when -v is given (must be 1234).
  script('fido2-assert', `echo "ARGS: $*" > ${log}
uv=0; f=""
while [ -n "$1" ]; do
  [ "$1" = "-v" ] && uv=1
  [ "$1" = "-i" ] && f="$2"
  shift
done
[ -f "$f" ] || { echo "no -i file" >&2; exit 2; }
if [ $uv = 1 ]; then
  read -r pin
  echo "PIN: $pin" >> ${log}
  [ "$pin" = "1234" ] || { echo "bad pin" >&2; exit 3; }
fi
echo "YXV0aA=="; echo "c2ln"; echo "Y3JlZA=="`);
  process.env.FAKE_FIDO2_DIR = dir;
  process.env.PATH = `${dir}:${process.env.PATH}`;
};
