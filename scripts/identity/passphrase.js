// scripts/identity/passphrase.js
// TTY passphrase reader with no echo.
// there is NO env-var fallback — the passphrase is interactive-only. If stdin
// is not a TTY, throw (the caller must be run via `! node ...` so the prompt
// can read from the TTY).

const ETX = String.fromCharCode(3);     // Ctrl+C
const DEL = String.fromCharCode(127);   // backspace on most terminals

export async function readPassphrase(prompt) {
  if (!process.stdin.isTTY) {
    throw new Error('readPassphrase: stdin is not a TTY — no env-var fallback per architecture. Re-run via `! node ...` so the prompt can read from the TTY.');
  }
  process.stdout.write(prompt);
  return new Promise((resolve) => {
    let buf = '';
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (ch) => {
      const c = ch.toString('utf8');
      if (c === '\r' || c === '\n') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(buf);
        return;
      }
      if (c === ETX) {
        stdin.setRawMode(false);
        process.stdout.write('\n');
        process.exit(130);
      }
      if (c === DEL || c === '\b') {
        if (buf.length > 0) {
          buf = buf.slice(0, -1);
          process.stdout.write('\b \b');
        }
        return;
      }
      buf += c;
      process.stdout.write('*');
    };
    stdin.on('data', onData);
  });
}

// Echo-on TTY line reader (for non-secret prompts like the keychain account name).
// Returns the trimmed line. Falls back to OS username when prompt is empty AND
// the caller passes a `default` value (so the reviewer can just press Enter to
// accept the OS-username default — never a hardcoded operator name).
export async function readLine(prompt, { default: defaultValue = null } = {}) {
  if (!process.stdin.isTTY) {
    throw new Error('readLine: stdin is not a TTY — no env-var fallback. Re-run via `! node ...` so the prompt can read from the TTY.');
  }
  const suffix = defaultValue ? ` [${defaultValue}]: ` : ': ';
  process.stdout.write(prompt + suffix);
  return new Promise((resolve) => {
    let buf = '';
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (ch) => {
      const c = ch.toString('utf8');
      if (c === '\r' || c === '\n') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        const trimmed = buf.trim();
        resolve(trimmed || (defaultValue ? String(defaultValue) : ''));
        return;
      }
      if (c === ETX) {
        stdin.setRawMode(false);
        process.stdout.write('\n');
        process.exit(130);
      }
      if (c === DEL || c === '\b') {
        if (buf.length > 0) {
          buf = buf.slice(0, -1);
          process.stdout.write('\b \b');
        }
        return;
      }
      buf += c;
      process.stdout.write(c);
    };
    stdin.on('data', onData);
  });
}
