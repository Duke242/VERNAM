#!/usr/bin/env node
/*
 * VERNAM CLI, the command-line half of the browser tool.
 *
 * Same file format, same primitives, no size limit: everything streams through
 * a 1 MiB buffer, so a 500 GiB file costs the same memory as a 5 KiB one. Use
 * this when the browser cannot (Firefox and Safari cap the in-memory download
 * at 2 GiB), or when you want encryption in a script, a cron job, or over SSH.
 *
 * Zero dependencies. It reuses the libsodium build already vendored for the
 * web page (assets/vendor/sodium.js), so the crypto is byte-identical: a file
 * encrypted here opens at privacytools.io/encrypt, and the other way round.
 *
 * Made by PrivacyTools.io, https://www.privacytools.io
 * Licensed under the VERNAM License (see LICENSE): do whatever you like,
 * just keep a visible, linked credit to https://www.privacytools.io on any
 * hosted or distributed copy.
 *
 * File format (VRNM): see FORMAT.md. Kept in lockstep with assets/js/vernam.js.
 */

'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const nodeCrypto = require('crypto');

// ---------------------------------------------------------------------------
// Format constants. These MUST match assets/js/vernam.js and FORMAT.md.
// ---------------------------------------------------------------------------

const MAGIC = Buffer.from([0x56, 0x52, 0x4e, 0x4d]); // "VRNM"
const VERSION = 1;
const EXT = '.vrn';
const CHUNK = 1 << 20; // 1 MiB plaintext per secretstream message
const HEADER_LEN = 54;

const PROFILES = {
  standard: { opslimit: 3, memlimit: 256 * 1024 * 1024 },
  high: { opslimit: 4, memlimit: 1024 * 1024 * 1024 },
};

// Bounds for the KDF cost fields read from a file header on decrypt. They live
// outside the AEAD, so a hostile .vrn could request a huge Argon2 cost and take
// the machine down before the auth tag is ever checked.
const MAX_OPSLIMIT = 10;
const MIN_MEMLIMIT = 8 * 1024 * 1024; // 8 MiB
const MAX_MEMLIMIT = 1024 * 1024 * 1024; // 1 GiB (our highest profile)

// Same reasoning for the length prefix of each body message: it is plaintext,
// so a corrupt or hostile file can claim any size. We only ever write
// CHUNK + ABYTES; accept a bit more for other implementations, then refuse.
const MAX_CT = 16 * 1024 * 1024;

// Output files are created 0600. Decrypted plaintext should not be
// world-readable by default; chmod afterwards if you want it shared.
const OUT_MODE = 0o600;

// ---------------------------------------------------------------------------
// libsodium (the vendored browser build, loaded under Node)
// ---------------------------------------------------------------------------

const SODIUM_PATH = path.join(__dirname, '..', 'assets', 'vendor', 'sodium.js');
const WORDLIST_PATH = path.join(__dirname, '..', 'assets', 'js', 'wordlist.js');

let S = null;

async function ready() {
  if (S) return S;
  if (!fs.existsSync(SODIUM_PATH)) {
    throw new UserError(
      'Could not find ' + SODIUM_PATH + '.\n' +
      'Run this script from inside a checkout of the VERNAM repository.'
    );
  }
  // The bundle reaches for `self` to find crypto.getRandomValues. Node has the
  // WebCrypto object on globalThis, so pointing `self` at it is enough. We do
  // NOT define `window`: that would make the embedded Emscripten runtime take
  // its browser path and try to fetch the wasm over HTTP.
  if (typeof globalThis.self === 'undefined') globalThis.self = globalThis;
  require(SODIUM_PATH);
  if (!globalThis.sodium) throw new UserError('The vendored libsodium build did not load.');
  await globalThis.sodium.ready;
  S = globalThis.sodium;
  return S;
}

// The BIP-0039 wordlist is written for the browser (`window.PTWordlist = [...]`).
// Run it in a bare context with a stand-in `window` rather than polluting
// globalThis. The file is a plain array literal shipped in this repo.
let WORDLIST = null;
function loadWordlist() {
  if (WORDLIST) return WORDLIST;
  try {
    const src = fs.readFileSync(WORDLIST_PATH, 'utf8');
    const ctx = { window: {} };
    require('vm').runInNewContext(src, ctx, { filename: WORDLIST_PATH, timeout: 5000 });
    if (Array.isArray(ctx.window.PTWordlist) && ctx.window.PTWordlist.length >= 256) {
      WORDLIST = ctx.window.PTWordlist;
      return WORDLIST;
    }
  } catch (e) {
    /* fall through to the small built-in list */
  }
  WORDLIST = FALLBACK_WORDLIST;
  return WORDLIST;
}

const FALLBACK_WORDLIST = ('copper lantern saffron gravel willow tundra marble ember cipher nimbus ' +
  'quartz fathom cobalt meadow ardent falcon harbor ingot juniper kelp ' +
  'lumen mosaic nectar opal pewter ripple summit thorn umber velvet ' +
  'walnut zenith amber basalt cedar dapple flint glacier hazel iris').split(' ');

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// Errors we raise ourselves: printed as a plain message, no stack trace.
class UserError extends Error {}

function u32le(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

function looksEncrypted(head) {
  return !!head && head.length >= 4 && head.subarray(0, 4).equals(MAGIC);
}

function stripExt(name) {
  return name.endsWith(EXT) ? name.slice(0, -EXT.length) : name + '.decrypted';
}

// The original filename comes out of the authenticated metadata, but it was
// chosen by whoever encrypted the file, so treat it as untrusted when it turns
// into a path: keep only the basename, strip control and bidi-override
// characters, drop leading dots, and cap the length.
function sanitizeName(name) {
  let n = String(name == null ? '' : name);
  n = n.split(/[\\/]/).pop();
  // Drop C0/C1 controls, DEL, and bidi overrides/isolates. Written as code
  // point checks so this file stays plain ASCII.
  n = Array.from(n).filter(function (c) {
    const k = c.codePointAt(0);
    if (k < 0x20 || k === 0x7f) return false;      // C0 controls and DEL
    if (k >= 0x80 && k <= 0x9f) return false;      // C1 controls
    if (k >= 0x202a && k <= 0x202e) return false;  // bidi overrides
    if (k >= 0x2066 && k <= 0x2069) return false;  // bidi isolates
    return true;
  }).join("");
  n = n.replace(/^\.+/, '').replace(/\s+/g, ' ').trim();
  if (n.length > 200) {
    const dot = n.lastIndexOf('.');
    const ext = dot > 0 ? n.slice(dot) : '';
    n = n.slice(0, 200 - ext.length) + ext;
  }
  return n || 'decrypted';
}

function fmtBytes(n) {
  if (n == null) return '?';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? Math.round(v) : v.toFixed(v < 10 ? 2 : 1)) + ' ' + units[i];
}

async function readFull(fd, buf, length, position) {
  let got = 0;
  while (got < length) {
    const { bytesRead } = await fd.read(buf, got, length - got, position + got);
    if (bytesRead === 0) break; // EOF
    got += bytesRead;
  }
  return got;
}

async function writeAll(fd, chunk) {
  let off = 0;
  while (off < chunk.length) {
    const { bytesWritten } = await fd.write(chunk, off, chunk.length - off);
    off += bytesWritten;
  }
}

// ---------------------------------------------------------------------------
// Output sink: write to a temp file beside the destination, rename on success.
// VERNAM never leaves a partial output behind.
// ---------------------------------------------------------------------------

const pendingTemps = new Set();

function cleanupTempsSync() {
  for (const p of pendingTemps) {
    try { fs.unlinkSync(p); } catch (e) { /* already gone */ }
  }
  pendingTemps.clear();
}

async function makeSink(finalPath, force) {
  if (!force && fs.existsSync(finalPath)) {
    throw new UserError(finalPath + ' already exists. Pass --force to overwrite it.');
  }
  const dir = path.dirname(finalPath);
  const tmp = path.join(dir, '.' + path.basename(finalPath) + '.' + nodeCrypto.randomBytes(6).toString('hex') + '.part');
  const fd = await fsp.open(tmp, 'wx', OUT_MODE);
  pendingTemps.add(tmp);
  let bytes = 0;
  return {
    path: finalPath,
    async write(chunk) {
      await writeAll(fd, chunk);
      bytes += chunk.length;
    },
    async close() {
      await fd.close();
      await fsp.rename(tmp, finalPath);
      pendingTemps.delete(tmp);
      return bytes;
    },
    async abort() {
      try { await fd.close(); } catch (e) {}
      try { await fsp.unlink(tmp); } catch (e) {}
      pendingTemps.delete(tmp);
    },
  };
}

// ---------------------------------------------------------------------------
// Progress reporting (stderr, only on a terminal)
// ---------------------------------------------------------------------------

function makeProgress(label, total, enabled) {
  if (!enabled) return { update() {}, done() {} };
  const start = Date.now();
  let last = 0;
  let width = 0;
  const render = (done, final) => {
    const secs = (Date.now() - start) / 1000;
    const pct = total ? Math.min(100, Math.floor((done / total) * 100)) : 0;
    const rate = secs > 0 ? done / secs : 0;
    const line = label + ' ' + String(pct).padStart(3) + '%  ' +
      fmtBytes(done) + ' / ' + fmtBytes(total) + '  ' + fmtBytes(rate) + '/s';
    process.stderr.write('\r' + line.padEnd(width));
    width = Math.max(width, line.length);
    if (final) process.stderr.write('\n');
  };
  return {
    update(done) {
      const now = Date.now();
      if (now - last < 100) return; // ~10 repaints a second, no more
      last = now;
      render(done, false);
    },
    done(bytes) { render(bytes, true); },
  };
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

async function encryptFile(inPath, passphrase, opts) {
  const s = await ready();
  const prof = PROFILES[opts.profile === 'high' ? 'high' : 'standard'];
  const stat = await fsp.stat(inPath);
  if (stat.isDirectory()) throw new UserError(inPath + ' is a directory. Make an archive of it first (tar, zip).');
  const size = stat.size;
  const name = path.basename(inPath);
  const outPath = opts.out
    ? (isDir(opts.out) ? path.join(opts.out, name + EXT) : opts.out)
    : inPath + EXT;

  // Check this before Argon2id rather than after: nobody wants to wait out a
  // key derivation only to be told the output was already there.
  if (!opts.force && fs.existsSync(outPath)) {
    throw new UserError(outPath + ' already exists. Pass --force to overwrite it.');
  }

  if (!opts.quiet) process.stderr.write('Deriving key (Argon2id, ' + opts.profile + ' profile)...\n');
  const salt = s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
  const key = s.crypto_pwhash(
    s.crypto_secretstream_xchacha20poly1305_KEYBYTES,
    passphrase, salt, prof.opslimit, prof.memlimit, s.crypto_pwhash_ALG_ARGON2ID13
  );

  const init = s.crypto_secretstream_xchacha20poly1305_init_push(key);
  const state = init.state;
  const T_MSG = s.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
  const T_FIN = s.crypto_secretstream_xchacha20poly1305_TAG_FINAL;

  const sink = await makeSink(outPath, opts.force);
  const fd = await fsp.open(inPath, 'r');
  const prog = makeProgress('Encrypting', size, opts.progress);

  try {
    const head = Buffer.alloc(HEADER_LEN);
    MAGIC.copy(head, 0);
    head[4] = VERSION;
    head[5] = s.crypto_pwhash_ALG_ARGON2ID13;
    u32le(prof.opslimit).copy(head, 6);
    u32le(prof.memlimit).copy(head, 10);
    Buffer.from(salt).copy(head, 14);
    Buffer.from(init.header).copy(head, 30);
    await sink.write(head);

    // Message 0: the metadata, encrypted. Keeps the original filename secret
    // and lets decryption restore it.
    const meta = Buffer.from(JSON.stringify({ n: name, s: size }), 'utf8');
    let ct = s.crypto_secretstream_xchacha20poly1305_push(state, meta, null, T_MSG);
    await sink.write(u32le(ct.length));
    await sink.write(ct);

    if (size === 0) {
      ct = s.crypto_secretstream_xchacha20poly1305_push(state, new Uint8Array(0), null, T_FIN);
      await sink.write(u32le(ct.length));
      await sink.write(ct);
    } else {
      const buf = Buffer.allocUnsafe(CHUNK);
      let off = 0;
      while (off < size) {
        const want = Math.min(CHUNK, size - off);
        const got = await readFull(fd, buf, want, off);
        if (got === 0) throw new UserError('The input file shrank while it was being read.');
        off += got;
        const tag = off >= size ? T_FIN : T_MSG;
        ct = s.crypto_secretstream_xchacha20poly1305_push(state, buf.subarray(0, got), null, tag);
        await sink.write(u32le(ct.length));
        await sink.write(ct);
        prog.update(off);
      }
      prog.done(off);
    }

    const written = await sink.close();
    return { name: path.basename(outPath), path: outPath, size: written, inputSize: size };
  } catch (e) {
    await sink.abort();
    throw e;
  } finally {
    await fd.close().catch(() => {});
    try { s.memzero(key); } catch (e) {}
  }
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

function parseHeader(s, head) {
  if (!looksEncrypted(head)) throw new UserError('This is not a PrivacyTools.io encrypted file.');
  const version = head[4];
  if (version !== VERSION) throw new UserError('Unsupported file version.');
  const alg = head[5];
  const opslimit = head.readUInt32LE(6);
  const memlimit = head.readUInt32LE(10);
  // Validate the (unauthenticated) KDF parameters before deriving the key, so a
  // crafted file can't pick a rogue algorithm or an absurd memory cost.
  if (alg !== s.crypto_pwhash_ALG_ARGON2ID13) {
    throw new UserError('Unsupported file (unknown key-derivation algorithm).');
  }
  if (opslimit < 1 || opslimit > MAX_OPSLIMIT || memlimit < MIN_MEMLIMIT || memlimit > MAX_MEMLIMIT) {
    throw new UserError('This file requests unsupported key-derivation settings and was not opened.');
  }
  return {
    version, alg, opslimit, memlimit,
    salt: head.subarray(14, 14 + s.crypto_pwhash_SALTBYTES),
    streamHeader: head.subarray(30, 30 + s.crypto_secretstream_xchacha20poly1305_HEADERBYTES),
  };
}

async function decryptFile(inPath, passphrase, opts) {
  const s = await ready();
  const stat = await fsp.stat(inPath);
  if (stat.isDirectory()) throw new UserError(inPath + ' is a directory.');
  const size = stat.size;
  if (size < HEADER_LEN) throw new UserError('This is not a PrivacyTools.io encrypted file.');

  const fd = await fsp.open(inPath, 'r');
  let sink = null;
  const prog = makeProgress('Decrypting', size, opts.progress);

  try {
    const head = Buffer.alloc(HEADER_LEN);
    await readFull(fd, head, HEADER_LEN, 0);
    const h = parseHeader(s, head);

    if (!opts.quiet) process.stderr.write('Deriving key (Argon2id)...\n');
    const key = s.crypto_pwhash(
      s.crypto_secretstream_xchacha20poly1305_KEYBYTES,
      passphrase, h.salt, h.opslimit, h.memlimit, h.alg
    );
    let state;
    try {
      state = s.crypto_secretstream_xchacha20poly1305_init_pull(h.streamHeader, key);
    } finally {
      try { s.memzero(key); } catch (e) {}
    }
    const T_FIN = s.crypto_secretstream_xchacha20poly1305_TAG_FINAL;

    let pos = HEADER_LEN;
    const lenBuf = Buffer.alloc(4);

    async function pullNext() {
      if (await readFull(fd, lenBuf, 4, pos) < 4) throw new UserError('The file is truncated or corrupted.');
      const len = lenBuf.readUInt32LE(0);
      pos += 4;
      if (len < s.crypto_secretstream_xchacha20poly1305_ABYTES || len > MAX_CT) {
        throw new UserError('The file is truncated or corrupted.');
      }
      const ct = Buffer.allocUnsafe(len);
      if (await readFull(fd, ct, len, pos) < len) throw new UserError('The file is truncated or corrupted.');
      pos += len;
      const r = s.crypto_secretstream_xchacha20poly1305_pull(state, ct);
      if (!r) throw new UserError('Wrong passphrase, or the file is corrupted or was tampered with.');
      return r;
    }

    // The metadata comes first: we need the original name to open the output.
    let meta;
    try {
      const first = await pullNext();
      meta = JSON.parse(Buffer.from(first.message).toString('utf8'));
    } catch (e) {
      if (e instanceof SyntaxError) {
        throw new UserError('Wrong passphrase, or the file is corrupted or was tampered with.');
      }
      throw e;
    }

    const outName = sanitizeName(meta && meta.n ? meta.n : stripExt(path.basename(inPath)));
    const outPath = opts.out
      ? (isDir(opts.out) ? path.join(opts.out, outName) : opts.out)
      : path.join(path.dirname(inPath), outName);
    sink = await makeSink(outPath, opts.force);

    let done = false;
    while (pos < size) {
      const r = await pullNext();
      await sink.write(r.message);
      prog.update(pos);
      if (r.tag === T_FIN) { done = true; break; }
    }
    if (!done) throw new UserError('The file is truncated or corrupted.');
    prog.done(pos);

    const written = await sink.close();
    if (meta && typeof meta.s === 'number' && meta.s !== written) {
      // Every chunk was authenticated, so this should be unreachable; if it
      // ever fires, something is wrong and the output should not be trusted.
      throw new UserError('Decrypted size does not match the recorded size. The output was discarded.');
    }
    return { name: outName, path: outPath, size: written };
  } catch (e) {
    if (sink) await sink.abort();
    throw e;
  } finally {
    await fd.close().catch(() => {});
  }
}

function isDir(p) {
  try { return fs.statSync(p).isDirectory(); } catch (e) { return false; }
}

// ---------------------------------------------------------------------------
// Passphrase input
// ---------------------------------------------------------------------------

// Read a passphrase without echoing it. Prompts on stderr so stdout stays
// clean for piping.
function promptHidden(question) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      reject(new UserError('No terminal available to read a passphrase.'));
      return;
    }
    process.stderr.write(question);
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let out = '';
    const finish = (err, value) => {
      stdin.removeListener('data', onData);
      stdin.setRawMode(!!wasRaw);
      stdin.pause();
      process.stderr.write('\n');
      if (err) reject(err); else resolve(value);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        const code = ch.codePointAt(0);
        if (code === 13 || code === 10) { finish(null, out); return; }         // Enter
        if (code === 3) {                                                      // Ctrl+C
          process.stderr.write("\n");
          cleanupTempsSync();
          process.exit(130);
        }
        if (code === 4) { finish(null, out); return; }                         // Ctrl+D
        if (code === 127 || code === 8) { out = out.slice(0, -1); continue; }  // backspace
        if (code < 32) continue;                                               // other controls
        out += ch;
      }
    };
    stdin.on('data', onData);
  });
}

function readStdinAll() {
  return new Promise((resolve, reject) => {
    const parts = [];
    process.stdin.on('data', (d) => parts.push(d));
    process.stdin.on('end', () => resolve(Buffer.concat(parts).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

// First line only, with the trailing newline removed. That way a passphrase
// file written by `echo` or an editor behaves the way you expect.
function firstLine(text) {
  const nl = text.indexOf('\n');
  const line = nl === -1 ? text : text.slice(0, nl);
  return line.replace(/\r$/, '');
}

async function getPassphrase(opts, mode) {
  if (opts.passphraseFile != null) {
    const text = opts.passphraseFile === '-'
      ? await readStdinAll()
      : await fsp.readFile(opts.passphraseFile, 'utf8');
    return firstLine(text);
  }
  if (process.env.VERNAM_PASSPHRASE) return process.env.VERNAM_PASSPHRASE;
  if (!process.stdin.isTTY) {
    throw new UserError(
      'No passphrase given, and stdin is not a terminal.\n' +
      'Use --passphrase-file <path> (or - for stdin), or set VERNAM_PASSPHRASE.'
    );
  }
  const p = await promptHidden('Passphrase: ');
  if (mode === 'encrypt') {
    if (!p) throw new UserError('An empty passphrase is not allowed.');
    const again = await promptHidden('Repeat passphrase: ');
    if (again !== p) throw new UserError('The two passphrases did not match. Nothing was written.');
  }
  return p;
}

// ---------------------------------------------------------------------------
// Passphrase generation and strength (same rules as the browser tool)
// ---------------------------------------------------------------------------

function generatePassphrase(words) {
  const list = loadWordlist();
  words = words || 6;
  // Rejection-sample so the modulo does not bias the word distribution.
  const out = [];
  const limit = Math.floor(0x100000000 / list.length) * list.length;
  while (out.length < words) {
    const n = nodeCrypto.randomBytes(4).readUInt32LE(0);
    if (n >= limit) continue;
    out.push(list[n % list.length]);
  }
  return out.join('-');
}

const COMMON = ('password passw0rd 123456 12345678 qwerty letmein admin ' +
  'welcome iloveyou abc123 111111 000000 dragon monkey hunter2 login ' +
  'master superman trustno1 starwars').split(' ');

// Returns { bits, exact }. `exact` is true only when we can stand behind the
// number: a common passphrase, or one built entirely from wordlist words.
function analyze(p) {
  if (!p) return { bits: 0, exact: true };
  const s = p.trim();
  if (!s) return { bits: 0, exact: true };
  if (COMMON.indexOf(s.toLowerCase()) !== -1) return { bits: 0, exact: true };
  const toks = s.split(/[-\s]+/).filter(Boolean);
  if (toks.length >= 2) {
    const list = loadWordlist();
    const set = Object.create(null);
    for (const w of list) set[w] = 1;
    if (toks.every((t) => set[t.toLowerCase()])) {
      return { bits: toks.length * Math.log2(list.length), exact: true };
    }
  }
  let pool = 0;
  if (/[a-z]/.test(s)) pool += 26;
  if (/[A-Z]/.test(s)) pool += 26;
  if (/[0-9]/.test(s)) pool += 10;
  if (/[^A-Za-z0-9]/.test(s)) pool += 33;
  return { bits: s.length * Math.log2(pool || 1), exact: false };
}

function strengthLabel(bits) {
  if (bits < 28) return 'Weak';
  if (bits < 45) return 'Fair';
  if (bits < 60) return 'Good';
  return 'Strong';
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

async function infoFile(inPath) {
  const s = await ready();
  const stat = await fsp.stat(inPath);
  if (stat.size < HEADER_LEN) throw new UserError('This is not a PrivacyTools.io encrypted file.');
  const fd = await fsp.open(inPath, 'r');
  try {
    const head = Buffer.alloc(HEADER_LEN);
    await readFull(fd, head, HEADER_LEN, 0);
    const h = parseHeader(s, head);
    let profile = 'custom';
    for (const [name, p] of Object.entries(PROFILES)) {
      if (p.opslimit === h.opslimit && p.memlimit === h.memlimit) profile = name;
    }
    const lines = [
      'File:        ' + inPath,
      'Size:        ' + fmtBytes(stat.size) + ' (' + stat.size + ' bytes)',
      'Format:      VRNM version ' + h.version,
      'KDF:         Argon2id, opslimit ' + h.opslimit + ', memlimit ' + fmtBytes(h.memlimit),
      'Profile:     ' + profile,
      'Cipher:      XChaCha20-Poly1305 secretstream, ' + fmtBytes(CHUNK) + ' chunks',
      'Salt:        ' + Buffer.from(h.salt).toString('hex'),
      '',
      'The filename and size of the original are encrypted; decrypt to see them.',
    ];
    process.stdout.write(lines.join('\n') + '\n');
  } finally {
    await fd.close().catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// CLI plumbing
// ---------------------------------------------------------------------------

function readVersion() {
  try { return fs.readFileSync(path.join(__dirname, '..', 'VERSION'), 'utf8').trim(); } catch (e) { return 'unknown'; }
}

const HELP = `VERNAM, file encryption that runs on your machine and nowhere else.

USAGE
  vernam <file> [options]           encrypt, or decrypt if the file is a .vrn
  vernam encrypt <file> [options]   force encryption
  vernam decrypt <file> [options]   force decryption
  vernam gen [--words N]            generate a strong passphrase
  vernam info <file>                show a .vrn file's header
  vernam help | version

OPTIONS
  -o, --out <path>          output file (or an existing directory)
      --high                use the high-security KDF profile (1 GiB Argon2id)
  -f, --force               overwrite the output if it already exists
      --passphrase-file <p> read the passphrase from a file, or - for stdin
  -q, --quiet               no progress output
      --words N             word count for 'gen' (default 6)

PASSPHRASE
  With a terminal, VERNAM asks (and asks twice when encrypting). Otherwise it
  reads --passphrase-file, or the VERNAM_PASSPHRASE environment variable.
  There is deliberately no --passphrase flag: command lines are visible to
  every other process on the machine.

EXAMPLES
  vernam backup.tar                     -> backup.tar.vrn
  vernam backup.tar.vrn                 -> backup.tar
  vernam --high -o /media/usb/b.vrn backup.tar
  vernam gen --words 8
  VERNAM_PASSPHRASE="$(cat key.txt)" vernam -q huge.img

NOTES
  Files stream through a 1 MiB buffer, so size is not limited by memory.
  Output files are created with 0600 permissions.
  Nothing is ever sent anywhere. Unplug the network and it still works.
  Lose the passphrase and the file is gone: there is no recovery.

The format is documented in FORMAT.md and is identical to the browser tool at
https://www.privacytools.io/encrypt -- files move freely between the two.

Made by PrivacyTools.io -- https://www.privacytools.io
`;

function parseArgs(argv) {
  const opts = { _: [], profile: 'standard', force: false, quiet: false, out: null, passphraseFile: null, words: 6 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = (name) => {
      const v = argv[++i];
      if (v == null) throw new UserError(name + ' needs a value.');
      return v;
    };
    switch (a) {
      case '-o': case '--out': opts.out = need(a); break;
      case '--high': opts.profile = 'high'; break;
      case '--standard': opts.profile = 'standard'; break;
      case '-f': case '--force': opts.force = true; break;
      case '--passphrase-file': opts.passphraseFile = need(a); break;
      case '-q': case '--quiet': opts.quiet = true; break;
      case '--words': opts.words = parseInt(need(a), 10); break;
      case '-h': case '--help': opts._.unshift('help'); break;
      case '-v': case '--version': opts._.unshift('version'); break;
      default:
        if (a.startsWith('-') && a !== '-') throw new UserError('Unknown option: ' + a + '\nRun `vernam help` for usage.');
        opts._.push(a);
    }
  }
  return opts;
}

async function main(argv) {
  const opts = parseArgs(argv);
  let cmd = opts._[0];

  if (!cmd || cmd === 'help') { process.stdout.write(HELP); return 0; }
  if (cmd === 'version') { process.stdout.write('VERNAM ' + readVersion() + '\n'); return 0; }

  if (cmd === 'gen') {
    const n = opts.words;
    if (!Number.isInteger(n) || n < 1 || n > 64) throw new UserError('--words must be between 1 and 64.');
    const p = generatePassphrase(n);
    process.stdout.write(p + '\n');
    if (process.stderr.isTTY) {
      const bits = Math.round(analyze(p).bits);
      process.stderr.write(n + ' words, about ' + bits + ' bits of entropy (' + strengthLabel(bits) + ').\n' +
        'Store it somewhere safe. There is no recovery.\n');
    }
    return 0;
  }

  // Everything below takes a file.
  let target;
  if (cmd === 'encrypt' || cmd === 'decrypt' || cmd === 'info') {
    target = opts._[1];
    if (!target) throw new UserError('`vernam ' + cmd + '` needs a file. Run `vernam help` for usage.');
  } else {
    target = cmd;
    cmd = 'auto';
  }
  if (opts._.length > (cmd === 'auto' ? 1 : 2)) {
    throw new UserError('Only one file at a time. Run `vernam help` for usage.');
  }
  if (!fs.existsSync(target)) throw new UserError('No such file: ' + target);

  if (cmd === 'info') { await infoFile(target); return 0; }

  if (cmd === 'auto') {
    const fd = await fsp.open(target, 'r');
    const head = Buffer.alloc(4);
    try { await readFull(fd, head, 4, 0); } finally { await fd.close().catch(() => {}); }
    cmd = looksEncrypted(head) ? 'decrypt' : 'encrypt';
  }

  const progress = !opts.quiet && process.stderr.isTTY;
  const passphrase = await getPassphrase(opts, cmd);
  if (cmd === 'encrypt' && !passphrase) throw new UserError('An empty passphrase is not allowed.');

  if (cmd === 'encrypt' && !opts.quiet) {
    const a = analyze(passphrase);
    if (a.bits < 45) {
      process.stderr.write('Warning: that passphrase looks ' + strengthLabel(a.bits).toLowerCase() +
        '. `vernam gen` makes a strong one.\n');
    }
  }

  const res = cmd === 'encrypt'
    ? await encryptFile(target, passphrase, { ...opts, progress })
    : await decryptFile(target, passphrase, { ...opts, progress });

  if (!opts.quiet) {
    process.stderr.write((cmd === 'encrypt' ? 'Encrypted' : 'Decrypted') + ' -> ' + res.path +
      ' (' + fmtBytes(res.size) + ')\n');
  }
  return 0;
}

if (require.main === module) {
  process.on('SIGINT', () => { process.stderr.write('\nCancelled.\n'); cleanupTempsSync(); process.exit(130); });
  process.on('SIGTERM', () => { cleanupTempsSync(); process.exit(143); });

  main(process.argv.slice(2)).then(
    (code) => process.exit(code || 0),
    (err) => {
      cleanupTempsSync();
      if (err && err.name === 'AbortError') { process.exit(130); }
      const msg = err instanceof UserError ? err.message : (err && err.message) || String(err);
      process.stderr.write('vernam: ' + msg + '\n');
      if (!(err instanceof UserError) && process.env.VERNAM_DEBUG) process.stderr.write(err.stack + '\n');
      process.exit(1);
    }
  );
}

module.exports = { encryptFile, decryptFile, generatePassphrase, analyze, sanitizeName, looksEncrypted, ready };
