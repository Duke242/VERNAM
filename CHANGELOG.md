# Changelog

All notable changes to VERNAM are recorded here. Versions are two-part
(MAJOR.MINOR) and bump in 0.1 steps per release (1.0, 1.1, 1.2, and so on).

The `.vrn` file format has its own version byte (currently `1`) inside each file,
independent of the tool version below; old files always keep opening.

## 1.2 (2026-08-17)

Adds a command-line tool. No format change, every existing .vrn file keeps opening.

- New `cli/vernam.js`: encrypt and decrypt from a terminal, with no file size limit. Everything streams through a 1 MiB buffer, so memory use is flat no matter how big the file is. This is the answer for files above 2 GiB in Firefox and Safari, where the browser falls back to an in-memory download.
- Zero dependencies: the CLI runs on plain Node 18+ and reuses the libsodium build already vendored for the web page, so files move freely between the CLI and the browser tool.
- Auto-detects encrypt vs decrypt, same as the web page. Also `vernam gen` (passphrase generator) and `vernam info` (header inspection).
- Passphrases are read from a hidden prompt, `--passphrase-file`, or `VERNAM_PASSPHRASE`. There is deliberately no `--passphrase` flag: command lines are visible to other processes.
- Output is written to a temp file and renamed only on success, so a failed or interrupted run never leaves a partial file behind. Outputs are created with 0600 permissions, and an existing file is never overwritten without `--force`.

## 1.1 (2026-06-18)

Security hardening. No format change, every existing .vrn file keeps opening.

- Reject a file whose header asks for an out-of-range Argon2 memory or operation cost, so a malformed or hostile file cannot exhaust memory when you open it.
- Validate the key-derivation algorithm field on decrypt.
- Sanitize the recovered filename before using it as a save name (strip path separators, control and bidi-override characters, and leading dots; cap the length).
- Wipe the derived key from memory after each operation.

## 1.0.0 (2026-06-16)

- First public release.
- Drag-and-drop file encryption, fully client-side, nothing uploaded.
- Argon2id key derivation + XChaCha20-Poly1305 secretstream, via vendored libsodium.
- Auto-detects encrypt vs decrypt, streams large files to disk, standard and high-security profiles.
