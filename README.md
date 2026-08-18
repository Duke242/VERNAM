<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/vernam-logo-dark.svg">
  <img alt="VERNAM" src=".github/assets/vernam-logo-light.svg" width="360">
</picture>


**Encrypt any file, right in your browser.**
Free, open source, and fully client-side. Nothing is ever uploaded.

**[Try it live →](https://www.privacytools.io/encrypt)** · **[VERNAM.app →](https://VERNAM.app)**

 ⭐️ **We just launched, and a single star genuinely helps.**
 VERNAM is free and open source, with nothing to sell and no one funding it. If you think strong
 encryption should be free for everyone, please
 **[star us on GitHub](https://github.com/LifetimeLabsDev/VERNAM)**. It helps more
 people find the project and keeps it alive.

[![VERNAM on PrivacyTools.io](https://privacytools.io/badge/vernam/featured-light.svg)](https://privacytools.io/app/vernam)

[![GitGem](https://gitgem.org/api/badge/github/LifetimeLabsDev/VERNAM.svg)](https://gitgem.org/github/LifetimeLabsDev/VERNAM)
</div>

---

VERNAM is a tiny, drag-and-drop file encryptor that runs entirely in the browser.
Drop a file, set a passphrase, done. Drop the encrypted file back in, type the
passphrase, get your original. That is the whole product.

It is named after **Gilbert Vernam**, inventor of the one-time pad, the only cipher
ever mathematically proven unbreakable. VERNAM (the tool) is not a literal one-time
pad, but it is built on its descendant: XChaCha20, a modern stream cipher.

Made by [PrivacyTools.io](https://www.privacytools.io).

## Why it is different

- **Nothing leaves your device.** No uploads, no cloud, no servers. Go offline and it still works.
- **No account, ever.** No sign-up, no email, no tracking.
- **Any file, any size.** Large files stream straight to disk instead of eating your memory.
- **Tamper-evident.** Change one byte and decryption fails loudly.
- **Open source.** Audit it, fork it, host it yourself.

## Cryptography

- **Key derivation:** Argon2id stretches your passphrase into a 256-bit key.
- **Encryption:** XChaCha20-Poly1305 via libsodium's `secretstream` (authenticated, streaming).
- **Integrity:** per-chunk authentication plus truncation and reordering detection.

These are the same peer-reviewed primitives behind Signal, WireGuard, and 1Password.
The container format is documented in [FORMAT.md](FORMAT.md).

> **One honest warning:** there is no backdoor and no recovery. If you forget the
> passphrase, the file is gone. That is the point. Use the built-in generator and
> store it somewhere safe.

## Please host your own copy

We *want* this everywhere. The more places strong, free encryption lives, the harder
it is to take away. Put VERNAM on your own domain, your blog, your company intranet,
a USB stick, anywhere. There is **no build step and no dependencies to install**, it is
a handful of static files.

**Run it locally:**

```sh
git clone https://github.com/LifetimeLabsDev/VERNAM.git
cd VERNAM
python3 -m http.server 8000
# open http://localhost:8000
```

(Any static file server works. Opening `index.html` as a `file://` will not, because
browsers block WebAssembly and the File System Access API on the `file:` scheme.)

**Put it on the web:** drop the folder on any static host (your own nginx, GitHub
Pages, Netlify, Cloudflare Pages). No backend, no config. That is exactly how
[VERNAM.app](https://VERNAM.app) runs.

Streaming-to-disk for large files uses the File System Access API (Chromium-based
browsers). Firefox and Safari fall back to an in-memory download, capped at 2 GiB.
For anything bigger there, use the [command line tool](#the-command-line-tool),
which has no size limit at all.

## The command line tool

`cli/vernam.js` is the same encryptor without a browser: same format, same
primitives, no size limit. It streams everything through a 1 MiB buffer, so a
500 GiB file uses the same memory as a 5 KiB one. Reach for it when the browser
cannot (Firefox and Safari cap the in-memory download at 2 GiB), or when you
want encryption inside a script, a cron job, or over SSH.

It needs **Node 18 or newer and nothing else**. There is no `npm install`: it
reuses the libsodium build already vendored for the web page, so a file
encrypted on the command line opens in the browser tool and the other way round.

```sh
git clone https://github.com/LifetimeLabsDev/VERNAM.git
cd VERNAM
node cli/vernam.js help

# put it on your PATH, if you like
ln -s "$PWD/cli/vernam.js" /usr/local/bin/vernam
```

**Everyday use.** Direction is auto-detected from the file, exactly like the web
page: drop in anything and it encrypts, drop in a `.vrn` and it decrypts.

```sh
vernam backup.tar          # -> backup.tar.vrn, asks for a passphrase (twice)
vernam backup.tar.vrn      # -> backup.tar, asks once
vernam gen                 # a strong passphrase, 6 words from BIP-0039
vernam info backup.tar.vrn # what's in the header, without decrypting
```

| Option | What it does |
|--------|--------------|
| `-o, --out <path>` | Write somewhere else. A directory is fine; the name comes from inside the file. |
| `--high` | High-security KDF profile (1 GiB Argon2id instead of 256 MiB). |
| `-f, --force` | Overwrite the output if it already exists. Off by default. |
| `--passphrase-file <p>` | Read the passphrase from a file, or `-` for stdin. |
| `-q, --quiet` | No progress output. |
| `--words N` | Word count for `vernam gen` (default 6). |

**Passphrases.** On a terminal, VERNAM asks (twice, when encrypting) and never
echoes what you type. Without a terminal it reads `--passphrase-file` or the
`VERNAM_PASSPHRASE` environment variable. There is deliberately no
`--passphrase` flag: command lines are visible to every other process on the
machine.

```sh
# unattended, in a script
VERNAM_PASSPHRASE="$(cat /run/secrets/backup-key)" vernam -q nightly.tar
vernam --passphrase-file /run/secrets/backup-key nightly.tar.vrn
```

**Safety.** The output goes to a temp file and is renamed only after the last
chunk authenticates, so a wrong passphrase, a corrupt file, or a Ctrl+C never
leaves a partial file behind. Outputs are created `0600`. Your input file is
never touched or deleted.

```
$ vernam huge.img
Passphrase:
Repeat passphrase:
Deriving key (Argon2id, standard profile)...
Encrypting  63%  1.87 GiB / 2.97 GiB  268 MiB/s
Encrypted -> huge.img.vrn (2.97 GiB)
```

## The one condition: link back to PrivacyTools.io

VERNAM is released under the **[VERNAM License](LICENSE)** (a custom, WTFPL-style
license, not OSI-approved). Do almost anything you like with it, copy it, change it,
sell it, ship it, **on one condition: keep a clear, visible, working link back to
[PrivacyTools.io](https://www.privacytools.io)** on any hosted or distributed copy.

Concretely, if you run VERNAM as a website or app, put a real, clickable link to
`https://www.privacytools.io` somewhere ordinary visitors can see it. A footer line is
plenty, for example:

> Powered by [VERNAM](https://www.privacytools.io/encrypt), from [PrivacyTools.io](https://www.privacytools.io).

Make the link work, and do not imply that PrivacyTools.io endorses your version. That is
the entire ask. We would rather you spread this far and wide than lock it down, the
link is how we keep the lights on. The exact terms (including the patent grant and the
names/trademark note) are in [LICENSE](LICENSE).

VERNAM also bundles a few permissive third-party components (libsodium under the ISC
License, the BIP-0039 wordlist under the MIT License); keep their notices in
[THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt) when you redistribute. The crypto
primitives themselves (XChaCha20-Poly1305, Argon2id, BLAKE2) are open, unpatented
standards.

## Brand assets

Writing about VERNAM, or adding that credit link? Grab the logo, the cipher-grid mark,
and the color palette from the PrivacyTools.io brand kit instead of recreating them by
hand:

**https://www.privacytools.io/brand#vernam**

## What is in here

| File | What it is |
|------|------------|
| `index.html` | The page: hero, the tool card, and the marketing sections. |
| `assets/css/card.css` | Styles for the tool card. |
| `assets/js/vernam-ui.js` | Wiring for the tool card (drives the engine). |
| `assets/js/vernam.js` | The crypto engine. Exposes `window.Vernam`. |
| `cli/vernam.js` | The [command line tool](#the-command-line-tool). Node 18+, no dependencies. |
| `assets/js/wordlist.js` | BIP-0039 English wordlist for the passphrase generator. |
| `assets/vendor/sodium.js` | Vendored libsodium (ISC). No CDN, works offline. |
| `FORMAT.md` | The `.vrn` file format spec. |
| `LICENSE` | The VERNAM License (see above). |
| `THIRD-PARTY-LICENSES.txt` | Notices for the bundled components. |

> The tool card (`index.html`'s card markup, `assets/css/card.css`, `assets/js/vernam-ui.js`) and the engine
> (`assets/js/vernam.js`) are generated from the canonical PrivacyTools.io source, so this copy
> always matches the live tool at privacytools.io/encrypt.

### Using the engine on its own

```html
<script src="assets/vendor/sodium.js"></script>
<script src="assets/js/wordlist.js"></script>
<script src="assets/js/vernam.js"></script>
<script>
  await Vernam.ready();
  // encryptFile / decryptFile take a File and a passphrase
  const result = await Vernam.encryptFile(file, "correct horse battery staple", {
    profile: "standard",            // or "high"
    onStage:    s => console.log(s),
    onProgress: f => console.log(Math.round(f * 100) + "%"),
  });
  // Vernam.detect(file) -> "encrypt" | "decrypt"
  // Vernam.generatePassphrase(6), Vernam.strength(str)
</script>
```

---

Made with care by **[PrivacyTools.io](https://www.privacytools.io)** · fighting surveillance since 2015
