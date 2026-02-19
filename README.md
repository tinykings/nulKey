<h1 align="center">nulKey</h1>

<h3 align="center">A stateless password manager.</h3>
<h4 align="center">https://nulkey.pages.dev/</h4>



## How it works
No database, no sync, no cloud — just deterministic derivation. Enter your master password and a domain, get the same password every time.  
nulKey derives passwords using **PBKDF2-SHA256** (1,000,000 iterations) over a combination of:

- Your master password
- A **secret pattern** — 4 emoji symbols you select from a personalized keypad
- The domain / URL
- A username
- A counter (for rotating passwords without changing your master)

The same inputs always produce the same output. Nothing is stored anywhere.

### The emoji keypad

When you type your master password, the 10 keypad symbols are regenerated from a SHA-256 hash of it. This means:

- The symbols act as a **visual fingerprint** — a typo in your master password produces a completely different set of symbols, alerting you before you generate the wrong password.
- Your 4-symbol selection is an additional secret factor that never appears in any input field.

### Auto-clear

The generated password disappears after 60 seconds and the clipboard is cleared.

## Features

- **Stateless** — no passwords stored anywhere, on-device or server-side
- **Offline-capable** — installable PWA with full service worker caching
- **Passkey support** — optionally lock your master password behind biometrics using WebAuthn PRF; the master password is encrypted on-device and never stored in plaintext
- **Configurable output** — length (4–128), uppercase, lowercase, numbers, special characters
- **Counter field** — rotate a password for a specific site without changing your master
- **Strict CSP** — Content Security Policy with Trusted Types enforcement
- **CLI companion** — produce identical passwords from the terminal

## CLI

`nulkey-cli.py` is a Python 3 script that replicates the browser's derivation exactly.

```
python3 nulkey-cli.py
```

You'll be prompted for your master password, shown your dynamic keypad, asked to select 4 symbols, then prompted for domain, username, counter, and length. The output matches the web app for the same inputs.

No dependencies beyond the Python standard library.

## Deployment

Deployed as a static site via Cloudflare Workers using [Wrangler](https://developers.cloudflare.com/workers/wrangler/):

```
npx wrangler deploy
```

The `wrangler.jsonc` serves the current directory as static assets.

## Security notes

- The master password is zeroed from JS memory immediately after key derivation begins (`master = null`).
- Passkey storage uses **WebAuthn PRF** to encrypt the master password with a hardware-bound key — the plaintext never touches IndexedDB.
- The salt fed into PBKDF2 includes the sorted emoji selection, username, domain, and counter. Sorting the emoji makes the pattern order-independent (selecting symbols 1,3,2,4 is the same as 1,2,3,4).
- All crypto uses the browser's **SubtleCrypto** API — no third-party crypto libraries.
