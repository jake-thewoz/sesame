# Sesame 🔐

*A lightweight, local-first password manager written in Rust.*

---

## Overview

Sesame is a secure, **local-only** password manager designed for developers and privacy-conscious users.  
It stores an encrypted vault on your machine- no cloud, no telemetry, and no dependencies you don’t control.

## Security

Sesame is designed to be as secure as possible. Features include:

- 🖥️ **Local-Only** – There is no network connectivity, so there are no attack surfaces outside of your own computer.
- 🔐 **Argon2id key derivation** – Winner of the Password Hashing Competition, memory-hard, and designed to resist brute-force attacks.
- ⚡ **ChaCha20-Poly1305 encryption** – Fast, secure, and trusted by projects like WireGuard and Cloudflare.
- 🧂 **Unique salts and nonces** – Every vault and operation uses unique parameters for maximum safety.
- 📦 **No unnecessary decryptions** – Vault items are only decrypted when specifically requested.
- 👻 **Memory safety** – All vault information is zeroized from memory after use, like it was never there at all!

Visit the [Security](SECURITY.md) tab to report a vulnerability, and check out the [Threat Model](THREAT_MODEL.md) for more details.

---

## Quick Start

### 1. Installation

**Build from source ([Rust and Cargo required](https://doc.rust-lang.org/cargo/getting-started/installation.html)):**

```bash
git clone https://github.com/jake-thewoz/sesame.git
cd sesame
cargo build --release
cd target/release
./sesame --help
```

### 2. Create your first vault

```bash
./sesame init
```

### 3. Add a password

```bash
./sesame add
(follow prompts)
```

### 4. View your vault items

```bash
./sesame list
```

### 5. Retrieve a password

```bash
./sesame show <id>
```

## Usage

Run `sesame --help` for the full list of commands and options.

## Roadmap

Track progress by viewing the current [issues](https://github.com/jake-thewoz/sesame/issues).

## Download

Get the latest builds from the **[Releases](https://github.com/jake-thewoz/sesame/releases)** page.

| Platform | File |
|---|---|
| Windows (x86_64) | `sesame-v0.1.1-x86_64-pc-windows-msvc.tar.gz` |
| macOS (Apple Silicon) | `sesame-v0.1.1-aarch64-apple-darwin.tar.gz` |
| macOS (Intel) | `sesame-v0.1.1-x86_64-apple-darwin.tar.gz` |
| Linux (glibc) | `sesame-v0.1.1-x86_64-unknown-linux-gnu.tar.gz` |
| Linux (musl, portable) | `sesame-v0.1.1-x86_64-unknown-linux-musl.tar.gz` |

**Verify integrity** with the included `SHA256SUMS`:
- macOS/Linux: `shasum -a 256 -c SHA256SUMS`
- Windows (PowerShell): `Get-FileHash <file> -Algorithm SHA256`

## License

This project is licensed under the Apache 2.0 License. View the [license](LICENSE) for details.
