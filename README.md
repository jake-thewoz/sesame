# Sesame 🔐

*A lightweight, local-first password manager written in Rust.*

---

## Overview

Sesame is a secure, **local-only** password manager designed for developers and privacy-conscious users.  
It stores an encrypted vault on your machine- no cloud, no telemetry, and no dependencies you don’t control.

### Goals

- ✅ **Local-first** – Your data stays with you.  
- ✅ **Strong security** – Modern cryptography, sensible defaults.  
- ✅ **Simple CLI** – Easy to integrate with your own scripts and workflows.  
- ✅ **Extensible** – Foundation for future TUI/GUI or web integrations.

---

## Quick Start

### 1. Installation

**Build from source (Rust required):**

```bash
git clone https://github.com/jake-thewoz/sesame.git
cd sesame
cargo build --release
./target/release/sesame --help
```

### 2. Create your first vault

```bash
sesame init
```

### 3. Add a password

```bash
sesame add
(follow prompts)
```

### 4. View your vault items

```bash
sesame list
```

### 5. Retrieve a password

```bash
sesame show <id>
```

## Usage

Run `sesame --help` for the full list of commands and options.

## Roadmap

Track progress by viewing the current [issues](https://github.com/jake-thewoz/sesame/issues).

## Security

Sesame is designed to be as secure as possible. Features include:

- 🖥️ **Local-Only** – There is no network connectivity, so there are no attack surfaces outside of your own computer.
- 🔐 **Argon2id key derivation** – Winner of the Password Hashing Competition, memory-hard, and designed to resist brute-force attacks.
- ⚡ **ChaCha20-Poly1305 encryption** – Fast, secure, and trusted by projects like WireGuard and Cloudflare.
- 🧂 **Unique salts and nonces** – Every vault and operation uses unique parameters for maximum safety.
- 📦 **No unnecessary decryptions** – Vault items are only decrypted when specifically requested.
- 👻 **Memory safety** – All vault information is zeroized from memory after use, so no attacker can glean anything from imaging RAM after use.

Visit the [Security](SECURITY.md) tab to report a vulnerability, and check out the [Threat Model](THREAT_MODEL.md) for a more details.

## License

This project is licensed under the Apache 2.0 License. View the [license](LICENSE.md) for details.
