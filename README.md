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
git clone https://github.com/YOUR-USERNAME/sesame.git
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

Sesame is **local-only**, meaning it lives entirely on your machine.

View the SECURITY.md to see the full threat model.

## License

This project is licensed under the Apache 2.0 License. View the [license](LICENSE) for details.
