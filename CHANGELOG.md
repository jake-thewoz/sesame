# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- `search` now searches username, notes, and title by default (no more `--deep`)

## [0.1.0] - 2025-08-24

### Added

- Initial public release of **Sesame**.
- CLI commands:
  - `init` – create a new vault
  - `add` – add a password entry
  - `list` – list all entries
  - `show` – retrieve a password entry
  - `delete` – delete an entry
  - `edit` – edit an entry
  - `gen` – generate a random secure password
  - `change-master` – change the master password
  - `search` – search for an entry
  - `backup` – backup the vault to another location
- Local encrypted vault storage.
  - [Argon2id](https://en.wikipedia.org/wiki/Argon2) for master key derivation
  - [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) for [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) vault encryption
  - [Zeroizing](https://docs.rs/zeroize/latest/zeroize/struct.Zeroizing.html) passwords, keys, and entries/data
