# Sesame – Threat Model (WIP)

## 1. Scope & Goals

Sesame is a **local-first CLI password manager**. There is **no network/sync** functionality. The goal is to protect secrets at rest and minimize exposure in memory and OS facilities (e.g., clipboard).

Out of scope (for now): multi-user sharing, remote storage, browser integration.

## 2. Assets

- **A1. Master password** (user input)
- **A2. Derived keys** (KDF outputs)
- **A3. Vault contents** (decrypted secrets in memory)
- **A4. Vault file** (encrypted on disk)
- **A5. KDF parameters & salts** (in vault header)
- **A6. Binary + release artifacts** (supply chain)
- **A7. Logs/config** (should never contain secrets)
- **A8. Backups** (user-managed copies)

## 3. Actors & Assumptions

- **User:** intends to protect their secrets.
- **Local adversary:** another account on the same machine with limited access.
- **Malware:** code running under user privileges.
- **Evil maid:** temporary physical access to unlocked or sleeping machine.
- **Future contributors:** may submit code/PRs.

**Assumptions:** OS is not already compromised; secure RNG available; user can set reasonable filesystem permissions.

## 4. Architecture & Data Flow (overview)

1. User enters **master password** → **Argon2id** derives KEK (salt from header).
2. Vault header includes: file format version, KDF params, salt, AEAD nonce.
3. Vault body is encrypted via **AEAD (XChaCha20-Poly1305)**; decrypt to memory on demand.
4. Optional: copy secret to **clipboard** (auto-clear after N seconds).
5. Writes are **atomic** (write temp, fsync, rename). Integrity verified on load.

**Trust boundaries:** disk ↔ process memory; process ↔ clipboard; releases ↔ local machine.

## 5. Threats (STRIDE) & Mitigations

### Spoofing

- **T1:** User runs trojan binary named `sesame`.  
  **M:** Publish checksums; optional signature (minisign/sigstore); document verification; use GitHub Releases CI.

### Tampering

- **T2:** Attacker modifies vault header to weaken KDF (downgrade).  
  **M:** Store KDF params inside the authenticated header; refuse unsafe downgrades; warn on weaker-than-last-seen params.

- **T3:** Corrupting the vault to cause data loss.  
  **M:** Atomic writes + fsync; optional backup rotation; integrity check on open; distinct magic/version bytes.

### Repudiation

- **T4:** No record of destructive ops.  
  **M:** Optional minimal audit entries (timestamps, operation names) **without secrets**; configurable/opt-out.

### Information Disclosure

- **T5:** Plaintext secrets linger in RAM or swap.  
  **M:** Minimize lifetime; zeroize buffers; avoid large allocations; advise disabling swap or using encrypted swap.

- **T6:** Clipboard exposes secrets to other apps.  
  **M:** Opt-in copy; auto-clear timer; warn user; optional OSC52 over TTY (where supported).

- **T7:** Secrets printed to stdout, logs, or crash dumps.  
  **M:** Redact outputs; never log secrets; consider disabling crash dumps or documenting how to do so per OS.

- **T8:** Weak master password enables offline cracking.  
  **M:** Argon2id with calibrated params; optional password-strength feedback; minimum length policy.

### Denial of Service

- **T9:** Overly strong KDF params make unlock impractical on target machines.  
  **M:** Interactive tuning; store calibrated defaults by machine; allow a safe “--kdf-preview” utility.

### Elevation of Privilege

- **T10:** Over-permissive file permissions.  
  **M:** Set restrictive permissions on first write; check & warn if too open; document secure locations.

## 6. Security Controls (planned / implemented)

- **KDF:** Argon2id, unique salt per vault. - ✅ implemented with hard-coded sensible parameters.
- **AEAD:** XChaCha20-Poly1305, unique nonce per encryption, header authenticated. - ✅ implemented
- **Secure randomness:** OS CSPRNG - ✅ implemented with Rust standard libs.
- **Zeroization:** Use crates or manual `zeroize` on buffers holding secrets. - ✅ implemented with [zeroize](https://docs.rs/zeroize/latest/zeroize/index.html)
- **Clipboard:** `--copy` opt-in with `--clear-after SECONDS`. - 🟡 partially implemented, needs more testing on all target OSs.
- **Filesystem:** atomic write; restrictive mode (0o600 on Unix); path normalization. - 🟡 Partially implemented. Unix has 0o600 permissions on vault, but Windows has no similar protections yet.
- **Logging:** off by default or redacted; no secrets ever. - ✅ implemented. Minimal logging, no secrets.
- **Build/Release:** CI builds, checksums - ✅ implemented (release.yml, SHA256SUMS)
- **Dependencies:** `cargo audit`/`cargo deny`; Dependabot weekly. - 🟡 planned

## 7. Residual Risks & User Guidance

- If the host OS is compromised, secrets are at risk (keylogger/RAM scraping).  
- Clipboard is inherently risky; use it sparingly.
- Keep regular encrypted backups of the vault file in case of corruption.

## 8. Testing & Verification

- KATs for encrypt/decrypt; reject wrong key; reject tampered header/body.
- Fuzz vault header parsing.
- Unit tests for KDF parameter serialization; cross-version compatibility test fixtures.
- CI gates: build, tests, `cargo fmt`, `clippy`, `audit`.

## 9. Change Management

- **File format versioning:** bump on incompatible changes; provide migration tool.
- **KDF policy:** only equal or stronger than previous; warn/refuse on downgrade.
- Document changes in `CHANGELOG.md` and Releases.

