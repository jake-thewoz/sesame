use anyhow::{Result, anyhow};
use rusqlite::{Connection};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305};
use argon2::{Argon2, Params};

use crate::db;

pub fn derive_key_from_header(conn: &Connection, password: &str) -> Result<[u8; 32]> {
    let (salt, mem_kib, iters, parallelism) = db::load_kdf_params(&conn)?;
    let params = Params::new(mem_kib as u32, iters as u32, parallelism as u32, Some(32))
        .map_err(|e| anyhow!("bad Argon2 params: {e:?}"))?;
    derive_key(password, &salt, &params)
}

pub fn derive_key(password: &str, salt: &[u8], params: &Params) -> Result<[u8; 32]> {
    // Argon2id
    let argon = Argon2::new_with_secret(&[], argon2::Algorithm::Argon2id, argon2::Version::V0x13, params.clone())
        .map_err(|e| anyhow!("argon2 setup failed: {e:?}"))?;
    let mut out = [0u8; 32];
    argon.hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("argon2 derive failed: {e:?}"))?;
    Ok(out)
}

pub fn encrypt_blob(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| anyhow!("getrandom failed: {:?}", e))?;
    let ct = cipher.encrypt(chacha20poly1305::Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow!("encrypt failed: {e:?}"))?;

    Ok((ct, nonce))
}

pub fn decrypt_blob(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let pt = cipher
        .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| anyhow!("decrypt failed: {e:?}"))?;
    Ok(pt)
}
