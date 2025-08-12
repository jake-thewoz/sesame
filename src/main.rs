use anyhow::{Result, anyhow};
use rusqlite::{Connection, params};
use std::io::{self, Write};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305};
use argon2::{Argon2, Params};
use rpassword::read_password;

// Schema for the vault
const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS header(
    id INTEGER PRIMARY KEY CHECK (id = 1),
    format_version INTEGER NOT NULL,
    kdf_salt BLOB NOT NULL,
    kdf_mem_kib INTEGER NOT NULL,
    kdf_iters INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS catalog(
    id INTEGER PRIMARY KEY CHECK (id = 1),
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS items(
    id TEXT PRIMARY KEY,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"#;

fn main() -> Result<()> {
    // 1) Open/create vault and ensure tables exist
    let conn = Connection::open("vault.db")?;
    conn.execute_batch(SCHEMA_SQL)?;
    println!("Schema ready.");

    // 2) Ensure header row exists
    ensure_header(&conn)?;
    println!("Header ready.");

    // 3) Load KDF inputs from header
    let (salt, mem_kib, iters, parallelism) = load_kdf_params(&conn)?;
    // Argon2 params (output key len = 32 bytes)
    let params = Params::new(mem_kib as u32, iters as u32, parallelism as u32, Some(32))
        .map_err(|e| anyhow!("bad Argon2 params: {e:?}"))?;

    // 4) Ask user for master password (no echo)
    print!("Enter master password: ");
    io::stdout().flush().ok();
    let password = read_password()?; //returns String

    // 5) Derive 32-byte kdye with Argon2id
    let key = derive_key(&password, &salt, &params)?;
    // wipe password from memory
    // TODO later we can zeroize with a crate, but dropping is fine now
    drop(password);

    // 6) Ensure encrypted empty catalog exists
    ensure_empty_catalog(&conn, &key)?;

    println!("Catalog ready. Done.");
    Ok(())
}

fn ensure_header(conn: &Connection) -> Result<()> {
    // Do we already have the header?
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM header WHERE id = 1",
        [],
        |row| row.get(0),
    )?;

    if count == 0 {
        // --- KDF parameters ---
        // mem_kib: 256 MiB, iters: 3, parallelism: 1
        let format_version: i64 = 1;
        let kdf_mem_kib: i64 = 256 * 1024; // 256 MiB in KiB
        let kdf_iters: i64 = 3;
        let kdf_parallelism: i64 = 1;

        // 16-byte random salt
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)
            .map_err(|e| anyhow::anyhow!("getrandom failed: {:?}", e))?;

        conn.execute(
            "INSERT INTO header (id, format_version, kdf_salt, kdf_mem_kib, kdf_iters, kdf_parallelism) VALUES (1, ?, ?, ?, ?, ?)",
            params![format_version, &salt[..], kdf_mem_kib, kdf_iters, kdf_parallelism],
        )?;

        println!("Inserted header with new random salt.");
    } else {
        println!("Header already present.");
    }

    Ok(())
}

fn load_kdf_params(conn: &Connection) -> Result<(Vec<u8>, i64, i64, i64)> {
    let (salt, mem_kib, iters, parallelism): (Vec<u8>, i64, i64, i64) = conn.query_row(
        "SELECT kdf_salt, kdf_mem_kib, kdf_iters, kdf_parallelism FROM header WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    )?;
    if salt.len() < 8 {
        return Err(anyhow!("header has invalid salt length"));
    }
    Ok((salt, mem_kib, iters, parallelism))
}

fn derive_key(password: &str, salt: &[u8], params: &Params) -> Result<[u8; 32]> {
    // Argon2id
    let argon = Argon2::new_with_secret(&[], argon2::Algorithm::Argon2id, argon2::Version::V0x13, params.clone())
        .map_err(|e| anyhow!("argon2 setup failed: {e:?}"))?;
    let mut out = [0u8; 32];
    argon.hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("argon2 derive failed: {e:?}"))?;
    Ok(out)
}

fn ensure_empty_catalog(conn: &Connection, key: &[u8; 32]) -> Result<()> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM catalog WHERE id = 1",
        [],
        |row| row.get(0)
    )?;

    if count == 0 {
        let plaintext = b"[]"; // empty JSON list
        let (ciphertext, nonce) = encrypt_blob(key, plaintext)?;
        let now = now_unix();
        conn.execute(
            "INSERT INTO catalog (id, nonce, ciphertext, updated_at) VALUES (1, ?, ?, ?)",
            params![&nonce[..], &ciphertext, now],
        )?;
        println!("Created encrypted empty catalog.");
    }

    Ok(())
}

fn encrypt_blob(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| anyhow!("getrandom failed: {:?}", e))?;
    let ct = cipher.encrypt(chacha20poly1305::Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow!("encrypt failed: {e:?}"))?;

    Ok((ct, nonce))
}

fn now_unix() -> i64 {
    // Simple, portable "seconds since epoch"
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    dur.as_secs() as i64
}
