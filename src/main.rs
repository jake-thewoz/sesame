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

// Structs for the data
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct ItemPlain {
    title: String,
    username: String,
    password: String,
    notes: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct CatalogEntry {
    id: String,
    title: String,
    updated_at: i64,
}

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

    // 5) Derive 32-byte key with Argon2id
    let key = derive_key(&password, &salt, &params)?;
    // wipe password from memory
    // TODO later we can zeroize with a crate, but dropping is fine now
    drop(password);

    // 6) Ensure encrypted empty catalog exists
    ensure_empty_catalog(&conn, &key)?;

    // 7) Read catalog and print
    list_items(&conn, &key)?;

    // 8) Prompt user to add + list
    let choice = read_line("Add an item now? (y/N): ")?;
    if choice.eq_ignore_ascii_case("y") {
        add_item_interactive(&conn, &key)?;
        println!("\nDecrypted catalog after add:");
        list_items(&conn, &key)?;
    }

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

fn decrypt_blob(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let pt = cipher
        .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| anyhow!("decrypt failed: {e:?}"))?;
    Ok(pt)
}

fn read_line(prompt: &str) -> Result<String> {
    use std::io::{self, Write};
    print!("{prompt}");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

fn new_id() -> Result<String> {
    // 16 random bytes -> hex string id
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b)
        .map_err(|e| anyhow!("getrandom failed: {:?}", e))?;
    Ok(b.iter().map(|x| format!("{:02x}", x)).collect())
}

fn load_catalog(conn: &Connection, key: &[u8; 32]) -> Result<Vec<CatalogEntry>> {
    // read row
    let (nonce, ct): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT nonce, ciphertext FROM catalog WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    // Guard and convert nonce Vec<u8> -> [u8; 12]
    if nonce.len() != 12 {
        return Err(anyhow!("catalog nonce has wrong length: {}", nonce.len()));
    }
    let mut n = [0u8; 12];
    n.copy_from_slice(&nonce);

    let pt = decrypt_blob(key, &n, &ct)?;
    if pt.is_empty() {
        return Ok(Vec::new());
    }
    let v: Vec<CatalogEntry> = serde_json::from_slice(&pt)
        .map_err(|e| anyhow!("catalog json decode failed: {e:?}"))?;
    Ok(v)
}

fn save_catalog(conn: &Connection, key: &[u8; 32], entries: &[CatalogEntry]) -> Result<()> {
    let pt = serde_json::to_vec(entries)?;
    let (ct, nonce) = encrypt_blob(key, &pt)?;
    let now = now_unix();
    conn.execute(
        "UPDATE catalog SET nonce = ?, ciphertext = ?, updated_at = ? WHERE id = 1",
        params![&nonce[..], &ct, now],
    )?;
    Ok(())
}

fn add_item_interactive(conn: &Connection, key: &[u8; 32]) -> Result<()> {
    // Collect fields (mask the secret input)
    let title = read_line("Title: ")?;
    let username = read_line("Username: ")?;
    print!("Password (hidden): ");
    std::io::stdout().flush().ok();
    let password = rpassword::read_password()?;
    let notes = read_line("Notes (optional): ")?;

    // Build plaintext item
    let item = ItemPlain {
        title: title.clone(),
        username,
        password,
        notes
    };
    let pt = serde_json::to_vec(&item)?;

    // Encrypt + insert into items
    let (ct, nonce) = encrypt_blob(key, &pt)?;
    let id = new_id()?;
    let now = now_unix();
    conn.execute(
        "INSERT INTO items (id, nonce, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        params![&id, &nonce[..], &ct, now, now],
    )?;

    // Update catalog
    let mut entries = load_catalog(conn, key)?;
    // If an entry with the same id exists (shouldn't), replace title; else push
    if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
        e.title = title;
        e.updated_at = now;
    } else {
        entries.push(CatalogEntry { id, title, updated_at: now });
    }

    save_catalog(conn, key, &entries)?;

    println!("Item added.");
    Ok(())
}

fn list_items(conn: &Connection, key: &[u8; 32]) -> Result<()> {
    let entries = load_catalog(conn, key)?;
    if entries.is_empty() {
        println!("(catalog is empty)");
        return Ok(());
    }
    println!("{:<36}  {:<30}  {}", "ID", "Title", "Updated");
    for e in entries {
        println!("{:<36}  {:<30}  {}", e.id, e.title, e.updated_at);
    }
    Ok(())
}
