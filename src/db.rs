use anyhow::{Result, anyhow, bail};
use rusqlite::{Connection, params};
use zeroize::Zeroizing;
use std::path::Path;
use argon2::Params;

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

pub struct Vault {
    pub conn: rusqlite::Connection,
    pub key: Zeroizing<[u8; 32]>,
}

impl Vault {
    // Open/create DB, ensure schema/header, derive key, ensure catalog exists
    pub fn open(db_path: &str, password: &str) -> Result<Self> {
        let new_file = !Path::new(db_path).exists();
        let conn = Connection::open(db_path)?;

        if new_file {
            println!("Creating new vault at {}", db_path);
        }

        // Restrict file permissions for mac and linux
        #[cfg(unix)]
        restrict_vault_perms(db_path)?;

        // Schema + header
        conn.execute_batch(SCHEMA_SQL)?;
        ensure_header(&conn)?;

        // Derive key from header params
        let key_bytes: [u8; 32] = crate::crypto::derive_key_from_header(&conn, password)?;
        let key = Zeroizing::new(key_bytes);

        // Ensure catalog row exists (idempotent)
        crate::catalog::ensure_empty_catalog(&conn, &*key)?;

        Ok(Vault { conn, key })
    }
}

#[cfg(unix)]
fn restrict_vault_perms(path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
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
            .map_err(|e| anyhow!("salt generation failed (getrandom): {:?}", e))?;

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO header (id, format_version, kdf_salt, kdf_mem_kib, kdf_iters, kdf_parallelism) VALUES (1, ?, ?, ?, ?, ?)",
            params![format_version, &salt[..], kdf_mem_kib, kdf_iters, kdf_parallelism],
        )?;
        tx.commit()?;

        println!("Inserted header with new random salt.");
    } 

    Ok(())
}

pub fn load_kdf_params(conn: &Connection) -> Result<(Vec<u8>, i64, i64, i64)> {
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

pub fn set_master_password(v: &Vault, old_pw: &str, new_pw: &str) -> Result<()> {
    // derive old key from current header
    let old_key_bytes: [u8; 32] = crate::crypto::derive_key_from_header(&v.conn, old_pw)?;
    let old_key = Zeroizing::new(old_key_bytes);

    // get new kdf inputs (and new salt)
    let mem_kib: i64 = 256 * 1024; // 256 MiB in KiB
    let iters: i64 = 3;
    let parallelism: i64 = 1;
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|e| anyhow!("salt generation failed (getrandom): {:?}", e))?;

    // derive new key
    let params = Params::new(mem_kib as u32, iters as u32, parallelism as u32, Some(32))
        .map_err(|e| anyhow!("bad Argon2 params: {e:?}"))?;
    let new_key_bytes: [u8; 32] = crate::crypto::derive_key(new_pw, &salt, &params)?;
    let new_key = Zeroizing::new(new_key_bytes);

    // begin db transaction
    let tx = v.conn.unchecked_transaction()?;

    // each item in items
    let mut sel = tx.prepare("SELECT id, nonce, ciphertext FROM items")?;
    let rows = sel.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,     // id
            r.get::<_, Vec<u8>>(1)?,    // nonce
            r.get::<_, Vec<u8>>(2)?,    // ciphertext
        ))
    })?;
    let mut upd = tx.prepare(
        "UPDATE items
            SET nonce = ?, ciphertext = ?, updated_at = ?
        WHERE id = ?"
    )?;
    let now = crate::util::now_unix();

    for row in rows {
        let (id, old_nonce_vec, old_ct) = row?;
        // convert nonce
        if old_nonce_vec.len() != 12 {
            bail!("item {} had invalid nonce length {}", id, old_nonce_vec.len());
        }
        let mut old_nonce = [0u8; 12];
        old_nonce.copy_from_slice(&old_nonce_vec);
        // decrypt with old key and old nonce
        let pt = crate::crypto::decrypt_blob(&old_key, &old_nonce, &old_ct)?;
        // encrypt pt with new key and new nonce
        let (new_ct, new_nonce) = crate::crypto::encrypt_blob(&new_key, &pt)?;
        // UPDATE row
        upd.execute(
            params![&new_nonce[..], &new_ct, now, id],
        )?;

        drop(pt);
    }
    drop(upd);
    drop(sel);

    // catalog (one row, no need to go through items after decryption)
    let (old_nonce_vec_c, old_ct): (Vec<u8>, Vec<u8>) = tx.query_row(
        "SELECT nonce, ciphertext FROM catalog WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?))
    )?;
    if old_nonce_vec_c.len() != 12 {
        bail!("catalog had invalid nonce length {}", old_nonce_vec_c.len());
    }
    let mut old_nonce = [0u8; 12];
    old_nonce.copy_from_slice(&old_nonce_vec_c);
    // decrypt with old key and old nonce
    let pt = crate::crypto::decrypt_blob(&old_key, &old_nonce, &old_ct)?;
    // encrypt pt with new key and new nonce
    let (new_ct, new_nonce) = crate::crypto::encrypt_blob(&new_key, &pt)?;
    // UPDATE row 
    tx.execute(
        "UPDATE catalog
            SET nonce = ?, ciphertext = ?, updated_at = ?
        WHERE id = 1",
        params![&new_nonce[..], &new_ct, now],
    )?;
    drop(pt);

    // update header
    // (opt) if kdf params changed, change them
    tx.execute(
        "UPDATE header 
        SET kdf_salt = ?, kdf_mem_kib = ?, kdf_iters = ?, kdf_parallelism = ?
        WHERE id = 1",
        params![&salt[..], mem_kib, iters, parallelism],
    )?;
    tx.commit()?;

    Ok(())
}

pub fn backup_to_path(v: &Vault, to: &str, overwrite: bool) -> Result<()> {
    let dest = Path::new(&to);
    // Check if path is the same as current DB path
    let src = v.conn.path().ok_or_else(|| anyhow!("Source DB has no path"))?;
    if dest == Path::new(src) {
        bail!("Destination and source are the same. Refusing to overwrite live databse.");
    }

    // If something's at dest, and no overwrite, fail
    if !overwrite && dest.exists() {
        bail!("Destination already exists. Use a different path or overwrite with --overwrite flag.");
    }

    // Ensure dest parent dir exists
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Open dest Connection
    let mut dest_conn = rusqlite::Connection::open(dest)?;

    // Backup
    {
        use rusqlite::backup::Backup;
        let backup = Backup::new(&v.conn, &mut dest_conn)?;
        // -1 means copy all pages in one go
        backup.step(-1)?;
    }

    // Tighten permissions on unix
    #[cfg(unix)]
    restrict_vault_perms(to)?;

    Ok(())
}
