use anyhow::{Result, anyhow};
use rusqlite::{Connection, params};

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

pub fn open_and_init(db_path: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(SCHEMA_SQL)?;
    ensure_header(&conn)?;
    Ok(conn)
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
