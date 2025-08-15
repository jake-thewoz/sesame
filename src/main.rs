use anyhow::{Result, anyhow};
use rusqlite::{Connection, params};
use std::io::{self, Write};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305};
use argon2::{Argon2, Params};
use rpassword::read_password;
use clap::{Parser};

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

/* --- CLI types --- */

#[derive(Parser)]
#[command(name="sesame", version)]
struct Cli {
    // Path to vault database
    #[arg(long, default_value = "vault.db")]
    db: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Parser)]
enum Cmd {
    // Init header + empty encrypted catalog (idempotent)
    Init,
    // Add new item (interactive prompts)
    Add,
    // List catalog entries (titles + ids)
    List,
    // Show a single item by full ID
    Show { sel: String },
    // Delete a single item with ID
    Delete { sel: String },
    // Edit a single item with ID
    Edit { sel: String },
}

/* --- helpers for unlock --- */

fn prompt_password() -> Result<String> {
    print!("Enter master password: ");
    io::stdout().flush().ok();
    Ok(read_password()?)
}

fn open_and_init(db_path: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(SCHEMA_SQL)?;
    ensure_header(&conn)?;
    Ok(conn)
}

fn derive_key_from_header(conn: &Connection, password: &str) -> Result<[u8; 32]> {
    let (salt, mem_kib, iters, parallelism) = load_kdf_params(&conn)?;
    let params = Params::new(mem_kib as u32, iters as u32, parallelism as u32, Some(32))
        .map_err(|e| anyhow!("bad Argon2 params: {e:?}"))?;
    derive_key(password, &salt, &params)
}

/* --- main function --- */

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Init => {
            let conn = open_and_init(&cli.db)?;
            // also ensure empty catalog exists (idempotent)
            let pw = prompt_password()?;
            let key = derive_key_from_header(&conn, &pw)?;
            ensure_empty_catalog(&conn, &key)?;
            println!("Initialized vault at '{}'", &cli.db);
        }
        Cmd::Add => {
            let conn = open_and_init(&cli.db)?;
            let pw = prompt_password()?;
            let key = derive_key_from_header(&conn, &pw)?;
            ensure_empty_catalog(&conn, &key)?;
            add_item_interactive(&conn, &key)?;
            list_items(&conn, &key)?;
        }
        Cmd::List => {
            let conn = open_and_init(&cli.db)?;
            let pw = prompt_password()?;
            let key = derive_key_from_header(&conn, &pw)?;
            ensure_empty_catalog(&conn, &key)?;
            list_items(&conn, &key)?;
        }
        Cmd::Show { sel } => {
            let conn = open_and_init(&cli.db)?;
            let pw = prompt_password()?;
            let key = derive_key_from_header(&conn, &pw)?;
            ensure_empty_catalog(&conn, &key)?;
            let id = resolve_selector_to_id(&conn, &key, &sel)?;
            show_item(&conn, &key, &id)?;
        }
        Cmd::Delete { sel } => {
            let conn = open_and_init(&cli.db)?;
            let pw = prompt_password()?;
            let key = derive_key_from_header(&conn, &pw)?;
            ensure_empty_catalog(&conn, &key)?;
            let id = resolve_selector_to_id(&conn, &key, &sel)?;
            delete_item(&conn, &key, &id)?;
            // Show remaining items
            list_items(&conn, &key)?;
        }
        Cmd::Edit { sel } => {
            let conn = open_and_init(&cli.db)?;
            let pw = prompt_password()?;
            let key = derive_key_from_header(&conn, &pw)?;
            ensure_empty_catalog(&conn, &key)?;
            let id = resolve_selector_to_id(&conn, &key, &sel)?;
            edit_item(&conn, &key, &id)?;
            // Show updated entry for confirmation
            show_item(&conn, &key, &id)?;
        }
    }

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

fn load_catalog_sorted(conn: &Connection, key: &[u8; 32]) -> Result<Vec<CatalogEntry>> {
    let mut v = load_catalog(conn, key)?;

    // Order: title asc, then id asc
    v.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase())
        .then(a.id.cmp(&b.id))
    );
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
    let entries = load_catalog_sorted(conn, key)?;
    if entries.is_empty() {
        println!("(catalog is empty)");
        return Ok(());
    }
    println!("{:<4} {:<12}  {:<30}  {}", "#", "ID", "Title", "Updated");
    for (i, e) in entries.iter().enumerate() {
        println!("{:<4} {:<12}  {:<30}  {}", i+1, &e.id[..12], e.title, e.updated_at);
    }
    Ok(())
}

fn show_item(conn: &Connection, key: &[u8; 32], id: &str) -> Result<()> {
    // Fetch encrypted row by ID
    let item = load_item(conn, key, id)?;

    // Print values
    println!("Title:    {}", item.title);
    println!("Username: {}", item.username);
    println!("Password: {}", item.password);
    if !item.notes.trim().is_empty() {
        println!("Notes:    {}", item.notes);
    }

    Ok(())
}

fn load_item(conn: &Connection, key: &[u8; 32], id: &str) -> Result<ItemPlain> {
    // Fetch encrypted row by ID
    let (nonce, ct): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT nonce, ciphertext FROM items WHERE id = ?",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|_| anyhow!("No item found with ID {id}"))?;

    // Check and convert nonce Vec<u8> -> [u8; 12]
    if nonce.len() != 12 {
        return Err(anyhow!("catalog nonce has wrong length: {}", nonce.len()));
    }
    let mut n = [0u8; 12];
    n.copy_from_slice(&nonce);

    // Decrypt into plaintext JSON
    let pt = decrypt_blob(key, &n, &ct)?;

    // Parse into struct and print
    let item: ItemPlain = serde_json::from_slice(&pt)
        .map_err(|e| anyhow!("failed to parse item JSON: {e:?}"))?;

    Ok(item)
}

fn delete_item(conn: &Connection, key: &[u8; 32], id: &str) -> Result<()> {
    // Delete the encrypted row
    let rows = conn.execute("DELETE FROM items WHERE id = ?", [id])?;
    if rows == 0 {
        println!("No item found with ID {id}");
        return Ok(());
    }

    // Update catalog: remove entry and re-encrypt
    let mut entries = load_catalog(conn, key)?;
    let before = entries.len();
    entries.retain(|e| e.id != id);
    if entries.len() == before {
        // Catalog didn't have entry
        println!("Deleted item, but it wasn't in the catalog list.");
    }
    
    save_catalog(conn, key, &entries)?;
    println!("Deleted {id}");
    Ok(())
}

fn prompt_with_default(label: &str, current: &str) -> Result<String> {
    use std::io::{self, Write};
    print!("{label} [{current}]: ");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    let s = s.trim().to_string();
    if s.is_empty() { Ok(current.to_string()) } else { Ok(s) }
}

fn prompt_password_optional(current_hidden_note: &str) -> Result<Option<String>> {
    // Return Some(new) if user typed one, or None if they pressed Enter
    use std::io::{self, Write};
    print!("Password (hidden) [{current_hidden_note}]: ");
    io::stdout().flush().ok();
    let pw = rpassword::read_password()?; // empty string if Enter
    if pw.is_empty() { Ok(None) } else { Ok(Some(pw)) }
}

fn edit_item(conn: &Connection, key: &[u8; 32], id: &str) -> Result<()> {
    // 1) Load current
    let mut item = load_item(conn, key, id)?;

    // 2) Prompt (Enter keeps existing)
    let new_title = prompt_with_default("Title", &item.title)?;
    let new_username = prompt_with_default("Username", &item.username)?;
    let pw_opt = prompt_password_optional("*hidden*")?;
    let new_notes = prompt_with_default("Notes", &item.notes)?;

    if let Some(new_pw) = pw_opt {
        item.password = new_pw;
    }
    item.title = new_title;
    item.username = new_username;
    item.notes = new_notes;

    // 3) Re-encrypt and update row
    let pt = serde_json::to_vec(&item)?;
    let (ct, nonce) = encrypt_blob(key, &pt)?;
    let now = now_unix();
    let rows = conn.execute(
        "UPDATE items SET nonce = ?, ciphertext = ?, updated_at = ? WHERE id = ?",
        params![&nonce[..], &ct, now, id],
    )?;
    if rows == 0 {
        return Err(anyhow!("Item disappeared during edit (id {id})"));
    }

    // 4) Update catalog title + updated_at, then re-encrypt/save
    let mut entries = load_catalog(conn, key)?;
    if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
        e.title = item.title.clone();
        e.updated_at = now;
    } else {
        // Edge-case: if catalog missed it, add it back so list stays consistent
        entries.push(CatalogEntry {
            id: id.to_string(),
            title: item.title.clone(),
            updated_at: now
        });
    }
    save_catalog(conn, key, &entries)?;

    println!("Edited item {id}");
    Ok(())
}

fn resolve_selector_to_id(conn: &Connection, key: &[u8; 32], sel: &str) -> Result<String> {
    let entries = load_catalog_sorted(conn, key)?;
    if entries.is_empty() {
        return Err(anyhow!("catalog is empty"));
    }

    // Index case- all digits
    if sel.chars().all(|c| c.is_ascii_digit()) {
        let idx: usize = sel.parse().unwrap_or(0);
        if idx == 0 || idx > entries.len() {
            return Err(anyhow!("index {} out of range 1..{}", idx, entries.len()));
        }
        return Ok(entries[idx - 1].id.clone());
    }

    // Prefix case- letters and numbers
    let prefix = sel.trim().to_lowercase();
    let min = 4; // require at least 4 chars
    if prefix.len() < min {
        return Err(anyhow!("prefix too short (minimum is {})", min));
    }
    let mut matches = entries.iter().filter(|e| e.id.starts_with(&prefix)).peekable();
    let first = matches.next();
    if first.is_none() {
        return Err(anyhow!("no items match prefix {}", sel));
    }
    if matches.peek().is_some() {
        return Err(anyhow!("prefix {} too ambiguous", sel));
    }
    
    Ok(first.unwrap().id.clone())
}
