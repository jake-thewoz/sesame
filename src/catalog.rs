use anyhow::{Result, anyhow};
use rusqlite::{Connection, params};
use zeroize::Zeroize;

use crate::util;
use crate::crypto;
use crate::db::Vault;

#[derive(serde::Serialize, serde::Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
pub struct CatalogEntry {
    pub id: String,
    pub title: String,
    pub updated_at: i64,
}

// Used by Vault::open, so needs conn and key args
pub fn ensure_empty_catalog(conn: &Connection, key: &[u8; 32]) -> Result<()> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM catalog WHERE id = 1",
        [],
        |row| row.get(0)
    )?;

    if count == 0 {
        let plaintext = b"[]"; // empty JSON list
        let (ciphertext, nonce) = crypto::encrypt_blob(key, plaintext)?;
        let now = util::now_unix();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO catalog (id, nonce, ciphertext, updated_at) VALUES (1, ?, ?, ?)",
            params![&nonce[..], &ciphertext, now],
        )?;
        tx.commit()?;
        println!("Created encrypted empty catalog.");
    }

    Ok(())
}

pub fn load_catalog(v: &Vault) -> Result<Vec<CatalogEntry>> {
    // read row
    let (nonce, ct): (Vec<u8>, Vec<u8>) = v.conn.query_row(
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

    let pt = crypto::decrypt_blob(&*v.key, &n, &ct)?;
    if pt.is_empty() {
        return Ok(Vec::new());
    }
    let v: Vec<CatalogEntry> = serde_json::from_slice(&pt)
        .map_err(|e| anyhow!("catalog json decode failed: {e:?}"))?;
    Ok(v)
}

fn load_catalog_sorted(v: &Vault) -> Result<Vec<CatalogEntry>> {
    let mut v_sort = load_catalog(v)?;

    // Order: title asc, then id asc
    v_sort.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase())
        .then(a.id.cmp(&b.id))
    );
    Ok(v_sort)
}

pub fn save_catalog(v: &Vault, entries: &[CatalogEntry]) -> Result<()> {
    let pt = serde_json::to_vec(entries)?;
    let (ct, nonce) = crypto::encrypt_blob(&*v.key, &pt)?;
    let now = util::now_unix();
    let tx = v.conn.unchecked_transaction()?;
    tx.execute(
        "UPDATE catalog SET nonce = ?, ciphertext = ?, updated_at = ? WHERE id = 1",
        params![&nonce[..], &ct, now],
    )?;
    tx.commit()?;

    Ok(())
}

pub fn list_items(v: &Vault) -> Result<()> {
    let entries = load_catalog_sorted(v)?;
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

pub fn resolve_selector_to_id(v: &Vault, sel: &str) -> Result<String> {
    let entries = load_catalog_sorted(v)?;
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

pub fn search(v: &Vault, query: &String, limit: usize, deep: bool) -> Result<()> {
    let needle = query.to_lowercase();
    let mut entries = load_catalog(v)?;
    entries.sort_by_key(|e| std::cmp::Reverse(e.updated_at));

    let mut results = Vec::new();

    // Go through catalog entries looking for hits
    for e in entries.iter() {
        let hit_title = e.title.to_lowercase().contains(&needle);
        let mut hit_user = false;
        let mut hit_notes = false;

        if !hit_title && deep {
            // Decrypt the item associated with the entry
            // Item will zeroize when dropped
            let item = crate::items::load_item(v, &e.id)?;
            hit_user = item.username.to_lowercase().contains(&needle);
            hit_notes = item.notes.to_lowercase().contains(&needle);
            // item drops here
        }

        if hit_title || hit_user || hit_notes {
            results.push((e, hit_title, hit_user, hit_notes));
            if limit > 0 && results.len() >= limit {
                break;
            }
        }
    }

    if results.is_empty() {
        println!("No matches for '{}'{}", query, if deep {" (deep)"} else {""});
        return Ok(());
    }

    // Show short list
    println!("{:<10}   {:<10}   {:<10}", "ID", "Title", "Matching Fields");
    for (e, title, username, notes) in results.iter() {
        let id: String = e.id.chars().take(8).collect();
        let mut fields: Vec<&str> = Vec::new();
        if *title { fields.push("title"); }
        if *username { fields.push("username"); }
        if *notes { fields.push("notes"); }

        let fields_string = &format!("({})", fields.join(", "));
        println!("{:<10}   {:<10}   {:<10}", id, e.title, fields_string);
    }

    println!("\nUse the id (at least 4 chars) with `show`/`edit`/`delete`");

    Ok(())
}
