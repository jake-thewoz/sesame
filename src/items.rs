use anyhow::{Result, anyhow};
use rusqlite::{Connection, params};
use std::io::{Write};

use crate::util;
use crate::crypto;
use crate::catalog;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ItemPlain {
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: String,
}

pub fn add_item_interactive(conn: &Connection, key: &[u8; 32]) -> Result<()> {
    // Collect fields (mask the secret input)
    let title = util::read_line("Title: ")?;
    let username = util::read_line("Username: ")?;
    print!("Password (hidden): ");
    std::io::stdout().flush().ok();
    let password = rpassword::read_password()?;
    let notes = util::read_line("Notes (optional): ")?;

    // Build plaintext item
    let item = ItemPlain {
        title: title.clone(),
        username,
        password,
        notes
    };
    let pt = serde_json::to_vec(&item)?;

    // Encrypt + insert into items
    let (ct, nonce) = crypto::encrypt_blob(key, &pt)?;
    let id = util::new_id()?;
    let now = util::now_unix();
    conn.execute(
        "INSERT INTO items (id, nonce, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        params![&id, &nonce[..], &ct, now, now],
    )?;

    // Update catalog
    let mut entries = catalog::load_catalog(conn, key)?;
    // If an entry with the same id exists (shouldn't), replace title; else push
    if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
        e.title = title;
        e.updated_at = now;
    } else {
        entries.push(catalog::CatalogEntry { id, title, updated_at: now });
    }

    catalog::save_catalog(conn, key, &entries)?;

    println!("Item added.");
    Ok(())
}

pub fn show_item(conn: &Connection, key: &[u8; 32], id: &str) -> Result<()> {
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

pub fn load_item(conn: &Connection, key: &[u8; 32], id: &str) -> Result<ItemPlain> {
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
    let pt = crypto::decrypt_blob(key, &n, &ct)?;

    // Parse into struct and print
    let item: ItemPlain = serde_json::from_slice(&pt)
        .map_err(|e| anyhow!("failed to parse item JSON: {e:?}"))?;

    Ok(item)
}

pub fn delete_item(conn: &Connection, key: &[u8; 32], id: &str) -> Result<()> {
    // Delete the encrypted row
    let rows = conn.execute("DELETE FROM items WHERE id = ?", [id])?;
    if rows == 0 {
        println!("No item found with ID {id}");
        return Ok(());
    }

    // Update catalog: remove entry and re-encrypt
    let mut entries = catalog::load_catalog(conn, key)?;
    let before = entries.len();
    entries.retain(|e| e.id != id);
    if entries.len() == before {
        // Catalog didn't have entry
        println!("Deleted item, but it wasn't in the catalog list.");
    }
    
    catalog::save_catalog(conn, key, &entries)?;
    println!("Deleted {id}");
    Ok(())
}

pub fn edit_item(conn: &Connection, key: &[u8; 32], id: &str) -> Result<()> {
    // 1) Load current
    let mut item = load_item(conn, key, id)?;

    // 2) Prompt (Enter keeps existing)
    let new_title = util::prompt_with_default("Title", &item.title)?;
    let new_username = util::prompt_with_default("Username", &item.username)?;
    let pw_opt = util::prompt_password_optional("*hidden*")?;
    let new_notes = util::prompt_with_default("Notes", &item.notes)?;

    if let Some(new_pw) = pw_opt {
        item.password = new_pw;
    }
    item.title = new_title;
    item.username = new_username;
    item.notes = new_notes;

    // 3) Re-encrypt and update row
    let pt = serde_json::to_vec(&item)?;
    let (ct, nonce) = crypto::encrypt_blob(key, &pt)?;
    let now = util::now_unix();
    let rows = conn.execute(
        "UPDATE items SET nonce = ?, ciphertext = ?, updated_at = ? WHERE id = ?",
        params![&nonce[..], &ct, now, id],
    )?;
    if rows == 0 {
        return Err(anyhow!("Item disappeared during edit (id {id})"));
    }

    // 4) Update catalog title + updated_at, then re-encrypt/save
    let mut entries = catalog::load_catalog(conn, key)?;
    if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
        e.title = item.title.clone();
        e.updated_at = now;
    } else {
        // Edge-case: if catalog missed it, add it back so list stays consistent
        entries.push(catalog::CatalogEntry {
            id: id.to_string(),
            title: item.title.clone(),
            updated_at: now
        });
    }
    catalog::save_catalog(conn, key, &entries)?;

    println!("Edited item {id}");
    Ok(())
}

