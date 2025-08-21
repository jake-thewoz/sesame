use anyhow::{Result, anyhow};
use rusqlite::{params};
use std::io::{Write};
use zeroize::Zeroize;

use crate::util;
use crate::crypto;
use crate::catalog;
use crate::db::Vault;

#[derive(serde::Serialize, serde::Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
pub struct ItemPlain {
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: String,
}

pub fn load_item(v: &Vault, id: &str) -> Result<ItemPlain> {
    // Fetch encrypted row by ID
    let (nonce, ct): (Vec<u8>, Vec<u8>) = v.conn.query_row(
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
    let pt = crypto::decrypt_blob(&*v.key, &n, &ct)?;

    // Parse into struct and print
    let item: ItemPlain = serde_json::from_slice(&pt)
        .map_err(|e| anyhow!("failed to parse item JSON: {e:?}"))?;

    Ok(item)
}

pub fn show_item(v: &Vault, id: &str) -> Result<()> {
    // Fetch encrypted row by ID
    let item = load_item(v, id)?;

    // Print values
    println!("Title:    {}", item.title);
    println!("Username: {}", item.username);
    println!("Password: {}", item.password);
    if !item.notes.trim().is_empty() {
        println!("Notes:    {}", item.notes);
    }

    Ok(())
}

pub fn add_item_interactive(v: &Vault) -> Result<()> {
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
    let pt = zeroize::Zeroizing::new(serde_json::to_vec(&item)?);

    // Encrypt + insert into items
    let (ct, nonce) = crypto::encrypt_blob(&*v.key, &pt)?;
    let id = util::new_id()?;
    let now = util::now_unix();
    let tx = v.conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO items (id, nonce, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        params![&id, &nonce[..], &ct, now, now],
    )?;
    tx.commit()?;

    // Update catalog
    let mut entries = catalog::load_catalog(v)?;
    // If an entry with the same id exists (shouldn't), replace title; else push
    if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
        e.title = title;
        e.updated_at = now;
    } else {
        entries.push(catalog::CatalogEntry { id, title, updated_at: now });
    }

    catalog::save_catalog(v, &entries)?;

    println!("Item added.");
    Ok(())
}

pub fn edit_item(v: &Vault, id: &str) -> Result<()> {
    // 1) Load current
    let mut item = load_item(v, id)?;

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
    let pt = zeroize::Zeroizing::new(serde_json::to_vec(&item)?);
    let (ct, nonce) = crypto::encrypt_blob(&*v.key, &pt)?;
    let now = util::now_unix();
    let tx = v.conn.unchecked_transaction()?;
    let rows = tx.execute(
        "UPDATE items SET nonce = ?, ciphertext = ?, updated_at = ? WHERE id = ?",
        params![&nonce[..], &ct, now, id],
    )?;
    if rows == 0 {
        return Err(anyhow!("Item disappeared during edit (id {id})"));
    }
    tx.commit()?;

    // 4) Update catalog title + updated_at, then re-encrypt/save
    let mut entries = catalog::load_catalog(v)?;
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
    catalog::save_catalog(v, &entries)?;

    println!("Edited item {id}");
    Ok(())
}

pub fn delete_item(v: &Vault, id: &str) -> Result<()> {
    // Delete the encrypted row
    let tx = v.conn.unchecked_transaction()?;
    let rows = tx.execute("DELETE FROM items WHERE id = ?", [id])?;
    if rows == 0 {
        println!("No item found with ID {id}");
        return Ok(());
    }
    tx.commit()?;

    // Update catalog: remove entry and re-encrypt
    let mut entries = catalog::load_catalog(v)?;
    let before = entries.len();
    entries.retain(|e| e.id != id);
    if entries.len() == before {
        // Catalog didn't have entry
        println!("Deleted item, but it wasn't in the catalog list.");
    }
    
    catalog::save_catalog(v, &entries)?;
    println!("Deleted {id}");
    Ok(())
}
