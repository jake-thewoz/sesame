use anyhow::{Result};
use clap::{Parser};

mod util;
mod crypto;
mod db;
mod catalog;
mod items;

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

/* --- main function --- */

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Init => {
            let conn = db::open_and_init(&cli.db)?;
            // also ensure empty catalog exists (idempotent)
            let pw = util::prompt_password()?;
            let key = crypto::derive_key_from_header(&conn, &pw)?;
            catalog::ensure_empty_catalog(&conn, &key)?;
            println!("Initialized vault at '{}'", &cli.db);
        }
        Cmd::Add => {
            let conn = db::open_and_init(&cli.db)?;
            let pw = util::prompt_password()?;
            let key = crypto::derive_key_from_header(&conn, &pw)?;
            catalog::ensure_empty_catalog(&conn, &key)?;
            items::add_item_interactive(&conn, &key)?;
            catalog::list_items(&conn, &key)?;
        }
        Cmd::List => {
            let conn = db::open_and_init(&cli.db)?;
            let pw = util::prompt_password()?;
            let key = crypto::derive_key_from_header(&conn, &pw)?;
            catalog::ensure_empty_catalog(&conn, &key)?;
            catalog::list_items(&conn, &key)?;
        }
        Cmd::Show { sel } => {
            let conn = db::open_and_init(&cli.db)?;
            let pw = util::prompt_password()?;
            let key = crypto::derive_key_from_header(&conn, &pw)?;
            catalog::ensure_empty_catalog(&conn, &key)?;
            let id = catalog::resolve_selector_to_id(&conn, &key, &sel)?;
            items::show_item(&conn, &key, &id)?;
        }
        Cmd::Delete { sel } => {
            let conn = db::open_and_init(&cli.db)?;
            let pw = util::prompt_password()?;
            let key = crypto::derive_key_from_header(&conn, &pw)?;
            catalog::ensure_empty_catalog(&conn, &key)?;
            let id = catalog::resolve_selector_to_id(&conn, &key, &sel)?;
            items::delete_item(&conn, &key, &id)?;
            // Show remaining items
            catalog::list_items(&conn, &key)?;
        }
        Cmd::Edit { sel } => {
            let conn = db::open_and_init(&cli.db)?;
            let pw = util::prompt_password()?;
            let key = crypto::derive_key_from_header(&conn, &pw)?;
            catalog::ensure_empty_catalog(&conn, &key)?;
            let id = catalog::resolve_selector_to_id(&conn, &key, &sel)?;
            items::edit_item(&conn, &key, &id)?;
            // Show updated entry for confirmation
            items::show_item(&conn, &key, &id)?;
        }
    }

    Ok(())
}
