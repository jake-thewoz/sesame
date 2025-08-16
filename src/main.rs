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
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            catalog::ensure_empty_catalog(&v.conn, &*v.key)?;
            println!("Initialized vault at '{}'", &cli.db);
        }
        Cmd::Add => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            catalog::ensure_empty_catalog(&v.conn, &*v.key)?;
            items::add_item_interactive(&v)?;
            catalog::list_items(&v)?;
        }
        Cmd::List => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            catalog::ensure_empty_catalog(&v.conn, &*v.key)?;
            catalog::list_items(&v)?;
        }
        Cmd::Show { sel } => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            catalog::ensure_empty_catalog(&v.conn, &*v.key)?;
            let id = catalog::resolve_selector_to_id(&v, &sel)?;
            items::show_item(&v, &id)?;
        }
        Cmd::Delete { sel } => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            catalog::ensure_empty_catalog(&v.conn, &*v.key)?;
            let id = catalog::resolve_selector_to_id(&v, &sel)?;
            items::delete_item(&v, &id)?;
            // Show remaining items
            catalog::list_items(&v)?;
        }
        Cmd::Edit { sel } => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            catalog::ensure_empty_catalog(&v.conn, &*v.key)?;
            let id = catalog::resolve_selector_to_id(&v, &sel)?;
            items::edit_item(&v, &id)?;
            // Show updated entry for confirmation
            items::show_item(&v, &id)?;
        }
    }

    Ok(())
}
