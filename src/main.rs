use anyhow::{Result};
use clap::{Parser};
use zeroize::Zeroizing;

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
    Show {
        sel: String,
        // Copy password into clipboard
        #[arg(long)]
        copy: bool,
        // Seconds to auto-clear
        #[arg(long, default_value_t = 20)]
        timeout: u64
    },
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
            let _v = db::Vault::open(&cli.db, pw.as_str())?;
            println!("Initialized vault at '{}'", &cli.db);
        }
        Cmd::Add => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            items::add_item_interactive(&v)?;
            catalog::list_items(&v)?;
        }
        Cmd::List => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            catalog::list_items(&v)?;
        }
        Cmd::Show { sel, copy, timeout } => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            let id = catalog::resolve_selector_to_id(&v, &sel)?;
            items::show_item(&v, &id)?;

            if copy {
                let item = items::load_item(&v, &id)?;
                let secret = Zeroizing::new(item.password.clone());
                util::clipboard_copy_pw_temporary(secret, timeout)?;
            }
        }
        Cmd::Delete { sel } => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            let id = catalog::resolve_selector_to_id(&v, &sel)?;

            // confirm before deleting
            let item = items::load_item(&v, &id)?;
            let title = &item.title;
            if !util::confirm(&format!("Delete '{}' ({})?", title, id)) {
                println!("Aborted.");
                return Ok(());
            }

            items::delete_item(&v, &id)?;
            catalog::list_items(&v)?;
        }
        Cmd::Edit { sel } => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            let id = catalog::resolve_selector_to_id(&v, &sel)?;

            // confirm before editing
            let item = items::load_item(&v, &id)?;
            let title = &item.title;
            if !util::confirm(&format!("Edit '{}' ({})?", title, id)) {
                println!("Aborted.");
                return Ok(());
            }

            items::edit_item(&v, &id)?;
            items::show_item(&v, &id)?;
        }
    }

    Ok(())
}
