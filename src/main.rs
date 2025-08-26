use anyhow::{Result};
use clap::{Parser};
use zeroize::Zeroizing;
use indoc::indoc;

mod util;
mod crypto;
mod db;
mod catalog;
mod items;

/* --- CLI types --- */

const SESAME_ASCII: &str = indoc! {r#"
 ____  _____  ____    _    __  __  _____
/ ___|| ____|/ ___|  / \  |  \/  || ____|
\___ \|  _|  \___ \ / _ \ | |\/| ||  _|
 ___) | |___  ___) / ___ \| |  | || |___
|____/|_____||____/_/   \_\_|  |_||_____|
"#};

#[derive(Parser)]
#[command(
    name="sesame",
    version,
    before_help = SESAME_ASCII,
    about = "A local-first password manager.",
    long_about = indoc! {"
        Sesame is a local-first password manager.
        It stores passwords in an encrypted SQLite vault,
        and gives you CLI commands for tasks.
    "},
    after_help = "Tip: run `sesame <command> --help` for command-specific options\n.",
    after_long_help = indoc! {"
        EXAMPLES:
          sesame --db vault.db init 
          sesame add 
          sesame show <ID_OR_PREFIX> --copy --timeout 40
          sesame gen --len 24 --no-specials
          sesame backup ./vault.backup.sqlite --overwrite

        Tip: run `sesame <command> --help` for command-specific options.\n
    "},
    arg_required_else_help = true,
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    // Path to vault database
    #[arg(long, value_name = "FILE", default_value = "vault.db",
        long_help = indoc! {"
            Path to the encrypted SQLite vault. If the file does not exist,
            `sesame init` will create it. You can keep multiple vaults in
            different files using this flag.
        "}
    )]
    db: String,
}

#[derive(Parser)]
enum Cmd {
    // Init header + empty encrypted catalog (idempotent)
    #[command(long_about = indoc! {"
        Create the vault (if not present) and initialize the encrypted catalog.
        Safe to re-run: existing vaults will be opened and verified.
        You will be prompted for the master password.
    "})]
    Init,

    // Add new item (interactive prompts)
    #[command(long_about = indoc! {"
        Add a login/note/token interactively. You'll be prompted for a title,
        username, password, and notes. After adding, the catalog is listed.
    "})]
    Add,

    // List catalog entries (titles + ids)
    #[command(visible_alias = "ls", long_about = indoc! {"
        Print a table of saved items with their index, IDs, and titles.
        IDs can be used with other commands.
    "})]
    List,

    // Show a single item by full ID
    #[command(visible_alias = "cat", long_about = indoc! {"
        Reveal an item by index or ID prefix (must be at least 4 digits of ID).
        Use --copy to place the secret on the clipboard for a limited time.
    "})]
    Show {
        #[arg(value_name = "ID_OR_PREFIX")]
        sel: String,

        // Copy password into clipboard
        #[arg(long, help = "Copy secret to clipboard.")]
        copy: bool,

        // Seconds to auto-clear
        #[arg(long, default_value_t = 20, value_name = "SECS",
            long_help = "How long the copied secret stays in the clipboard before clearing."
        )]
        timeout: u64
    },

    // Delete a single item with ID
    #[command(visible_alias = "rm", long_about = indoc! {"
        Delete the selected item. This action is irreversible (unless you have
        a backup of the vault).
    "})]
    Delete { 
        #[arg(value_name = "ID_OR_PREFIX")]
        sel: String
    },

    // Edit a single item with ID
    #[command(long_about = indoc! {"
        Open the selected item to edit interactively, similar to using `--add`.
    "})]
    Edit { 
        #[arg(value_name = "ID_OR_PREFIX")]
        sel: String
    },

    // Generate a random passowrd of len length
    // TODO: handle attack vector of non-clearing clipboard/terminal
    #[command(visible_alias = "pwgen",long_about = indoc! {"
        Create a random password. By default, all buckets (upper/lower/digits/speacials)
        are enabled, with a default length of 16.
        Use the `--no-*` toggles to exclude categories.
        Use the `--len` flag to change the length.
    "})]
    Gen { 
        #[arg(long, value_name = "N", default_value_t = 16)]
        len: usize,

        // Copy password into clipboard
        #[arg(long, help = "Copy password to clipboard.")]
        copy: bool,

        // Seconds to auto-clear
        #[arg(long, default_value_t = 20, value_name = "SECS",
            long_help = "How long the copied password stays in the clipboard before clearing."
        )]
        timeout: u64,

        // bucket toggles (default: all enabled)
        #[arg(long)] no_upper: bool,
        #[arg(long)] no_lower: bool,
        #[arg(long)] no_digits: bool,
        #[arg(long)] no_specials: bool,
    },

    // Change master password
    #[command(visible_alias = "passwd", long_about = indoc! {"
        Derive a new master key with Argon2id, and re-encrypt the vault.
    "})]
    ChangeMaster,

    // Search titles in catalog
    #[command(visible_alias = "grep", long_about = indoc! {"
        Case-insensitive substring match over titles, usernames, and notes.
        Combine with `show` / `edit` / `delete` using the returned IDs.
    "})]
    Search { 
        // Text to search for
        #[arg(value_name = "QUERY")]
        query: String,

        // Max results (0 is unlimited)
        #[arg(value_name = "N", long, default_value_t = 0)]
        limit: usize,
    },

    // Create a backup of the vault
    #[command(long_about = indoc! {"
        Copy the encrypted SQLite vault to a new location.
        By default, this fails if the destination already exists.
        Use the `--overwrite` flag to allow overwriting of destination file.
    "})]
    Backup { 
        // Destination filepath
        #[arg(value_name = "FILE")]
        to: String,

        // Fail if dest already exists
        #[arg(long)]
        overwrite: bool,
    },
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
        Cmd::Gen { len, copy, timeout,
            no_upper, no_lower, no_digits, no_specials
        } => {
            let new_pw = util::gen_password(len, no_upper, no_lower, no_digits, no_specials)?;
            println!("Generated password.");

            if copy {
                util::clipboard_copy_pw_temporary(new_pw, timeout)?;
            } else {
                println!("{}", new_pw.as_str());
            }
        }
        Cmd::ChangeMaster => {
            let old_pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, old_pw.as_str())?;
            println!("Setting new master password.");
            let new_pw = util::prompt_new_password()?;

            db::set_master_password(&v, old_pw.as_str(), new_pw.as_str())?;
            println!("New master password set.");
        }
        Cmd::Search { query, limit } => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            catalog::search(&v, &query, limit)?;
        }
        Cmd::Backup { to, overwrite } => {
            let pw = util::prompt_password()?;
            let v = db::Vault::open(&cli.db, pw.as_str())?;
            db::backup_to_path(&v, &to, overwrite)?;
            println!("Backup written to {}", to);
        }
    }

    Ok(())
}
