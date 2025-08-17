use anyhow::{Result, anyhow};
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use rpassword::read_password;
use zeroize::Zeroizing;

pub fn read_line(prompt: &str) -> Result<String> {
    use std::io::{self, Write};
    print!("{prompt}");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

pub fn prompt_password() -> Result<Zeroizing<String>> {
    print!("Enter master password: ");
    io::stdout().flush().ok();
    Ok(Zeroizing::new(read_password()?))
}

pub fn prompt_with_default(label: &str, current: &str) -> Result<String> {
    use std::io::{self, Write};
    print!("{label} [{current}]: ");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    let s = s.trim().to_string();
    if s.is_empty() { Ok(current.to_string()) } else { Ok(s) }
}

pub fn prompt_password_optional(current_hidden_note: &str) -> Result<Option<String>> {
    // Return Some(new) if user typed one, or None if they pressed Enter
    use std::io::{self, Write};
    print!("Password (hidden) [{current_hidden_note}]: ");
    io::stdout().flush().ok();
    let pw = rpassword::read_password()?; // empty string if Enter
    if pw.is_empty() { Ok(None) } else { Ok(Some(pw)) }
}

pub fn new_id() -> Result<String> {
    // 16 random bytes -> hex string id
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b)
        .map_err(|e| anyhow!("getrandom failed: {:?}", e))?;
    Ok(b.iter().map(|x| format!("{:02x}", x)).collect())
}

pub fn now_unix() -> i64 {
    // Simple, portable "seconds since epoch"
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    dur.as_secs() as i64
}

pub fn confirm(prompt: &str) -> bool {
    print!("{prompt} [y/N]: ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        matches!(input.trim(), "y" | "Y")
    } else {
        false
    }

}
/* --- Copy to clipboard functions --- */

// Try to set clipboard using arboard; Ok(()) if successful
fn try_arboard_set(text: &str) -> Result<()> {
    let mut cb = arboard::Clipboard::new()
        .map_err(|e| anyhow!("clipboard init failed: {e:?}"))?;
    cb.set_text(text.to_string())
        .map_err(|e| anyhow!("clipboard set failed: {e:?}"))?;
    Ok(())
}

// Try to read clipboard. If fails, return empty string
fn arboard_get_text_safe() -> String {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        if let Ok(t) = cb.get_text() {
            return t;
        }
    }
    String::new()
}

// Platform CLI fallbacks. Best effort, ignore errors
fn fallback_set(text: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // pbcopy
        let mut child = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("pbcopy spawn failed: {e}"))?;
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(text.as_bytes())?;
        let _ = child.wait();
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        // clip.exe
        let mut child = Command::new("cmd")
            .args(["/C", "clip"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("clip.exe spawn failed: {e}"))?;
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(text.as_bytes())?;
        let _ = child.wait();
        return Ok(());

    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // Wayland first: wl-copy
        if Command::new("sh").arg("-c").arg("command -v wl-copy >/dev/null")
            .status().map(|s| s.success()).unwrap_or(false)
        {
            let mut child = Command::new("wl-copy")
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| anyhow!("wl-copy spawn failed: {e}"))?;
            use std::io::Write;
            child.stdin.as_mut().unwrap().write_all(text.as_bytes())?;
            let _ = child.wait();
            return Ok(());
        }
        // X11: xclip -selection
        if Command::new("sh").arg("-c").arg("command -v xclip >/dev/null")
            .status().map(|s| s.success()).unwrap_or(false)
        {
            let mut child = Command::new("xclip")
                .args(["-selection", "clipboard"])
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| anyhow!("xclip spawn failed: {e}"))?;
            use std::io::Write;
            child.stdin.as_mut().unwrap().write_all(text.as_bytes())?;
            let _ = child.wait();
            return Ok(());
        }
        // Nothing avaliable
        return Err(anyhow!("no clipboard provider (install wl-copy or xclip)"));
    }
    #[allow(unreachable_code)]
    Err(anyhow!("unsupported platform"))
}

// Copy text to clipboard, trying arboard then fallback tools
pub fn clipboard_set(text: &str) -> Result<()> {
    if try_arboard_set(text).is_ok() {
        return Ok(());
    }
    fallback_set(text)
}

// Copy password to clipboard, restore previous or zero after timeout
pub fn clipboard_copy_pw_temporary(password: Zeroizing<String>, timeout_secs: u64) -> Result<()> {
    // Capture previous text (only works for arboard)
    let prev = arboard_get_text_safe();

    clipboard_set(password.as_str())?;

    if timeout_secs == 0 {
        println!("Copied to clipboard.");
        return Ok(());
    }

    println!("Copied to clipboard. Will clear in {}s...", timeout_secs);

    // Spawn a detached thread that restores previous contents.
    // Moving only copies- password will be dropped/zeroized here
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(timeout_secs));
        // Best-effort: try to restore with arboard, otherwise overwrite
        if try_arboard_set(&prev).is_err() {
            let _ = fallback_set("");
        }
    });

    Ok(())
}
