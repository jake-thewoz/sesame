use anyhow::{Result, anyhow};
use std::io::{self, Write};
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

