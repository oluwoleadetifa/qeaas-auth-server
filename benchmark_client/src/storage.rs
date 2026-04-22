// benchmark_client/src/storage.rs
use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};

use crate::models::StoredUser;

pub fn append_user(path: &str, user: &StoredUser) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open users file for append: {path}"))?;

    writeln!(f, "{}", serde_json::to_string(user)?)
        .with_context(|| format!("failed to write user record to {path}"))?;

    Ok(())
}

pub fn load_users(path: &str) -> Result<Vec<StoredUser>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open users file: {path}"))?;
    let reader = BufReader::new(file);

    let mut users = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let user: StoredUser = serde_json::from_str(&line)
            .with_context(|| "failed to parse JSONL user record")?;
        users.push(user);
    }

    Ok(users)
}

