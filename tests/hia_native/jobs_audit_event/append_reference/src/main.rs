// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original jobs audit append reference, isolated from runtime installation.

use std::{io::{self, BufRead}, path::Path};
use serde_json::{Value, json};
mod original;
mod namespace_version;
fn main() -> anyhow::Result<()> {
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line?)?;
        let result = if value["reset"].as_bool() == Some(true) {
            original::reset(); json!({"reset":true})
        } else {
            original::capture(Path::new(value["root"].as_str().unwrap()),
                value["host"].as_str().unwrap(), value["subject"].as_str().unwrap(),
                value["fail_sync"].as_str().unwrap_or(""))
        };
        println!("{}", serde_json::to_string(&result)?);
    }
    Ok(())
}
