// Copyright 2026 Muvon Un Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod publication;
use std::io::{self, BufRead, Write};

fn main() -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let raw = line?;
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        let id = value.get("id").and_then(serde_json::Value::as_u64).ok_or_else(|| anyhow::anyhow!("missing observer id"))?;
        let call = publication::McpToolCall { parameters: value };
        let result = publication::execute_body(&call);
        let output = match result {
            Ok(text) => serde_json::json!({"id": id, "ok": true, "text": text}),
            Err(error) => serde_json::json!({"id": id, "ok": false, "text": error.to_string()}),
        };
        serde_json::to_writer(&mut stdout, &output)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}
