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

//! Project actual original handler results through each installed-capability mask,
//! then execute the actual locked SDK's serialization and peer policy.
use std::io::{Read, Write};
use rmcp::model::{ListToolsResult, ServerResult};

const INSTALLED: [&str; 11] = [
    "batch_edit", "directory_create", "directory_move", "effective_config",
    "execution_shadow_admit", "file_move", "host_list", "text_editor", "view",
    "weight_bellman_plan", "workdir",
];

fn word(raw: &[u8], at: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&raw[at..at + 8]);
    u64::from_le_bytes(bytes)
}

fn main() -> anyhow::Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut sequence = 0u64;
    loop {
        let mut header = [0u8; 64];
        match input.read(&mut header[..1])? {
            0 => break,
            1 => input.read_exact(&mut header[1..])?,
            _ => unreachable!(),
        }
        anyhow::ensure!(&header[..8] == b"HCATSP02");
        anyhow::ensure!(word(&header, 8) == sequence);
        let flags = word(&header, 16);
        let modern = word(&header, 24);
        let policy = word(&header, 32);
        let size = word(&header, 40);
        let installed = word(&header, 48);
        anyhow::ensure!(modern <= 1 && policy <= 2 && size <= 8 * 1024 * 1024);
        anyhow::ensure!(installed <= 3 && word(&header, 56) == 0);
        anyhow::ensure!([0, 1, 3, 5, 7, 9, 11, 13, 15].contains(&flags));
        let mut body = vec![0u8; size as usize];
        input.read_exact(&mut body)?;
        let mut value: ListToolsResult = serde_json::from_slice(&body)?;
        value.tools.retain(|tool| INSTALLED.contains(&tool.name.as_ref())
            && (tool.name != "batch_edit" || installed & 1 != 0)
            && (tool.name != "weight_bellman_plan" || installed & 2 != 0));
        let count = value.tools.len() as u64;
        let mut value = ServerResult::ListToolsResult(value);
        if policy == 1 {
            value.strip_result_type_for_legacy_peer();
        } else if policy == 2 {
            value.fill_missing_cache_hints();
        }
        let encoded = serde_json::to_vec(&value)?;
        output.write_all(b"HCATSD02")?;
        for word in [sequence, flags, modern, policy, count, encoded.len() as u64, installed] {
            output.write_all(&word.to_le_bytes())?;
        }
        output.write_all(&encoded)?;
        sequence += 1;
    }
    anyhow::ensure!(sequence == 1728);
    output.flush()?;
    Ok(())
}
