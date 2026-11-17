// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
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
//! Observe actual Serde writer calls around the unchanged target commitment.

use std::io::{Read, Write};
include!(concat!(env!("OUT_DIR"), "/module.rs"));

fn main() -> anyhow::Result<()> {
	let mut input = String::new();
	std::io::stdin().read_to_string(&mut input)?;
	let mut output = std::io::stdout().lock();
	for (index, line) in input.lines().enumerate() {
		let value = original::trace_canonical_writer(line)?;
		serde_json::to_writer(&mut output, &serde_json::json!({"index": index, "trace": value}))?;
		output.write_all(b"\n")?;
	}
	output.flush()?;
	eprintln!("{{\"pid\":{},\"parent_pid\":{},\"pgid\":{}}}", std::process::id(), unsafe { libc::getppid() }, unsafe { libc::getpgrp() });
	Ok(())
}
