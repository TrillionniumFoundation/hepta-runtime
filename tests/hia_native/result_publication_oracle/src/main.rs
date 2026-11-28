// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Execute the frozen original hint composer and locked SDK/serde serializers.
//! The input adapter supplies an already-drained list verbatim. It does not
//! deduplicate, simulate native fragments, or reuse native output as a reference.

use rmcp::model::{CallToolResult, ContentBlock, ServerResult};
use serde_json::json;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

mod request_ctx {
	use super::RefCell;
	thread_local! {
		pub static DRAINED: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
	}
	pub fn drain_hints() -> Vec<String> {
		DRAINED.with(|slot| slot.borrow_mut().take().unwrap_or_default())
	}
}

include!("../fixtures/original_append_hints.rs");

fn word(input: &mut impl Read) -> AnyResult<u64> {
	let mut bytes = [0u8; 8];
	input.read_exact(&mut bytes)?;
	Ok(u64::from_le_bytes(bytes))
}

fn bytes(input: &mut impl Read, count: u64) -> AnyResult<Vec<u8>> {
	let mut bytes = vec![0; usize::try_from(count)?];
	input.read_exact(&mut bytes)?;
	Ok(bytes)
}

fn original_result(text: String, is_error: bool) -> ServerResult {
	let result = if is_error {
		CallToolResult::error(vec![ContentBlock::text(text)])
	} else {
		CallToolResult::success(vec![ContentBlock::text(text)])
	};
	// Execute the same locked SDK normalization used by the original server
	// handler for the production profile's negotiated 2025-06-18 protocol.
	let mut result = ServerResult::CallToolResult(result);
	result.strip_result_type_for_legacy_peer();
	result
}

fn emit<W: Write>(
	output: &mut W,
	mode: u64,
	is_error: bool,
	prefix: &[u8],
	text: String,
) -> AnyResult<()> {
	match mode {
		0 => output.write_all(text.as_bytes())?,
		1 => serde_json::to_writer(output, &text)?,
		2 => serde_json::to_writer(output, &original_result(text, is_error))?,
		3 => {
			// The prefix is a separately owned, already-validated native RPC
			// prefix. Its preservation is the adapter domain, not new parsing.
			// Obtain the result suffix from the actual SDK serializer too.
			let empty = serde_json::to_vec(&original_result(String::new(), is_error))?;
			let head = b"{\"content\":[{\"type\":\"text\",\"text\":\"\"";
			let suffix = empty
				.strip_prefix(head)
				.ok_or("locked SDK envelope changed")?;
			output.write_all(prefix)?;
			serde_json::to_writer(&mut *output, &text)?;
			output.write_all(suffix)?;
			output.write_all(b"}")?;
		}
		_ => return Err("unsupported original reference mode".into()),
	}
	Ok(())
}

fn replay(input_path: &str, output_path: &str) -> AnyResult<serde_json::Value> {
	let mut input = BufReader::new(File::open(input_path)?);
	let mut output = BufWriter::new(
		OpenOptions::new()
			.write(true)
			.read(true)
			.create_new(true)
			.open(output_path)?,
	);
	let mut magic = [0u8; 8];
	input.read_exact(&mut magic)?;
	if &magic != b"HRPOI001" {
		return Err("original input magic differs".into());
	}
	let count = word(&mut input)?;
	output.write_all(b"HRPOO001")?;
	output.write_all(&count.to_le_bytes())?;
	let mut body_bytes = 0u64;
	let mut mode_counts = [0u64; 4];
	let mut largest = 0u64;
	let mut seen = HashSet::new();
	for _ in 0..count {
		let case_id = word(&mut input)?;
		let mode = word(&mut input)?;
		let error = word(&mut input)?;
		let prefix_len = word(&mut input)?;
		let base_len = word(&mut input)?;
		let hint_count = word(&mut input)?;
		if !seen.insert(case_id) || mode > 3 || error > 1 {
			return Err("invalid original record identity".into());
		}
		if mode != 3 && prefix_len != 0 {
			return Err("prefix outside entrusted-prefix mode".into());
		}
		let prefix = bytes(&mut input, prefix_len)?;
		let base = String::from_utf8(bytes(&mut input, base_len)?)?;
		let mut hints = Vec::new();
		for _ in 0..hint_count {
			let size = word(&mut input)?;
			hints.push(String::from_utf8(bytes(&mut input, size)?)?);
		}
		request_ctx::DRAINED.with(|slot| *slot.borrow_mut() = Some(hints));
		let text = append_hints(base);
		if request_ctx::DRAINED.with(|slot| slot.borrow().is_some()) {
			return Err("original append did not drain the supplied list".into());
		}
		output.write_all(&case_id.to_le_bytes())?;
		let length_at = output.stream_position()?;
		output.write_all(&0u64.to_le_bytes())?;
		let start = output.stream_position()?;
		emit(&mut output, mode, error != 0, &prefix, text)?;
		let end = output.stream_position()?;
		let length = end.checked_sub(start).ok_or("output length underflow")?;
		output.seek(SeekFrom::Start(length_at))?;
		output.write_all(&length.to_le_bytes())?;
		output.seek(SeekFrom::Start(end))?;
		body_bytes = body_bytes
			.checked_add(length)
			.ok_or("body count overflow")?;
		largest = largest.max(length);
		mode_counts[mode as usize] += 1;
	}
	let mut tail = [0u8; 1];
	if input.read(&mut tail)? != 0 {
		return Err("trailing original input bytes".into());
	}
	output.flush()?;
	Ok(
		json!({"schema":"hepta.runtime.result-publication.original-replay.v1",
		"cases":count,"mode_counts":mode_counts,"body_bytes":body_bytes,"largest_body_bytes":largest,
		"original_append_function_executed":true,"post_drain_list_supplied_verbatim":true,
		"dedup_applied_by_composer":false,"serde_json":"1.0.151","rmcp":"3.4.1",
		"protocol_normalization":"rmcp ServerResult::strip_result_type_for_legacy_peer (2025-06-18)",
		"native_scheduler_qualified":false,"filesystem_callers_replaced":false}),
	)
}

fn main() -> AnyResult<()> {
	let args: Vec<String> = std::env::args().collect();
	if args.len() != 3 {
		return Err("usage: original-oracle INPUT.bin OUTPUT.bin".into());
	}
	let summary = replay(&args[1], &args[2])?;
	serde_json::to_writer(io::stdout().lock(), &summary)?;
	println!();
	Ok(())
}
