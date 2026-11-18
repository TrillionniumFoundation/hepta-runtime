// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Unchanged caller policy, with explicit scripted child contracts, never real archive claims.
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, Write};
include!("original_policy.rs");

#[derive(Clone, Deserialize, Serialize)]
struct Effect {
	kind: u64,
	argument_hex: String,
	flags: u64,
	reply_hex: String,
}
#[derive(Deserialize)]
struct Input {
	name: String,
	operation: u64,
	primary: Option<Record>,
	records: Vec<Record>,
	pending: Vec<String>,
	owner: String,
	id: String,
	sync: bool,
	effects: Vec<Effect>,
}
struct Script {
	rules: HashMap<(u64, String, u64), Effect>,
	trace: Vec<Effect>,
}
thread_local! {
	static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) };
}
#[derive(Debug)]
struct EffectTag(u64, u64, u64);
impl std::fmt::Display for EffectTag {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "scripted child error {}/{}/{}", self.0, self.1, self.2)
	}
}
impl std::error::Error for EffectTag {}
fn number(raw: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn word(raw: &mut [u8], at: usize, value: u64) {
	raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn hex(raw: &[u8]) -> String {
	use std::fmt::Write;
	let mut out = String::with_capacity(raw.len() * 2);
	for byte in raw {
		write!(out, "{byte:02x}").unwrap();
	}
	out
}
fn decode(value: &str) -> Vec<u8> {
	assert_eq!(value.len() % 2, 0);
	value
		.as_bytes()
		.chunks_exact(2)
		.map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
		.collect()
}
fn projection(value: &Record) -> Vec<u8> {
	let mut out = vec![0; 256];
	out[..8].copy_from_slice(b"HRAJJ001");
	word(&mut out, 8, 1);
	word(&mut out, 16, u64::from(value.elapsed_ms.is_some()));
	word(&mut out, 24, value.accepted_unix_ms as u64);
	word(&mut out, 32, (value.accepted_unix_ms >> 64) as u64);
	word(
		&mut out,
		40,
		match value.state {
			DurableState::Unknown => 0,
			DurableState::Completed => 1,
			DurableState::Failed => 2,
		},
	);
	word(&mut out, 48, value.elapsed_ms.unwrap_or(0));
	for (slot, value) in [&value.request_id, &value.owner, &value.tool_name]
		.into_iter()
		.enumerate()
	{
		let at = out.len();
		word(&mut out, 64 + slot * 16, at as u64);
		word(&mut out, 72 + slot * 16, value.len() as u64);
		out.extend_from_slice(value.as_bytes());
	}
	out
}
fn from_projection(raw: &[u8]) -> Record {
	assert_eq!(&raw[..8], b"HRAJJ001");
	assert_eq!(number(raw, 8), 1);
	let string = |slot: usize| {
		let at = number(raw, 64 + slot * 16) as usize;
		let size = number(raw, 72 + slot * 16) as usize;
		String::from_utf8(raw[at..at + size].to_vec()).unwrap()
	};
	let record = Record {
		request_id: string(0),
		owner: string(1),
		tool_name: string(2),
		accepted_unix_ms: number(raw, 24) as u128 | ((number(raw, 32) as u128) << 64),
		state: match number(raw, 40) {
			0 => DurableState::Unknown,
			1 => DurableState::Completed,
			2 => DurableState::Failed,
			_ => panic!("state"),
		},
		elapsed_ms: if number(raw, 16) == 1 {
			Some(number(raw, 48))
		} else {
			None
		},
	};
	assert_eq!(projection(&record), raw);
	record
}
fn child(kind: u64, argument: &[u8], flags: u64) -> Result<(u64, Vec<u8>)> {
	let effect = SCRIPT.with(|slot| {
		let mut slot = slot.borrow_mut();
		let script = slot.as_mut().unwrap();
		let key = (kind, hex(argument), flags);
		let effect = script
			.rules
			.get(&key)
			.unwrap_or_else(|| panic!("unexpected child {key:?}"))
			.clone();
		script.trace.push(effect.clone());
		effect
	});
	let raw = decode(&effect.reply_hex);
	assert_eq!(&raw[..8], b"HRAKC001");
	assert_eq!(number(&raw, 40), 0);
	let diagnostic = number(&raw, 8);
	let error = number(&raw, 16);
	let missing = number(&raw, 24);
	let value = number(&raw, 32);
	if diagnostic != 0 {
		assert_eq!(raw.len(), 48);
		assert_eq!(value, 0);
		let tag = EffectTag(diagnostic, error, missing);
		if diagnostic == 23 {
			let kind = if missing == 1 {
				io::ErrorKind::NotFound
			} else {
				io::ErrorKind::Other
			};
			return Err(anyhow::Error::new(io::Error::new(kind, "scripted child IO")).context(tag));
		}
		return Err(anyhow!(tag));
	}
	Ok((value, raw[48..].to_vec()))
}
fn read_record(_directory: &File, filename: &str) -> Result<Record> {
	let (size, raw) = child(100, filename.as_bytes(), 0)?;
	assert_eq!(size as usize, raw.len());
	Ok(from_projection(&raw))
}
struct Archive;
impl Archive {
	fn read_record(&self, filename: &str) -> Result<Record> {
		let (size, raw) = child(101, filename.as_bytes(), 0)?;
		assert_eq!(size as usize, raw.len());
		Ok(from_projection(&raw))
	}
}
fn is_active(id: &str) -> Result<bool> {
	let (active, raw) = child(102, id.as_bytes(), 0)?;
	assert!(active <= 1 && raw.is_empty());
	Ok(active != 0)
}
fn remove_record(_directory: &File, expected: &Record, sync_directory: bool) -> Result<()> {
	let (value, raw) = child(103, &projection(expected), u64::from(sync_directory))?;
	assert!(value == 0 && raw.is_empty());
	Ok(())
}
#[derive(Serialize)]
struct Output {
	name: String,
	result_hex: String,
	trace: Vec<Effect>,
	original_policy_executed: bool,
	real_archive_executed: bool,
	real_active_registry_executed: bool,
	real_hot_filesystem_executed: bool,
}
fn invoke(mut input: Input) -> Output {
	let count = input.effects.len();
	let rules: HashMap<_, _> = input
		.effects
		.into_iter()
		.map(|e| ((e.kind, e.argument_hex.clone(), e.flags), e))
		.collect();
	assert_eq!(count, rules.len());
	SCRIPT.with(|slot| {
		*slot.borrow_mut() = Some(Script {
			rules,
			trace: Vec::new(),
		})
	});
	let hot = File::open("/dev/null").unwrap();
	let archive = Archive;
	let outcome: Result<(u64, Option<Record>)> = match input.operation {
		1 => retained_record(&hot, &archive, &input.id).map(|r| (u64::from(r.is_some()), r)),
		2 => Ok((
			u64::from(archived_copy_matches(
				&archive,
				input.primary.as_ref().unwrap(),
			)),
			None,
		)),
		3 => archive_replacement(&archive, input.primary.as_ref().unwrap())
			.map(|r| (r.map_or(0, |replacing| 1 + u64::from(replacing)), None)),
		4 => retain_for_batch(
			&hot,
			&archive,
			&input.owner,
			&mut input.records,
			&input.pending.iter().cloned().collect(),
			input.sync,
		)
		.map(|value| (u64::from(value), None)),
		_ => panic!("operation"),
	};
	let mut out = vec![0; 64];
	out[..8].copy_from_slice(b"HRAKR001");
	let mut selected = None;
	match outcome {
		Ok((decision, record)) => {
			word(&mut out, 32, decision);
			selected = record;
		}
		Err(error) => {
			let (diagnostic, errno, kind) = if let Some(tag) = error.downcast_ref::<EffectTag>() {
				(tag.0, tag.1, tag.2)
			} else {
				let diagnostic = match error.to_string().as_str() {
					"request archive identity or outcome changed" => 35,
					"request archive identity changed" => 36,
					"request archive terminal outcome changed" => 37,
					_ => panic!("unclassified original error: {error:#}"),
				};
				(diagnostic, 0, 0)
			};
			word(&mut out, 8, diagnostic);
			word(&mut out, 16, errno);
			word(&mut out, 24, kind);
		}
	}
	if input.operation == 4 {
		word(&mut out, 40, input.records.len() as u64);
		for record in &input.records {
			let raw = projection(record);
			out.extend_from_slice(&(raw.len() as u64).to_le_bytes());
			out.extend_from_slice(&raw);
		}
	} else if let Some(record) = selected {
		let raw = projection(&record);
		word(&mut out, 48, raw.len() as u64);
		out.extend_from_slice(&raw);
	}
	let trace = SCRIPT.with(|slot| slot.borrow_mut().take().unwrap().trace);
	Output {
		name: input.name,
		result_hex: hex(&out),
		trace,
		original_policy_executed: true,
		real_archive_executed: false,
		real_active_registry_executed: false,
		real_hot_filesystem_executed: false,
	}
}
fn main() -> io::Result<()> {
	let mut output = io::BufWriter::new(io::stdout().lock());
	for line in io::stdin().lock().lines() {
		let result = invoke(serde_json::from_str(&line?).unwrap());
		serde_json::to_writer(&mut output, &result)?;
		writeln!(output)?;
		output.flush()?;
	}
	Ok(())
}
