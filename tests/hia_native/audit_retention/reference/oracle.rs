// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Execute unchanged original audit retention policy with explicit mechanical effect fixtures.
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, Write};

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DurableState {
	Unknown,
	Completed,
	Failed,
}

mod record_schema {
	use super::DurableState;
	use serde::{Deserialize, Serialize};

	// Serde derives its default Visitor diagnostic from the Rust identifier,
	// not serde(rename). Keep the original name for both string specializations.
	#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
	#[serde(deny_unknown_fields)]
	pub(super) struct Record<S> {
		pub(super) request_id: S,
		pub(super) owner: S,
		pub(super) tool_name: S,
		pub(super) state: DurableState,
		pub(super) accepted_unix_ms: u128,
		pub(super) elapsed_ms: Option<u64>,
	}
}
// Owned publications, projections and legacy rows keep their original type.
// Complete original verification borrows only the three string fields from its
// current bounded input; both forms share this exact serde field contract.
type RecordFields<S> = record_schema::Record<S>;
type Record = record_schema::Record<String>;

const MAX_GLOBAL: usize = 512;
const MAX_OWNER: usize = 128;

#[cfg(unix)]
fn archived_copy_matches(archive: &Archive, record: &Record) -> bool {
	let Ok(archived) = archive.read_record(&format!("{}.json", record.request_id)) else {
		return false;
	};
	archived.owner == record.owner
		&& archived.tool_name == record.tool_name
		&& archived.accepted_unix_ms == record.accepted_unix_ms
		&& (record.state == DurableState::Unknown || record.state == archived.state)
		&& (record.elapsed_ms.is_none() || record.elapsed_ms == archived.elapsed_ms)
}

#[cfg(unix)]
fn retain_before_begin(
	directory: &File,
	archive: &Archive,
	owner: &str,
	records: &mut Vec<Record>,
) -> Result<bool> {
	retain_for_batch(directory, archive, owner, records, &HashSet::new(), true)
}

#[cfg(unix)]
fn retain_for_batch(
	directory: &File,
	archive: &Archive,
	owner: &str,
	records: &mut Vec<Record>,
	pending: &HashSet<String>,
	sync_directory: bool,
) -> Result<bool> {
	while records
		.iter()
		.filter(|record| record.owner == owner)
		.count()
		>= MAX_OWNER
	{
		let mut victim = None;
		for (index, record) in records.iter().enumerate() {
			if record.owner == owner
				&& !pending.contains(&record.request_id)
				&& !is_active(&record.request_id)?
				&& archived_copy_matches(archive, record)
			{
				victim = Some(index);
				break;
			}
		}
		let Some(index) = victim else {
			return Ok(false);
		};
		remove_record(directory, &records[index], sync_directory)?;
		records.remove(index);
	}
	while records.len() >= MAX_GLOBAL {
		let mut victim = None;
		for (index, record) in records.iter().enumerate() {
			if !pending.contains(&record.request_id)
				&& !is_active(&record.request_id)?
				&& archived_copy_matches(archive, record)
			{
				victim = Some(index);
				break;
			}
		}
		let Some(index) = victim else {
			return Ok(false);
		};
		remove_record(directory, &records[index], sync_directory)?;
		records.remove(index);
	}
	Ok(true)
}

fn word(out: &mut [u8], at: usize, value: u64) {
	out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn get(raw: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

fn project_record<S: AsRef<str>>(record: &RecordFields<S>) -> Vec<u8> {
	let mut out = vec![0; 128];
	out[..8].copy_from_slice(b"HAJPR001");
	word(&mut out, 8, 1);
	word(&mut out, 16, u64::from(record.elapsed_ms.is_some()));
	word(&mut out, 24, record.accepted_unix_ms as u64);
	word(&mut out, 32, (record.accepted_unix_ms >> 64) as u64);
	word(
		&mut out,
		40,
		match record.state {
			DurableState::Unknown => 0,
			DurableState::Completed => 1,
			DurableState::Failed => 2,
		},
	);
	word(&mut out, 48, record.elapsed_ms.unwrap_or(0));
	for (index, text) in [
		record.request_id.as_ref(),
		record.owner.as_ref(),
		record.tool_name.as_ref(),
	]
	.into_iter()
	.enumerate()
	{
		let offset = out.len();
		word(&mut out, 64 + index * 16, offset as u64);
		word(&mut out, 72 + index * 16, text.len() as u64);
		out.extend_from_slice(text.as_bytes());
	}
	out
}


type Result<T> = std::result::Result<T, u64>;
struct File;
struct Archive;

#[derive(Clone, Deserialize)]
struct Rule {
	status: u64,
	error: u64,
	#[serde(default)]
	record_hex: Option<String>,
}

#[derive(Deserialize)]
struct Case {
	name: String,
	initial_hex: String,
	effects: HashMap<String, HashMap<String, Vec<Rule>>>,
}

struct Fixture {
	rules: HashMap<String, HashMap<String, Vec<Rule>>>,
	counters: HashMap<(String, String), usize>,
	archive: HashMap<String, Record>,
	sequence: u64,
	trace: Vec<u8>,
}

thread_local! {
	static FIXTURE: RefCell<Option<Fixture>> = const { RefCell::new(None) };
}

impl Fixture {
	fn pick(&mut self, group: &str, key: &str, default: Rule) -> Rule {
		let counter = self.counters.entry((group.to_owned(), key.to_owned())).or_default();
		let at = *counter;
		*counter += 1;
		self.rules
			.get(group)
			.and_then(|rules| rules.get(key))
			.map(|tape| tape[at.min(tape.len() - 1)].clone())
			.unwrap_or(default)
	}

	fn record(&mut self, kind: u64, argument: &[u8], rule: &Rule, payload: &[u8]) {
		self.sequence += 1;
		let mut reply = b"HATRQ001".to_vec();
		for word in [3, self.sequence, kind, rule.status, rule.error, payload.len() as u64, 0] {
			reply.extend_from_slice(&word.to_le_bytes());
		}
		reply.extend_from_slice(payload);
		self.trace.extend_from_slice(b"HTREFF01");
		self.trace.extend_from_slice(&kind.to_le_bytes());
		self.trace.extend_from_slice(&(argument.len() as u64).to_le_bytes());
		self.trace.extend_from_slice(argument);
		self.trace.extend_from_slice(&(reply.len() as u64).to_le_bytes());
		self.trace.extend_from_slice(&reply);
	}
}

fn zero_rule() -> Rule {
	Rule { status: 0, error: 0, record_hex: None }
}

fn is_active(request_id: &str) -> Result<bool> {
	FIXTURE.with_borrow_mut(|state| {
		let fixture = state.as_mut().unwrap();
		let rule = fixture.pick("active", request_id, zero_rule());
		fixture.record(1, request_id.as_bytes(), &rule, &[]);
		match rule.status {
			0 => Ok(false),
			1 => Ok(true),
			2 => Err(rule.error),
			_ => panic!("invalid active fixture"),
		}
	})
}

impl Archive {
	fn read_record(&self, filename: &str) -> Result<Record> {
		FIXTURE.with_borrow_mut(|state| {
			let fixture = state.as_mut().unwrap();
			let default = match fixture.archive.get(filename) {
				Some(record) => Rule {
					status: 0,
					error: 0,
					record_hex: Some(encode(&project_record(record))),
				},
				None => Rule { status: 1, error: 901, record_hex: None },
			};
			let rule = fixture.pick("archive", filename, default);
			let payload = rule.record_hex.as_ref().map(|value| decode(value)).unwrap_or_default();
			fixture.record(2, filename.as_bytes(), &rule, &payload);
			match rule.status {
				0 => Ok(parse_record(&payload)),
				1 => Err(rule.error),
				_ => panic!("invalid archive fixture"),
			}
		})
	}
}

fn remove_record(_directory: &File, record: &Record, sync_directory: bool) -> Result<()> {
	FIXTURE.with_borrow_mut(|state| {
		let fixture = state.as_mut().unwrap();
		let rule = fixture.pick("remove", &record.request_id, zero_rule());
		let mut argument = u64::from(sync_directory).to_le_bytes().to_vec();
		argument.extend_from_slice(&project_record(record));
		fixture.record(3, &argument, &rule, &[]);
		match rule.status {
			0 => Ok(()),
			1 => Err(rule.error),
			_ => panic!("invalid remove fixture"),
		}
	})
}

fn parse_record(raw: &[u8]) -> Record {
	assert!(raw.len() >= 128);
	assert_eq!(&raw[..8], b"HAJPR001");
	assert_eq!(get(raw, 8), 1);
	let fields: Vec<String> = (0..3)
		.map(|index| {
			let at = get(raw, 64 + index * 16) as usize;
			let size = get(raw, 72 + index * 16) as usize;
			std::str::from_utf8(&raw[at..at + size]).unwrap().to_owned()
		})
		.collect();
	Record {
		request_id: fields[0].clone(),
		owner: fields[1].clone(),
		tool_name: fields[2].clone(),
		state: match get(raw, 40) {
			0 => DurableState::Unknown,
			1 => DurableState::Completed,
			2 => DurableState::Failed,
			_ => panic!("invalid typed state"),
		},
		accepted_unix_ms: u128::from(get(raw, 24)) | (u128::from(get(raw, 32)) << 64),
		elapsed_ms: if get(raw, 16) == 0 { None } else { Some(get(raw, 48)) },
	}
}

fn invoke(case: Case) -> Vec<u8> {
	let frame = decode(&case.initial_hex);
	assert_eq!(&frame[..8], b"HATRQ001");
	assert_eq!(get(&frame, 80), frame.len() as u64);
	let at = get(&frame, 40) as usize;
	let size = get(&frame, 48) as usize;
	let owner = std::str::from_utf8(&frame[at..at + size]).unwrap();
	let mut records: Vec<Record> = (0..get(&frame, 16) as usize)
		.map(|index| {
			let at = get(&frame, 128 + index * 16) as usize;
			let size = get(&frame, 136 + index * 16) as usize;
			parse_record(&frame[at..at + size])
		})
		.collect();
	let table = get(&frame, 64) as usize;
	let pending: HashSet<String> = (0..get(&frame, 24) as usize)
		.map(|index| {
			let at = get(&frame, table + index * 16) as usize;
			let size = get(&frame, table + index * 16 + 8) as usize;
			std::str::from_utf8(&frame[at..at + size]).unwrap().to_owned()
		})
		.collect();
	let mut archive = HashMap::new();
	for record in &records {
		archive.entry(format!("{}.json", record.request_id)).or_insert_with(|| record.clone());
	}
	FIXTURE.with_borrow_mut(|state| {
		assert!(state.is_none());
		*state = Some(Fixture {
			rules: case.effects,
			counters: HashMap::new(),
			archive,
			sequence: 0,
			trace: Vec::new(),
		});
	});
	let result = match get(&frame, 8) {
		1 => {
			assert!(pending.is_empty() && get(&frame, 32) == 1);
			retain_before_begin(&File, &Archive, owner, &mut records)
		},
		2 => retain_for_batch(&File, &Archive, owner, &mut records, &pending, get(&frame, 32) == 1),
		_ => panic!("invalid fixture operation"),
	};
	let fixture = FIXTURE.with_borrow_mut(|state| state.take().unwrap());
	let (status, error): (u64, u64) = match result {
		Ok(true) => (1, 0),
		Ok(false) => (2, 0),
		Err(error) => (3, error),
	};
	let mut output = b"HATRV001".to_vec();
	for word in [status, error, records.len() as u64, fixture.trace.len() as u64] {
		output.extend_from_slice(&word.to_le_bytes());
	}
	for record in records {
		let raw = project_record(&record);
		output.extend_from_slice(&(raw.len() as u64).to_le_bytes());
		output.extend_from_slice(&raw);
	}
	output.extend_from_slice(&fixture.trace);
	output
}

fn encode(raw: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut text = String::with_capacity(raw.len() * 2);
	for byte in raw {
		text.push(char::from(DIGITS[(byte >> 4) as usize]));
		text.push(char::from(DIGITS[(byte & 15) as usize]));
	}
	text
}

fn decode(text: &str) -> Vec<u8> {
	assert_eq!(text.len() % 2, 0);
	text.as_bytes()
		.chunks_exact(2)
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn main() -> io::Result<()> {
	let mut stdout = io::BufWriter::new(io::stdout().lock());
	for line in io::stdin().lock().lines() {
		let case: Case = serde_json::from_str(&line?).unwrap();
		let name = encode(case.name.as_bytes());
		let output = invoke(case);
		writeln!(stdout, "{}:{}", name, encode(&output))?;
	}
	stdout.flush()
}
