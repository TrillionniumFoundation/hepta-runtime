// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original hot-cache methods with explicitly scripted storage children.
mod namespace_version {
	include!("original_namespace.rs");
}
mod audit {
	use anyhow::{anyhow, bail, Result};
	use serde::{Deserialize, Serialize};
	use std::cell::RefCell;
	use std::collections::VecDeque;
	use std::fs::File;
	use std::io::{self, BufRead, Write};
	use std::sync::{Mutex, OnceLock};
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
		directory: u64,
		archive: u64,
		consume: bool,
		records: Vec<Record>,
		before_stamp_hex: String,
		effects: Vec<Effect>,
	}
	#[derive(Deserialize)]
	struct Case {
		name: String,
		steps: Vec<Input>,
	}
	struct Script {
		remaining: VecDeque<Effect>,
		trace: Vec<Effect>,
		directory: u64,
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
			let effect = script
				.remaining
				.pop_front()
				.expect("unexpected extra child");
			assert_eq!(
				(effect.kind, effect.argument_hex.as_str(), effect.flags),
				(kind, hex(argument).as_str(), flags)
			);
			script.trace.push(effect.clone());
			effect
		});
		let raw = decode(&effect.reply_hex);
		assert_eq!(&raw[..8], b"HRACC001");
		assert_eq!(number(&raw, 40), 0);
		let diagnostic = number(&raw, 8);
		let error = number(&raw, 16);
		let error_kind = number(&raw, 24);
		let value = number(&raw, 32);
		if diagnostic != 0 {
			assert_eq!(raw.len(), 48);
			assert_eq!(value, 0);
			let tag = EffectTag(diagnostic, error, error_kind);
			if diagnostic == 23 {
				let kind = if error_kind == 1 {
					io::ErrorKind::NotFound
				} else {
					io::ErrorKind::Other
				};
				return Err(
					anyhow::Error::new(io::Error::new(kind, "scripted child IO")).context(tag),
				);
			}
			return Err(anyhow!(tag));
		}
		Ok((value, raw[48..].to_vec()))
	}
	fn directory_argument() -> [u8; 8] {
		SCRIPT.with(|slot| slot.borrow().as_ref().unwrap().directory.to_le_bytes())
	}
	fn from_stamp(raw: &[u8]) -> ArchiveStamp {
		assert_eq!(raw.len(), 112);
		assert_eq!(&raw[..8], b"HRAST001");
		let namespace = match number(raw, 56) {
			1 => {
				assert_eq!(&raw[80..112], &[0; 32]);
				super::namespace_version::Version::Watch(number(raw, 64), number(raw, 72))
			}
			2 => {
				assert_eq!(number(raw, 64), 0);
				assert_eq!(number(raw, 72), 0);
				super::namespace_version::Version::Fingerprint(raw[80..112].try_into().unwrap())
			}
			_ => panic!("namespace tag"),
		};
		ArchiveStamp {
			device: number(raw, 8),
			inode: number(raw, 16),
			modified: (number(raw, 24) as i64, number(raw, 32) as i64),
			changed: (number(raw, 40) as i64, number(raw, 48) as i64),
			namespace,
		}
	}
	fn from_records(raw: &[u8], count: u64) -> Vec<Record> {
		let mut at = 0;
		let mut result = Vec::new();
		for _ in 0..count {
			let size = number(raw, at) as usize;
			at += 8;
			result.push(from_projection(&raw[at..at + size]));
			at += size;
		}
		assert_eq!(at, raw.len());
		result
	}
	fn archive_stamp(_directory: &File) -> Result<ArchiveStamp> {
		let (count, raw) = child(100, &directory_argument(), 0)?;
		assert_eq!(count, 112);
		Ok(from_stamp(&raw))
	}
	fn entries(_directory: &File) -> Result<Vec<Record>> {
		let (count, raw) = child(101, &directory_argument(), 0)?;
		Ok(from_records(&raw, count))
	}
	struct Archive {
		token: u64,
	}
	impl Archive {
		fn existing_directory(&self, filename: &str) -> Result<Option<()>> {
			let mut argument = self.token.to_le_bytes().to_vec();
			argument.extend_from_slice(filename.as_bytes());
			let (value, raw) = child(102, &argument, 0)?;
			assert!(value <= 1 && raw.is_empty());
			Ok((value == 1).then_some(()))
		}
	}
	fn save_archive_with_sync(
		archive: &Archive,
		record: &Record,
		sync_directory: bool,
		prefer_legacy: bool,
	) -> Result<()> {
		let mut argument = archive.token.to_le_bytes().to_vec();
		argument.extend_from_slice(&projection(record));
		let (value, raw) = child(
			103,
			&argument,
			u64::from(sync_directory) | (u64::from(prefer_legacy) << 1),
		)?;
		assert!(value == 0 && raw.is_empty());
		Ok(())
	}
	fn inspect_cache() -> (u64, u64, u64) {
		let Some(cache) = HOT_CACHE.get() else {
			return (0, 0, 0);
		};
		let poison = u64::from(cache.is_poisoned());
		let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
		(guard.len() as u64, 1, poison)
	}
	#[derive(Serialize)]
	struct Output {
		name: String,
		result_hex: String,
		trace: Vec<Effect>,
	}
	fn invoke(mut input: Input, directory: &File) -> Output {
		SCRIPT.with(|slot| {
			*slot.borrow_mut() = Some(Script {
				remaining: input.effects.into(),
				trace: Vec::new(),
				directory: input.directory,
			})
		});
		let archive = Archive {
			token: input.archive,
		};
		let outcome: Result<(u64, Vec<Record>)> = match input.operation {
			0 => Ok((inspect_cache().2, Vec::new())),
			1 => cache_hot_owned(directory, std::mem::take(&mut input.records))
				.map(|_| (0, Vec::new())),
			2 => hot_snapshot_cached(directory).map(|value| (u64::from(value), Vec::new())),
			3 => hot_snapshot_at(directory, &archive, input.consume).map(|records| (0, records)),
			4 => update_cached_completion(
				directory,
				&input.records[0],
				from_stamp(&decode(&input.before_stamp_hex)),
			)
			.map(|_| (0, Vec::new())),
			5 => {
				let previous_hook = std::panic::take_hook();
				std::panic::set_hook(Box::new(|_| {}));
				let result = std::panic::catch_unwind(|| {
					let _guard = HOT_CACHE
						.get_or_init(|| Mutex::new(VecDeque::new()))
						.lock()
						.unwrap_or_else(|p| p.into_inner());
					panic!("private poison trigger");
				});
				std::panic::set_hook(previous_hook);
				assert!(result.is_err());
				Ok((0, Vec::new()))
			}
			_ => panic!("operation"),
		};
		let mut out = vec![0; 64];
		out[..8].copy_from_slice(b"HRACR001");
		let mut selected = Vec::new();
		match outcome {
			Ok((value, records)) => {
				word(&mut out, 32, value);
				selected = records;
			}
			Err(error) => {
				let (diagnostic, errno, kind) = if let Some(tag) = error.downcast_ref::<EffectTag>()
				{
					(tag.0, tag.1, tag.2)
				} else {
					let diagnostic = match error.to_string().as_str() {
						"request hot cache unavailable" => 43,
						"request hot namespace changed during validation" => 44,
						"request hot snapshot unavailable" => 45,
						_ => panic!("unclassified original error: {error:#}"),
					};
					(diagnostic, 0, 0)
				};
				word(&mut out, 8, diagnostic);
				word(&mut out, 16, errno);
				word(&mut out, 24, kind);
			}
		}
		let (count, initialized, _) = inspect_cache();
		word(&mut out, 40, selected.len() as u64);
		word(&mut out, 48, count);
		word(&mut out, 56, initialized);
		for record in &selected {
			let raw = projection(record);
			out.extend_from_slice(&(raw.len() as u64).to_le_bytes());
			out.extend_from_slice(&raw);
		}
		let script = SCRIPT.with(|slot| slot.borrow_mut().take().unwrap());
		assert!(script.remaining.is_empty(), "unconsumed child plan");
		Output {
			name: input.name,
			result_hex: hex(&out),
			trace: script.trace,
		}
	}
	#[derive(Serialize)]
	struct CaseOutput {
		name: String,
		results: Vec<Output>,
		original_functions_executed: bool,
		original_cache_state_uses_std_once_lock_and_mutex: bool,
		mutex_observed_initialized: bool,
		actual_private_poison_panics: usize,
		real_archive_executed: bool,
		real_hot_filesystem_executed: bool,
	}
	pub fn main() -> io::Result<()> {
		let mut input = io::stdin().lock().lines();
		let case: Case = serde_json::from_str(&input.next().expect("one case")?).unwrap();
		assert!(
			input.next().is_none(),
			"one fresh process per cache lifetime"
		);
		let directory = File::open("/dev/null").unwrap();
		let panics = case.steps.iter().filter(|s| s.operation == 5).count();
		let results = case
			.steps
			.into_iter()
			.map(|step| invoke(step, &directory))
			.collect();
		let result = CaseOutput {
			name: case.name,
			results,
			original_functions_executed: true,
			original_cache_state_uses_std_once_lock_and_mutex: true,
			mutex_observed_initialized: HOT_CACHE.get().is_some(),
			actual_private_poison_panics: panics,
			real_archive_executed: false,
			real_hot_filesystem_executed: false,
		};
		let mut output = io::BufWriter::new(io::stdout().lock());
		serde_json::to_writer(&mut output, &result)?;
		writeln!(output)?;
		output.flush()
	}
}
fn main() -> std::io::Result<()> {
	audit::main()
}
