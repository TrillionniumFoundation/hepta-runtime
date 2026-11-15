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

//! Bounded parsing of an immutable Linux ELF core recording, without live resolution.
//!
//! The payload follows the frozen REA 6.8.0 `recorded_crash_impl.py` helper. A PID,
//! pathname, address, register, or signal in this recording never grants authority
//! over a current process. The caller owns the byte snapshot and resource budget;
//! this module performs no filesystem, process, dependency, or environment lookup.

use serde_json::{json, Value};
use std::fmt;

#[path = "rea_recorded_core_budget.rs"]
mod budget;
#[path = "rea_recorded_core_layout.rs"]
mod layout;

use budget::{encoded, lossy_display, Budget};
use layout::{core_note_type, program_type, Architecture};

const RANGE_MESSAGE: &str = "Recorded source range exceeds its declared container.";
const LIMITATIONS: [&str; 6] = [
	"The initial Linux note profile accepts System V/unspecified or GNU/Linux OSABI with ABI version zero; an unspecified OSABI alone does not prove operating-system origin.",
	"Historical PID and signal values are recorded metadata, not current process identity or attach authority.",
	"Only exact Linux CORE NT_PRSTATUS/NT_SIGINFO owners are interpreted; every descriptor and owner retains original bytes. Other note semantics remain unknown.",
	"NT_SIGINFO thread association is unknown. Only SIGSEGV SEGV_MAPERR/SEGV_ACCERR initially establish a fault-address union meaning.",
	"PT_LOAD file bytes are recorded bytes. Undumped memory and current executable/library identity remain unknown; no current host file is resolved from a recorded pathname.",
	"Missing notes/registers/signals do not establish their absence at the original crash. Full unwinding, executable pairing and live control are not provided.",
];

/// Frozen helper failures and separately identified native admission failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CoreFailure {
	pub reason: &'static str,
	pub message: String,
}

impl CoreFailure {
	fn new(reason: &'static str, message: impl Into<String>) -> Self {
		Self {
			reason,
			message: message.into(),
		}
	}

	fn format(message: impl Into<String>) -> Self {
		Self::new("format", message)
	}

	fn range() -> Self {
		Self::format(RANGE_MESSAGE)
	}

	fn budget() -> Self {
		Self::new(
			"budget",
			"Complete recorded-core payload exceeds the native output budget.",
		)
	}

	fn allocation() -> Self {
		Self::new(
			"resource-limit",
			"Native recorded-core allocation failed within the admitted output budget.",
		)
	}
}

impl fmt::Display for CoreFailure {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(&self.message)
	}
}

impl std::error::Error for CoreFailure {}

#[derive(Default)]
struct Tables {
	segments: Vec<Value>,
	notes: Vec<Value>,
	padding: Vec<Value>,
	threads: Vec<Value>,
	signals: Vec<Value>,
}

struct Note<'a> {
	index: usize,
	segment_index: u64,
	type_id: u32,
	start: u64,
	end: u64,
	container_end: u64,
	owner_start: u64,
	descriptor_start: u64,
	owner: &'a [u8],
	descriptor: &'a [u8],
}

/// Parse the complete admitted recording or fail; never return truncated arrays.
///
/// `max_output_bytes` bounds the compact UTF-8 JSON encoding of the complete
/// payload, independently of any worker envelope. Budget refusal is deliberately
/// distinct from a frozen-helper format failure. The worker must also bound its
/// input snapshot and final envelope; this parser does not claim Python limits.
pub(super) fn parse_recorded_core(
	content: &[u8],
	max_output_bytes: usize,
) -> Result<Value, CoreFailure> {
	let architecture = validate_header(content)?;
	let mut section_work = layout::MAX_SECTION_CONSTRUCTORS;
	let count = layout::program_count(content, &mut section_work)?;
	let phoff = u64_at(content, 32)?;
	let phentsize = u64::from(u16_at(content, 54)?);
	if count > 0 && phentsize < 56 {
		return Err(CoreFailure::format(
			"Program-header entry is shorter than the required ELF64 structure.",
		));
	}
	let table_size = count
		.checked_mul(phentsize)
		.ok_or_else(CoreFailure::range)?;
	checked_range(phoff, table_size, content.len() as u64)?;
	let mut tables = Tables::default();
	let mut budget = Budget::new(max_output_bytes, &report(architecture, Tables::default()))?;
	for segment_index in 0..count {
		let header_offset = add(
			phoff,
			segment_index
				.checked_mul(phentsize)
				.ok_or_else(CoreFailure::range)?,
		)?;
		let header = bytes_at(content, header_offset, 56)?;
		let type_id = u32_at(header, 0)?;
		// Preserve the reference constructor's validation order, including
		// its lazy first-match stop, before checking this segment's backing.
		if type_id == 2 {
			layout::validate_dynamic_segment(content, u64_at(header, 8)?, &mut section_work)?;
		}
		let flags = u32_at(header, 4)?;
		let offset = u64_at(header, 8)?;
		let virtual_address = u64_at(header, 16)?;
		let physical_address = u64_at(header, 24)?;
		let file_size = u64_at(header, 32)?;
		let memory_size = u64_at(header, 40)?;
		let alignment = u64_at(header, 48)?;
		let backing = type_id != 0 && file_size > 0;
		if backing {
			checked_range(offset, file_size, content.len() as u64)?;
		}
		if type_id == 1 && file_size > memory_size {
			return Err(CoreFailure::format(
				"Recorded PT_LOAD file bytes exceed memory size.",
			));
		}
		budget.push(
			&mut tables.segments,
			json!({
				"index": segment_index,
				"type": program_type(type_id, architecture),
				"type_id": type_id,
				"header_location": location(header_offset, phentsize, content.len() as u64)?,
				"offset": hex(offset),
				"file_size": hex(file_size),
				"memory_size": hex(memory_size),
				"virtual_address": hex(virtual_address),
				"physical_address": hex(physical_address),
				"alignment": hex(alignment),
				"flags": hex(u64::from(flags)),
				"file_backing": if backing { "file" } else { "none" },
			}),
		)?;
		if type_id == 4 && file_size > 0 {
			parse_notes(
				content,
				architecture,
				segment_index,
				offset,
				file_size,
				&mut tables,
				&mut budget,
			)?;
		}
	}
	let value = report(architecture, tables);
	budget.finish(&value)?;
	Ok(value)
}

fn validate_header(content: &[u8]) -> Result<Architecture, CoreFailure> {
	if content.len() < 16 || content.get(..4) != Some(b"\x7fELF".as_slice()) {
		return Err(CoreFailure::format(
			"Selected recording lacks a complete ELF identification.",
		));
	}
	if content[4..6] != [2, 1] {
		return Err(CoreFailure::new(
			"unsupported-target",
			"Initial recorded-core profile requires ELF64 little-endian.",
		));
	}
	if content.len() < 64 {
		return Err(CoreFailure::format(
			"Selected ELF64 core header is truncated.",
		));
	}
	if content[6] != 1 {
		return Err(CoreFailure::format(
			"ELF identification version is not EV_CURRENT.",
		));
	}
	if u32_at(content, 20)? != 1 {
		return Err(CoreFailure::format("ELF header version is not EV_CURRENT."));
	}
	if !matches!(content[7], 0 | 3) || content[8] != 0 {
		return Err(CoreFailure::new("unsupported-target", format!(
			"Initial recorded-core profile requires System V or GNU/Linux OSABI with ABI version zero; selected OSABI={}, ABI version={}.",
			content[7], content[8],
		)));
	}
	let machine = u16_at(content, 18)?;
	let elf_type = u16_at(content, 16)?;
	if elf_type != 4 || !matches!(machine, 62 | 183) {
		return Err(CoreFailure::new("unsupported-target", format!(
			"Initial recorded-core profile requires ET_CORE for x86-64 or AArch64; selected ET_TYPE={elf_type}, e_machine={machine}.",
		)));
	}
	Ok(if machine == 62 {
		Architecture::X86_64
	} else {
		Architecture::Aarch64
	})
}

fn parse_notes(
	content: &[u8],
	architecture: Architecture,
	segment_index: u64,
	offset: u64,
	file_size: u64,
	tables: &mut Tables,
	budget: &mut Budget,
) -> Result<(), CoreFailure> {
	let mut position = offset;
	let end = add(offset, file_size)?;
	while position < end {
		let remaining = end - position;
		if remaining < 12 {
			let raw = bytes_at(content, position, remaining)?;
			if raw.iter().any(|byte| *byte != 0) {
				return Err(CoreFailure::format(
					"Nonzero trailing note bytes lack a complete note header.",
				));
			}
			budget.push(
				&mut tables.padding,
				json!({
					"segment_index": segment_index,
					"location": location(position, remaining, end)?,
					"bytes_base64": encoded(raw, budget.remaining())?,
				}),
			)?;
			break;
		}
		let namesz = u64::from(u32_at(content, position)?);
		let descsz = u64::from(u32_at(content, add(position, 4)?)?);
		let type_id = u32_at(content, add(position, 8)?)?;
		let owner_start = add(position, 12)?;
		let descriptor_start = add(owner_start, align4(namesz)?)?;
		let note_end = add(descriptor_start, align4(descsz)?)?;
		checked_range(position, note_end - position, end)?;
		let owner = bytes_at(content, owner_start, namesz)?;
		if !owner.is_empty() && !owner.contains(&0) {
			return Err(CoreFailure::format(
				"Declared note owner has no NUL terminator.",
			));
		}
		let descriptor = bytes_at(content, descriptor_start, descsz)?;
		let note = Note {
			index: tables.notes.len(),
			segment_index,
			type_id,
			start: position,
			end: note_end,
			container_end: end,
			owner_start,
			descriptor_start,
			owner,
			descriptor,
		};
		budget.push(&mut tables.notes, note.value(budget.remaining())?)?;
		position = note_end;
		if owner == b"CORE\0" {
			interpret_note(&note, architecture, tables, budget)?;
		}
	}
	Ok(())
}

impl Note<'_> {
	fn value(&self, available: usize) -> Result<Value, CoreFailure> {
		// Bound the two encoded originals before allocating either. Overlapping
		// PT_NOTE segments are still separate records and consume the same budget.
		let owner_size = budget::encoded_size(self.owner.len())?;
		let descriptor_size = budget::encoded_size(self.descriptor.len())?;
		let raw_size = owner_size
			.checked_add(descriptor_size)
			.ok_or_else(CoreFailure::budget)?;
		let remaining = available
			.checked_sub(raw_size)
			.ok_or_else(CoreFailure::budget)?;
		let display = if self.owner.is_empty() {
			None
		} else {
			let end = self
				.owner
				.iter()
				.position(|byte| *byte == 0)
				.unwrap_or(self.owner.len());
			Some(lossy_display(&self.owner[..end], remaining)?)
		};
		Ok(json!({
			"index": self.index,
			"segment_index": self.segment_index,
			"type": if self.owner == b"CORE\0" { core_note_type(self.type_id) } else { json!(self.type_id) },
			"type_id": self.type_id,
			"location": location(self.start, self.end - self.start, self.container_end)?,
			"owner_location": location(self.owner_start, self.owner.len() as u64, self.container_end)?,
			"owner_bytes_base64": encoded(self.owner, owner_size)?,
			"owner_display": display,
			"descriptor_location": location(self.descriptor_start, self.descriptor.len() as u64, self.container_end)?,
			"descriptor_bytes_base64": encoded(self.descriptor, descriptor_size)?,
		}))
	}
}

fn interpret_note(
	note: &Note<'_>,
	architecture: Architecture,
	tables: &mut Tables,
	budget: &mut Budget,
) -> Result<(), CoreFailure> {
	match note.type_id {
		1 => {
			if note.descriptor.len() < architecture.prstatus_size() {
				return Err(CoreFailure::format(format!(
					"Linux {} NT_PRSTATUS descriptor is truncated.",
					architecture.label(),
				)));
			}
			let mut registers = Vec::new();
			for (index, name) in architecture.registers().iter().enumerate() {
				let relative = 112 + 8 * index as u64;
				registers.push(json!({
					"name": name,
					"value": hex(u64_at(note.descriptor, relative)?),
					"location": location(add(note.descriptor_start, relative)?, 8, note.container_end)?,
				}));
			}
			budget.push(
				&mut tables.threads,
				json!({
					"note_index": note.index,
					"historical_pid": i32_at(note.descriptor, 32)?,
					"recorded_current_signal": i16_at(note.descriptor, 12)?,
					"registers": registers,
				}),
			)?;
		}
		0x5349_4749 => {
			if note.descriptor.len() < layout::SIGINFO_SIZE {
				return Err(CoreFailure::format(format!(
					"Linux {} NT_SIGINFO descriptor is truncated.",
					architecture.label(),
				)));
			}
			let number = i32_at(note.descriptor, 0)?;
			let code = i32_at(note.descriptor, 8)?;
			let known = number == 11 && matches!(code, 1 | 2);
			budget.push(
				&mut tables.signals,
				json!({
					"note_index": note.index,
					"number": number,
					"code": code,
					"errno": i32_at(note.descriptor, 4)?,
					"fault_address": if known { Some(hex(u64_at(note.descriptor, 16)?)) } else { None },
					"fault_address_meaning": if known { "recorded-sigsegv-address" } else { "unknown" },
					"thread_association": "unknown",
				}),
			)?;
		}
		_ => {}
	}
	Ok(())
}

fn report(architecture: Architecture, tables: Tables) -> Value {
	json!({
		"format": "elf-core", "architecture": architecture.name(),
		"target_execution": "not-performed", "live_process_identity": "unknown",
		"segments": tables.segments, "notes": tables.notes, "note_padding": tables.padding,
		"threads": tables.threads, "signals": tables.signals,
		"note_interpretation_completeness": "unknown", "limitations": LIMITATIONS,
	})
}

fn hex(value: u64) -> String {
	format!("0x{value:x}")
}

fn add(left: u64, right: u64) -> Result<u64, CoreFailure> {
	left.checked_add(right).ok_or_else(CoreFailure::range)
}

fn align4(value: u64) -> Result<u64, CoreFailure> {
	Ok(add(value, 3)? & !3)
}

fn checked_range(offset: u64, size: u64, limit: u64) -> Result<(), CoreFailure> {
	if offset > limit || size > limit - offset {
		Err(CoreFailure::range())
	} else {
		Ok(())
	}
}

fn bytes_at(content: &[u8], offset: u64, size: u64) -> Result<&[u8], CoreFailure> {
	checked_range(offset, size, content.len() as u64)?;
	let start = usize::try_from(offset).map_err(|_| CoreFailure::range())?;
	let end = usize::try_from(add(offset, size)?).map_err(|_| CoreFailure::range())?;
	content.get(start..end).ok_or_else(CoreFailure::range)
}

fn location(offset: u64, size: u64, limit: u64) -> Result<Value, CoreFailure> {
	checked_range(offset, size, limit)?;
	Ok(json!({"offset": hex(offset), "bytes": hex(size)}))
}

fn u16_at(content: &[u8], offset: u64) -> Result<u16, CoreFailure> {
	let bytes = bytes_at(content, offset, 2)?;
	Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn i16_at(content: &[u8], offset: u64) -> Result<i16, CoreFailure> {
	let bytes = bytes_at(content, offset, 2)?;
	Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(content: &[u8], offset: u64) -> Result<u32, CoreFailure> {
	let bytes = bytes_at(content, offset, 4)?;
	Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn i32_at(content: &[u8], offset: u64) -> Result<i32, CoreFailure> {
	let bytes = bytes_at(content, offset, 4)?;
	Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(content: &[u8], offset: u64) -> Result<u64, CoreFailure> {
	let bytes = bytes_at(content, offset, 8)?;
	Ok(u64::from_le_bytes([
		bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
	]))
}

#[cfg(test)]
#[path = "rea_recorded_core_parser_tests.rs"]
mod tests;
