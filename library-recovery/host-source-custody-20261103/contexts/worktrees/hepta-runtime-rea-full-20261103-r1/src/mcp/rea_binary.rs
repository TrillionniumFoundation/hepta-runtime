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

//! Native ELF build-artifact observations inside the existing preview worker.
//! Input bytes are never executed. Declared symbols are not a discovery claim
//! about all functions; GPU identity is restricted to observed ELF declarations.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write;

#[path = "rea_binary_parser.rs"]
mod parser;
use parser::{string_at, string_table, Elf, Section};

const MAX_ROWS: usize = 256;
const MAX_REPORT_BYTES: usize = 192 * 1024;
const MAX_SYMBOL_SCAN: u64 = 262_144;
const MAX_NOTE_SCAN: u64 = 4096;
const MAX_STRING_SCAN_BYTES: u64 = 16 * 1024 * 1024;

fn hex(bytes: &[u8]) -> String {
	let mut output = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		let _ = write!(output, "{byte:02x}");
	}
	output
}

fn sha256(bytes: &[u8]) -> String {
	hex(&Sha256::digest(bytes))
}

fn name_value(bytes: &[u8]) -> Value {
	json!({"utf8":std::str::from_utf8(bytes).ok(), "bytes_hex":hex(bytes)})
}

fn coverage(total: u64, returned: usize) -> Value {
	json!({
		"scope":"declared-table-records",
		"status":if total == returned as u64 { "complete" } else { "partial" },
		"declared_records":total.to_string(),
		"returned_records":returned,
		"omitted_records":total.saturating_sub(returned as u64).to_string(),
		"reason":if total == returned as u64 { Value::Null } else { json!("bounded result retains an initial subset; omitted rows are not available in this preview") }
	})
}

fn section_rows(elf: &Elf<'_>) -> Result<Value> {
	let mut rows = Vec::new();
	for (index, section) in elf.sections.iter().take(MAX_ROWS).enumerate() {
		let name = match elf.names {
			Some(table) => name_value(string_at(table, section.name)?),
			None => Value::Null,
		};
		rows.push(json!({
			"index":index, "name":name, "name_table_offset":section.name,
			"type_id":section.kind, "flags_hex":format!("0x{:x}",section.flags),
			"address_hex":format!("0x{:x}",section.address),
			"file_offset":section.offset.to_string(), "size":section.size.to_string(),
			"file_backed":section.kind != 0 && section.kind != 8,
			"link":section.link, "info":section.info, "alignment":section.alignment.to_string(),
			"entry_size":section.entry_size.to_string(),
			"compressed":section.flags & 0x800 != 0
		}));
	}
	Ok(
		json!({"coverage":coverage(elf.sections.len() as u64,rows.len()),"rows":rows,
		"table_and_file_ranges_validated":true,"names_available":elf.names.is_some()}),
	)
}

fn program_rows(elf: &Elf<'_>) -> Value {
	let rows: Vec<_> = elf.programs.iter().take(MAX_ROWS).enumerate().map(|(index, program)| json!({
		"index":index, "type_id":program.kind, "flags_hex":format!("0x{:x}",program.flags),
		"file_offset":program.offset.to_string(), "virtual_address_hex":format!("0x{:x}",program.virtual_address),
		"physical_address_hex":format!("0x{:x}",program.physical_address),
		"file_size":program.file_size.to_string(), "memory_size":program.memory_size.to_string(),
		"alignment":program.alignment.to_string()
	})).collect();
	json!({"coverage":coverage(elf.programs.len() as u64,rows.len()),"rows":rows,
		"table_and_file_ranges_validated":true,"load_range_constraints_validated":true})
}

fn symbol_index_table(selected: Option<&Section>, count: u64) -> Result<Option<&Section>> {
	if let Some(section) = selected {
		if section.flags & 0x800 != 0
			|| section.entry_size != 4
			|| section.size
				!= count
					.checked_mul(4)
					.ok_or_else(|| anyhow!("ELF extended symbol-index size overflow"))?
		{
			bail!("ELF extended symbol-index table has an unsupported shape");
		}
	}
	Ok(selected)
}

fn symbols(elf: &Elf<'_>) -> Result<Value> {
	let stride = if elf.reader.bits == 64 { 24 } else { 16 };
	let mut declared = 0u64;
	let mut inspected = 0u64;
	let mut string_bytes = 0u64;
	let mut rows = Vec::new();
	let mut tables = Vec::new();
	let mut table_count = 0u64;
	let mut skipped_compressed = 0u64;
	let mut undefined = 0u64;
	let mut defined = 0u64;
	let mut index_tables = BTreeMap::new();
	for section in elf.sections.iter().filter(|section| section.kind == 18) {
		let linked = elf
			.sections
			.get(usize::try_from(section.link)?)
			.ok_or_else(|| anyhow!("ELF extended-index table link is out of range"))?;
		if !matches!(linked.kind, 2 | 11) {
			bail!("ELF extended-index table must link to a symbol table");
		}
		if index_tables
			.insert(section.link as usize, section)
			.is_some()
		{
			bail!("ELF symbol table has duplicate extended-index tables");
		}
	}
	for (table_index, table) in elf
		.sections
		.iter()
		.enumerate()
		.filter(|(_, section)| section.kind == 2 || section.kind == 11)
	{
		table_count += 1;
		if table.flags & 0x800 != 0 {
			skipped_compressed += 1;
			continue;
		}
		if table.entry_size != stride || table.size % stride != 0 {
			bail!("ELF symbol table entry size is invalid/unsupported");
		}
		let count = table.size / stride;
		if u64::from(table.info) > count {
			bail!("ELF symbol table local-symbol boundary exceeds table");
		}
		declared = declared
			.checked_add(count)
			.ok_or_else(|| anyhow!("ELF symbol count overflow"))?;
		let names = elf
			.sections
			.get(usize::try_from(table.link)?)
			.ok_or_else(|| anyhow!("ELF symbol string-table link is out of range"))?;
		let names = string_table(&elf.reader, names)?;
		let indexes = symbol_index_table(index_tables.get(&table_index).copied(), count)?;
		let before = inspected;
		for index in 0..count {
			if inspected >= MAX_SYMBOL_SCAN || string_bytes >= MAX_STRING_SCAN_BYTES {
				break;
			}
			let at = table.offset + index * stride;
			let name_offset = elf.reader.u32(at)?;
			let (info, other, section_index, value, size) = if elf.reader.bits == 64 {
				let flags = elf.reader.bytes(at + 4, 2)?;
				(
					flags[0],
					flags[1],
					elf.reader.u16(at + 6)?,
					elf.reader.u64(at + 8)?,
					elf.reader.u64(at + 16)?,
				)
			} else {
				let flags = elf.reader.bytes(at + 12, 2)?;
				(
					flags[0],
					flags[1],
					elf.reader.u16(at + 14)?,
					u64::from(elf.reader.u32(at + 4)?),
					u64::from(elf.reader.u32(at + 8)?),
				)
			};
			let resolved_index = if section_index == 0xffff {
				let extension = indexes
					.ok_or_else(|| anyhow!("ELF symbol uses SHN_XINDEX without an index table"))?;
				let resolved = elf.reader.u32(extension.offset + index * 4)?;
				if resolved as usize >= elf.sections.len() {
					bail!("ELF extended symbol section index is out of range");
				}
				u64::from(resolved)
			} else {
				if section_index != 0
					&& section_index < 0xff00
					&& usize::from(section_index) >= elf.sections.len()
				{
					bail!("ELF symbol section index is out of range");
				}
				u64::from(section_index)
			};
			let name = string_at(names, name_offset)?;
			string_bytes += name.len() as u64 + 1;
			if resolved_index == 0 {
				undefined += 1;
			} else {
				defined += 1;
			}
			inspected += 1;
			if rows.len() < MAX_ROWS {
				rows.push(json!({
					"table_section_index":table_index,"symbol_index":index.to_string(),
					"name":name_value(name),"name_table_offset":name_offset,
					"binding_id":info >> 4,"type_id":info & 15,"other_raw":other,"visibility_id":other & 7,
					"section_index_raw":section_index,"section_index":resolved_index.to_string(),
					"undefined":resolved_index == 0,"value_hex":format!("0x{value:x}"),"size":size.to_string()
				}));
			}
		}
		if tables.len() < MAX_ROWS {
			tables.push(
				json!({"section_index":table_index,"type_id":table.kind,"string_table_section_index":table.link,
				"declared_symbols":count.to_string(),"inspected_symbols":(inspected-before).to_string()}),
			);
		}
	}
	let validation_complete = inspected == declared && skipped_compressed == 0;
	let mut retained_coverage = coverage(declared, rows.len());
	if skipped_compressed > 0 {
		retained_coverage["status"] = json!("partial");
		retained_coverage["reason"] =
			json!("compressed symbol tables are not decoded; their symbol counts remain unknown");
	}
	Ok(json!({
		"coverage":retained_coverage,"rows":rows,"tables":tables,
		"table_summary_coverage":coverage(table_count-skipped_compressed,tables.len()),"declared_symbol_tables":table_count,
		"uncompressed_declared_symbols":declared.to_string(),"inspected_symbols":inspected.to_string(),
		"skipped_compressed_tables":skipped_compressed,
		"entry_reference_validation":if validation_complete { "complete" } else { "partial" },
		"observed_undefined_symbols":undefined.to_string(),"observed_defined_symbols":defined.to_string(),
		"discovery_scope":"section-declared SYMTAB and DYNSYM only; dynamic-loader tables and stripped functions are not reconstructed",
		"limits":{"returned_rows":MAX_ROWS,"scanned_symbols":MAX_SYMBOL_SCAN,"scanned_name_bytes":MAX_STRING_SCAN_BYTES}
	}))
}

fn align(value: u64, alignment: u64) -> Result<u64> {
	value
		.checked_add(alignment - 1)
		.map(|value| value & !(alignment - 1))
		.ok_or_else(|| anyhow!("ELF note alignment overflow"))
}

fn notes(elf: &Elf<'_>) -> Result<Value> {
	let mut rows = Vec::new();
	let mut observed = 0u64;
	let mut opaque = 0u64;
	let mut stopped = false;
	let mut build_ids = Vec::new();
	let mut build_ids_observed = 0u64;
	for (section_index, section) in elf
		.sections
		.iter()
		.enumerate()
		.filter(|(_, section)| section.kind == 7)
	{
		if section.flags & 0x800 != 0 || !matches!(section.alignment, 4 | 8) {
			opaque += 1;
			continue;
		}
		let end = section.offset + section.size;
		let mut cursor = section.offset;
		while cursor < end {
			if observed >= MAX_NOTE_SCAN {
				stopped = true;
				break;
			}
			if end - cursor < 12 {
				bail!("ELF note has a truncated header");
			}
			let name_size = u64::from(elf.reader.u32(cursor)?);
			let descriptor_size = u64::from(elf.reader.u32(cursor + 4)?);
			let kind = elf.reader.u32(cursor + 8)?;
			if name_size > parser::MAX_STRING_BYTES as u64 {
				bail!("ELF note owner exceeds bounded inspection capacity");
			}
			let name_at = cursor + 12;
			let name_end = name_at
				.checked_add(name_size)
				.ok_or_else(|| anyhow!("ELF note owner range overflow"))?;
			let descriptor_at =
				section.offset + align(name_end - section.offset, section.alignment)?;
			let descriptor_end = descriptor_at
				.checked_add(descriptor_size)
				.ok_or_else(|| anyhow!("ELF note descriptor range overflow"))?;
			let next = section
				.offset
				.checked_add(align(descriptor_end - section.offset, section.alignment)?)
				.ok_or_else(|| anyhow!("ELF note next-offset overflow"))?;
			if name_end > end || descriptor_end > end || next > end {
				bail!("ELF note fields exceed the section");
			}
			let owner = elf.reader.bytes(name_at, name_size)?;
			let descriptor = elf.reader.bytes(descriptor_at, descriptor_size)?;
			let build_id = owner == b"GNU\0" && kind == 3;
			if build_id {
				build_ids_observed += 1;
			}
			if build_id && descriptor.len() <= 128 && build_ids.len() < MAX_ROWS {
				build_ids.push(json!({"section_index":section_index,"note_file_offset":cursor.to_string(),"bytes_hex":hex(descriptor)}));
			}
			if rows.len() < MAX_ROWS {
				rows.push(
					json!({"section_index":section_index,"file_offset":cursor.to_string(),
					"type_id":kind,"owner":name_value(owner),"descriptor_offset":descriptor_at.to_string(),
					"descriptor_bytes":descriptor_size.to_string(),"descriptor_sha256":sha256(descriptor),
					"gnu_build_id":build_id,
					"amdgpu_owner":owner == b"AMDGPU\0" || owner == b"AMD\0",
					"descriptor_interpreted":build_id && descriptor.len() <= 128}),
				);
			}
			observed += 1;
			cursor = next;
		}
	}
	Ok(json!({
		"scope":"SHT_NOTE records with uncompressed 4/8-byte alignment",
		"coverage":{"status":if opaque == 0 && !stopped && observed == rows.len() as u64 {"complete"}else{"partial"},
			"observed_records":observed.to_string(),"returned_records":rows.len(),"opaque_sections":opaque,
			"scan_limit_reached":stopped},
		"rows":rows,"gnu_build_ids":build_ids,"build_id_coverage":coverage(build_ids_observed,build_ids.len()),
		"limitations":["PT_NOTE-only records and compressed/other-alignment note sections are not decoded",
			"build IDs are observed bytes, not signatures or authenticity proofs",
			"AMDGPU note payloads are hashed but not decoded as MessagePack or interpreted as kernel metadata"]
	}))
}

// Parent preview and path metadata must still fit the existing 256 KiB worker
// limit. Reduce only result delivery, never convert omitted rows into absence.
fn budget_report(mut report: Value) -> Result<Value> {
	report["delivery"] = json!({"maximum_report_bytes":MAX_REPORT_BYTES,"limited":false});
	while serde_json::to_vec(&report)?.len() > MAX_REPORT_BYTES {
		let mut changed = false;
		for (rows_path, coverage_path) in [
			("/sections/rows", "/sections/coverage"),
			("/program_headers/rows", "/program_headers/coverage"),
			("/symbols/rows", "/symbols/coverage"),
			("/symbols/tables", "/symbols/table_summary_coverage"),
			("/notes/rows", "/notes/coverage"),
			("/notes/gnu_build_ids", "/notes/build_id_coverage"),
		] {
			let rows = report
				.pointer_mut(rows_path)
				.and_then(Value::as_array_mut)
				.ok_or_else(|| anyhow!("ELF report lost its bounded collection"))?;
			let before = rows.len();
			let returned = before / 2;
			rows.truncate(returned);
			let removed = before - returned;
			if removed == 0 {
				continue;
			}
			changed = true;
			let coverage = report
				.pointer_mut(coverage_path)
				.ok_or_else(|| anyhow!("ELF report lost coverage"))?;
			coverage["status"] = json!("partial");
			coverage["returned_records"] = json!(returned);
			coverage["delivery_limited"] = json!(true);
			if let Some(previous) = coverage.get("omitted_records") {
				let previous = previous
					.as_str()
					.ok_or_else(|| anyhow!("ELF report count is not a string"))?
					.parse::<u64>()?;
				coverage["omitted_records"] = json!((previous + removed as u64).to_string());
			}
			coverage["delivery_reason"]=json!("192 KiB ELF report budget retains an initial subset; omitted rows are not available in this preview");
		}
		if !changed {
			bail!("ELF structural summary exceeds report capacity");
		}
		report["delivery"]["limited"] = json!(true);
	}
	Ok(report)
}

/// Read structural ELF facts from the same bounded snapshot as the parent preview.
/// The returned report is deterministic; the parent owns identity, persistence,
/// isolation and the final transport budget.
pub(crate) fn inspect_elf_bytes(data: &[u8]) -> Result<Value> {
	let elf = parser::parse(data)?;
	let sections = section_rows(&elf)?;
	let programs = program_rows(&elf);
	let symbols = symbols(&elf)?;
	let notes = notes(&elf)?;
	let gpu = if elf.machine == 224 || elf.machine == 190 {
		json!({"machine_id":elf.machine,"architecture_family":if elf.machine==224{"amdgpu"}else{"cuda"},
			"elf_os_abi":elf.os_abi,"elf_abi_version":elf.abi_version,"elf_flags_hex":format!("0x{:x}",elf.flags),
			"target_architecture":null,"kernel_inventory":null,"coverage":"declarations-only",
			"limitations":["architecture family comes from the ELF machine ID; no GPU instructions, gfx/sm target, kernel metadata or execution compatibility are established"]})
	} else {
		Value::Null
	};
	budget_report(json!({
		"record_format":"hepta.rea.elf-structure.v1",
		"format":"elf","word_size_bits":elf.reader.bits,
		"byte_order":if elf.reader.little{"little"}else{"big"},
		"elf_type":elf.kind,"machine_id":elf.machine,"os_abi":elf.os_abi,"abi_version":elf.abi_version,
		"flags_hex":format!("0x{:x}",elf.flags),"entry_point_hex":format!("0x{:x}",elf.entry),
		"extended_numbering":{"section_count":elf.extended_sections,"program_count":elf.extended_programs,"section_name_index":elf.extended_names},
		"sections":sections,"program_headers":programs,"symbols":symbols,"notes":notes,"gpu":gpu,
		"coverage":{"scope":"declared-elf-structure","status":"partial"},
		"limitations":["Only declared ELF structures are inspected; this is not a complete ELF verifier or code analysis",
			"No instructions, relocations, symbol versions, dependencies or runtime/loadability conclusions are decoded",
			"Opaque and omitted records remain unobserved; all 64-bit offsets, lengths and addresses are encoded without rounding",
			"Notes are section-scoped; sections absent from stripped or unconventional objects are not reconstructed"]
	}))
}

#[cfg(test)]
#[path = "rea_binary_tests.rs"]
mod rea_binary_tests;
