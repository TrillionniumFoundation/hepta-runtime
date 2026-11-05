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

//! Byte-level core fixtures exercise recorded provenance and refusal boundaries.

use super::*;

const OUTPUT_LIMIT: usize = 1024 * 1024;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
	bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
	bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
	bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn header(machine: u16) -> Vec<u8> {
	let mut bytes = vec![0; 64];
	bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
	put16(&mut bytes, 16, 4);
	put16(&mut bytes, 18, machine);
	put32(&mut bytes, 20, 1);
	put16(&mut bytes, 52, 64);
	put16(&mut bytes, 54, 56);
	put16(&mut bytes, 58, 64);
	bytes
}

fn note(owner: &[u8], kind: u32, descriptor: &[u8]) -> Vec<u8> {
	let owner_bytes = owner.len().div_ceil(4) * 4;
	let descriptor_bytes = descriptor.len().div_ceil(4) * 4;
	let mut bytes = vec![0; 12 + owner_bytes + descriptor_bytes];
	put32(&mut bytes, 0, u32::try_from(owner.len()).unwrap());
	put32(&mut bytes, 4, u32::try_from(descriptor.len()).unwrap());
	put32(&mut bytes, 8, kind);
	bytes[12..12 + owner.len()].copy_from_slice(owner);
	bytes[12 + owner_bytes..12 + owner_bytes + descriptor.len()].copy_from_slice(descriptor);
	bytes
}

fn core(machine: u16, notes: &[u8]) -> Vec<u8> {
	let mut bytes = header(machine);
	put64(&mut bytes, 32, 64);
	put16(&mut bytes, 56, 1);
	bytes.resize(120, 0);
	put32(&mut bytes, 64, 4);
	put64(&mut bytes, 72, 120);
	put64(&mut bytes, 96, notes.len() as u64);
	bytes.extend_from_slice(notes);
	bytes
}

fn parsed(bytes: &[u8]) -> Value {
	parse_recorded_core(bytes, OUTPUT_LIMIT).unwrap()
}

fn failure(bytes: &[u8], reason: &str, message: &str) {
	let error = parse_recorded_core(bytes, OUTPUT_LIMIT).unwrap_err();
	assert_eq!(error.reason, reason);
	assert_eq!(error.message, message);
}

#[test]
fn recorded_core_empty_metadata_preserves_unknowns_and_frozen_limitations() {
	for (machine, architecture) in [(62, "x86_64-little-endian"), (183, "aarch64-little-endian")] {
		let value = parsed(&header(machine));
		assert_eq!(value["architecture"], architecture);
		assert_eq!(value["target_execution"], "not-performed");
		assert_eq!(value["live_process_identity"], "unknown");
		assert_eq!(value["note_interpretation_completeness"], "unknown");
		for key in ["segments", "notes", "note_padding", "threads", "signals"] {
			assert_eq!(value[key], json!([]));
		}
		assert_eq!(value["limitations"], json!(LIMITATIONS));
	}
}

#[test]
fn recorded_core_admission_matches_frozen_order_and_messages() {
	failure(
		b"\x7fELF",
		"format",
		"Selected recording lacks a complete ELF identification.",
	);
	let mut bytes = header(62);
	bytes[4] = 1;
	failure(
		&bytes[..16],
		"unsupported-target",
		"Initial recorded-core profile requires ELF64 little-endian.",
	);
	bytes[4] = 2;
	failure(
		&bytes[..63],
		"format",
		"Selected ELF64 core header is truncated.",
	);
	bytes[6] = 0;
	failure(
		&bytes,
		"format",
		"ELF identification version is not EV_CURRENT.",
	);
	bytes[6] = 1;
	put32(&mut bytes, 20, 2);
	failure(&bytes, "format", "ELF header version is not EV_CURRENT.");
	put32(&mut bytes, 20, 1);
	bytes[7] = 9;
	failure(&bytes, "unsupported-target", "Initial recorded-core profile requires System V or GNU/Linux OSABI with ABI version zero; selected OSABI=9, ABI version=0.");
	bytes[7] = 3;
	assert!(parse_recorded_core(&bytes, OUTPUT_LIMIT).is_ok());
	bytes[8] = 1;
	failure(&bytes, "unsupported-target", "Initial recorded-core profile requires System V or GNU/Linux OSABI with ABI version zero; selected OSABI=3, ABI version=1.");
	bytes[8] = 0;
	put16(&mut bytes, 16, 2);
	put16(&mut bytes, 18, 3);
	failure(&bytes, "unsupported-target", "Initial recorded-core profile requires ET_CORE for x86-64 or AArch64; selected ET_TYPE=2, e_machine=3.");
}

#[test]
fn recorded_core_program_headers_preserve_null_and_memory_only_ranges() {
	let mut bytes = core(62, &[]);
	put32(&mut bytes, 64, 0);
	put32(&mut bytes, 68, u32::MAX);
	put64(&mut bytes, 72, u64::MAX);
	put64(&mut bytes, 80, 0x1234_5678);
	put64(&mut bytes, 88, 0xabcd);
	put64(&mut bytes, 96, u64::MAX);
	put64(&mut bytes, 112, 0x1000);
	let value = parsed(&bytes);
	assert_eq!(
		value["segments"][0],
		json!({
			"index": 0, "type": "PT_NULL", "type_id": 0,
			"header_location": {"offset": "0x40", "bytes": "0x38"},
			"offset": "0xffffffffffffffff", "file_size": "0xffffffffffffffff", "memory_size": "0x0",
			"virtual_address": "0x12345678", "physical_address": "0xabcd", "alignment": "0x1000",
			"flags": "0xffffffff", "file_backing": "none",
		})
	);
	put32(&mut bytes, 64, 1);
	put64(&mut bytes, 96, 0);
	put64(&mut bytes, 104, 0x4000);
	let memory = parsed(&bytes);
	assert_eq!(memory["segments"][0]["file_backing"], "none");
	assert_eq!(memory["segments"][0]["offset"], "0xffffffffffffffff");
	put32(&mut bytes, 64, 0x6000_0042);
	assert_eq!(parsed(&bytes)["segments"][0]["type"], 0x6000_0042_u32);
}

#[test]
fn recorded_core_program_header_and_backing_boundaries_never_wrap() {
	let mut bytes = core(62, &[]);
	put16(&mut bytes, 54, 55);
	failure(
		&bytes,
		"format",
		"Program-header entry is shorter than the required ELF64 structure.",
	);
	put16(&mut bytes, 54, 56);
	put64(&mut bytes, 32, u64::MAX - 4);
	failure(&bytes, "format", RANGE_MESSAGE);
	put64(&mut bytes, 32, 64);
	put64(&mut bytes, 72, u64::MAX);
	put64(&mut bytes, 96, 1);
	failure(&bytes, "format", RANGE_MESSAGE);
	put64(&mut bytes, 72, 119);
	put32(&mut bytes, 64, 1);
	failure(
		&bytes,
		"format",
		"Recorded PT_LOAD file bytes exceed memory size.",
	);
	put64(&mut bytes, 104, 1);
	assert_eq!(parsed(&bytes)["segments"][0]["file_backing"], "file");
}

#[test]
fn recorded_core_notes_require_exact_owner_and_preserve_all_original_bytes() {
	let owners: [&[u8]; 5] = [b"CORE\0junk", b"CORE\0\0", b"\xff\xc0\0tail", b"\0", b""];
	let mut recording = Vec::new();
	for owner in owners {
		recording.extend(note(owner, 1, b"\0\xff\x80"));
	}
	let value = parsed(&core(62, &recording));
	assert_eq!(value["notes"].as_array().unwrap().len(), 5);
	assert_eq!(value["threads"], json!([]));
	for row in value["notes"].as_array().unwrap() {
		assert_eq!(row["type"], 1);
		assert_eq!(row["descriptor_bytes_base64"], "AP+A");
	}
	assert_eq!(value["notes"][0]["owner_bytes_base64"], "Q09SRQBqdW5r");
	assert_eq!(value["notes"][0]["owner_display"], "CORE");
	assert_eq!(value["notes"][2]["owner_display"], "\u{fffd}\u{fffd}");
	assert_eq!(value["notes"][3]["owner_display"], "");
	assert_eq!(value["notes"][4]["owner_display"], Value::Null);
}

#[test]
fn recorded_core_note_padding_and_malformed_ranges_remain_distinct() {
	let value = parsed(&core(62, &[0, 0, 0]));
	assert_eq!(
		value["note_padding"],
		json!([{
			"segment_index":0, "location":{"offset":"0x78", "bytes":"0x3"}, "bytes_base64":"AAAA",
		}])
	);
	failure(
		&core(62, &[0, 1, 0]),
		"format",
		"Nonzero trailing note bytes lack a complete note header.",
	);
	failure(
		&core(62, &note(b"CORE", 1, &[])),
		"format",
		"Declared note owner has no NUL terminator.",
	);
	let mut raw = note(b"CORE\0", 1, &[]);
	put32(&mut raw, 0, u32::MAX);
	put32(&mut raw, 4, u32::MAX);
	failure(&core(62, &raw), "format", RANGE_MESSAGE);
	// A zero-sized owner/descriptor still consumes a full 12-byte note header.
	let value = parsed(&core(62, &[0; 24]));
	assert_eq!(value["notes"].as_array().unwrap().len(), 2);
	assert_eq!(value["note_padding"], json!([]));
}

#[test]
fn recorded_core_amd64_registers_keep_unsigned_values_and_absolute_provenance() {
	let mut descriptor = vec![0; 336];
	put16(&mut descriptor, 12, 65535);
	put32(&mut descriptor, 32, 0xffff_fffe);
	for index in 0..27 {
		put64(&mut descriptor, 112 + index * 8, u64::MAX - index as u64);
	}
	let value = parsed(&core(62, &note(b"CORE\0", 1, &descriptor)));
	assert_eq!(value["notes"][0]["type"], "NT_PRSTATUS");
	assert_eq!(value["threads"][0]["historical_pid"], -2);
	assert_eq!(value["threads"][0]["recorded_current_signal"], -1);
	let registers = value["threads"][0]["registers"].as_array().unwrap();
	assert_eq!(registers.len(), 27);
	assert_eq!(
		registers[0],
		json!({"name":"r15", "value":"0xffffffffffffffff", "location":{"offset":"0xfc", "bytes":"0x8"}})
	);
	assert_eq!(registers[16]["name"], "rip");
	assert_eq!(registers[26]["name"], "gs");
	assert_eq!(value["signals"], json!([]));
	failure(
		&core(62, &note(b"CORE\0", 1, &descriptor[..335])),
		"format",
		"Linux x86-64 NT_PRSTATUS descriptor is truncated.",
	);
}

#[test]
fn recorded_core_aarch64_all_threads_are_retained_without_thread_selection() {
	let mut descriptor = vec![0; 392];
	put32(&mut descriptor, 32, 123);
	put64(&mut descriptor, 112 + 31 * 8, 0xfedc_ba98_7654_3210);
	put64(&mut descriptor, 112 + 32 * 8, 0x400080);
	let first = note(b"CORE\0", 1, &descriptor);
	put32(&mut descriptor, 32, 456);
	let mut notes = first;
	notes.extend(note(b"CORE\0", 1, &descriptor));
	let value = parsed(&core(183, &notes));
	assert_eq!(value["threads"].as_array().unwrap().len(), 2);
	assert_eq!(value["threads"][0]["historical_pid"], 123);
	assert_eq!(value["threads"][1]["historical_pid"], 456);
	let registers = value["threads"][0]["registers"].as_array().unwrap();
	assert_eq!(registers.len(), 34);
	assert_eq!(registers[0]["name"], "x0");
	assert_eq!(registers[30]["name"], "x30");
	assert_eq!(registers[31]["name"], "sp");
	assert_eq!(registers[31]["value"], "0xfedcba9876543210");
	assert_eq!(registers[32]["name"], "pc");
	assert_eq!(registers[33]["name"], "pstate");
	failure(
		&core(183, &note(b"CORE\0", 1, &descriptor[..391])),
		"format",
		"Linux AArch64 NT_PRSTATUS descriptor is truncated.",
	);
}

#[test]
fn recorded_core_output_budget_is_exact_and_does_not_return_partial_success() {
	let bytes = core(62, &note(b"unknown\0", 0xffff_ffff, &[0x80; 4096]));
	let value = parsed(&bytes);
	let exact_size = serde_json::to_vec(&value).unwrap().len();
	assert_eq!(parse_recorded_core(&bytes, exact_size).unwrap(), value);
	let refused = parse_recorded_core(&bytes, exact_size - 1).unwrap_err();
	assert_eq!(refused.reason, "budget");
	assert_eq!(parse_recorded_core(&bytes, 0).unwrap_err().reason, "budget");
	assert_eq!(
		budget::encoded_size(usize::MAX).unwrap_err().reason,
		"budget"
	);
}

#[test]
fn recorded_core_repeated_note_segments_are_counted_and_not_deduplicated() {
	let raw = note(b"\0", 0xf000_0001, b"xyz");
	let mut bytes = header(62);
	put64(&mut bytes, 32, 64);
	put16(&mut bytes, 56, 2);
	bytes.resize(176, 0);
	for offset in [64, 120] {
		put32(&mut bytes, offset, 4);
		put64(&mut bytes, offset + 8, 176);
		put64(&mut bytes, offset + 32, raw.len() as u64);
	}
	bytes.extend(raw);
	let value = parsed(&bytes);
	assert_eq!(value["notes"].as_array().unwrap().len(), 2);
	assert_eq!(value["notes"][0]["segment_index"], 0);
	assert_eq!(value["notes"][1]["segment_index"], 1);
	assert_eq!(value["notes"][0]["location"], value["notes"][1]["location"]);
	let exact = serde_json::to_vec(&value).unwrap().len();
	assert_eq!(
		parse_recorded_core(&bytes, exact - 1).unwrap_err().reason,
		"budget"
	);
}

#[test]
fn recorded_core_base64_and_invalid_utf8_are_bounded_without_byte_changes() {
	for (raw, expected) in [
		(b"".as_slice(), ""),
		(b"f", "Zg=="),
		(b"fo", "Zm8="),
		(b"foo", "Zm9v"),
		(b"foob", "Zm9vYg=="),
	] {
		assert_eq!(budget::encoded(raw, expected.len()).unwrap(), expected);
		if !raw.is_empty() {
			assert_eq!(
				budget::encoded(raw, expected.len() - 1).unwrap_err().reason,
				"budget"
			);
		}
	}
	assert_eq!(
		budget::lossy_display(b"a\xed\xa0\x80b\xe2\x82", 100).unwrap(),
		"a\u{fffd}\u{fffd}\u{fffd}b\u{fffd}"
	);
	assert_eq!(
		budget::lossy_display(b"\xff", 2).unwrap_err().reason,
		"budget"
	);
}

#[test]
fn recorded_core_siginfo_uses_the_frozen_32_byte_prefix_and_unknown_union_rules() {
	for machine in [62, 183] {
		let mut descriptor = vec![0; 32];
		put32(&mut descriptor, 0, 11);
		put32(&mut descriptor, 4, 0xffff_fffb);
		put32(&mut descriptor, 8, 2);
		put64(&mut descriptor, 16, 0xffff_ffff_ffff_0010);
		let mut notes = note(b"CORE\0", 0x5349_4749, &descriptor);
		put32(&mut descriptor, 8, 0xffff_ffff);
		notes.extend(note(b"CORE\0", 0x5349_4749, &descriptor));
		put32(&mut descriptor, 0, 7);
		put32(&mut descriptor, 8, 1);
		notes.extend(note(b"CORE\0", 0x5349_4749, &descriptor));
		let value = parsed(&core(machine, &notes));
		assert_eq!(
			value["signals"][0],
			json!({
				"note_index":0, "number":11, "code":2, "errno":-5,
				"fault_address":"0xffffffffffff0010",
				"fault_address_meaning":"recorded-sigsegv-address", "thread_association":"unknown",
			})
		);
		for index in [1, 2] {
			assert_eq!(value["signals"][index]["fault_address"], Value::Null);
			assert_eq!(value["signals"][index]["fault_address_meaning"], "unknown");
			assert_eq!(value["signals"][index]["thread_association"], "unknown");
		}
		assert_eq!(value["signals"][1]["code"], -1);
		let label = if machine == 62 { "x86-64" } else { "AArch64" };
		failure(
			&core(machine, &note(b"CORE\0", 0x5349_4749, &descriptor[..31])),
			"format",
			&format!("Linux {label} NT_SIGINFO descriptor is truncated."),
		);
		// The complete original, including extensions beyond the decoded prefix,
		// remains in the opaque descriptor record.
		descriptor.extend([0xaa; 5]);
		let extended = parsed(&core(machine, &note(b"CORE\0", 0x5349_4749, &descriptor)));
		assert_eq!(extended["notes"][0]["descriptor_location"]["bytes"], "0x25");
		assert_eq!(
			extended["notes"][0]["descriptor_bytes_base64"],
			budget::encoded(&descriptor, OUTPUT_LIMIT).unwrap()
		);
	}
}

#[test]
fn recorded_core_labels_follow_reference_owner_and_architecture_context() {
	let mut notes = Vec::new();
	for kind in [2, 3, 4, 6, 0x4649_4c45, 0x202, 0x7000_0001] {
		notes.extend(note(b"CORE\0", kind, &[1, 2, 3]));
	}
	let value = parsed(&core(62, &notes));
	for (index, name) in [
		"NT_FPREGSET",
		"NT_PRPSINFO",
		"NT_TASKSTRUCT",
		"NT_AUXV",
		"NT_FILE",
	]
	.iter()
	.enumerate()
	{
		assert_eq!(value["notes"][index]["type"], *name);
	}
	assert_eq!(value["notes"][5]["type"], 0x202);
	for (machine, expected) in [(62, json!(0x7000_0001)), (183, json!("PT_AARCH64_UNWIND"))] {
		let mut bytes = core(machine, &[]);
		put32(&mut bytes, 64, 0x7000_0001);
		assert_eq!(parsed(&bytes)["segments"][0]["type"], expected);
	}
}

#[test]
fn recorded_core_extended_count_observes_section_and_string_table_validation() {
	let mut bytes = header(62);
	put64(&mut bytes, 40, 64);
	put16(&mut bytes, 56, 0xffff);
	bytes.resize(128, 0);
	assert_eq!(parsed(&bytes)["segments"], json!([]));
	put64(&mut bytes, 32, 128);
	put32(&mut bytes, 108, 1);
	bytes.resize(184, 0);
	assert_eq!(parsed(&bytes)["segments"].as_array().unwrap().len(), 1);
	// Ordinary program counts deliberately do not inspect unused section data.
	put16(&mut bytes, 56, 0);
	put64(&mut bytes, 40, u64::MAX);
	assert_eq!(parsed(&bytes)["segments"], json!([]));
	put16(&mut bytes, 56, 0xffff);
	failure(&bytes, "format", "Recorded core failed unchanged upstream structural parsing: Reading section 0 at offset 18446744073709551615 past EOF 184");
	put64(&mut bytes, 40, 64);
	put16(&mut bytes, 58, 63);
	failure(
		&bytes,
		"format",
		"Recorded core failed unchanged upstream structural parsing: Too small e_shentsize: 63",
	);
	put16(&mut bytes, 58, 64);
	put16(&mut bytes, 62, 2);
	failure(
		&bytes,
		"format",
		"Recorded core failed unchanged upstream structural parsing: String Table not found",
	);
	put16(&mut bytes, 62, 0);
	failure(
		&bytes[..127],
		"format",
		"Recorded core failed unchanged upstream structural parsing: expected 8, found 7",
	);
	put32(&mut bytes, 68, 2);
	failure(
		&bytes,
		"format",
		"Recorded core failed unchanged upstream structural parsing: SHT_SYMTAB section points at section 0 of type SHT_SYMTAB, expected SHT_STRTAB",
	);
}

#[test]
fn recorded_core_extended_count_keeps_compression_constructor_and_seek_errors() {
	let mut bytes = header(62);
	put64(&mut bytes, 40, 64);
	put16(&mut bytes, 56, 0xffff);
	bytes.resize(128, 0);
	put64(&mut bytes, 72, 0x800);
	put64(&mut bytes, 88, 128);
	failure(
		&bytes,
		"format",
		"Recorded core failed unchanged upstream structural parsing: expected 4, found 0",
	);
	bytes.resize(152, 0);
	assert!(parse_recorded_core(&bytes, OUTPUT_LIMIT).is_ok());
	put64(&mut bytes, 88, u64::MAX);
	failure(
		&bytes,
		"decoder",
		"OverflowError: Python int too large to convert to C ssize_t",
	);
}

#[test]
fn recorded_core_dynamic_sections_preserve_structural_failure_order() {
	let mut bytes = core(62, &[]);
	put32(&mut bytes, 64, 2);
	put16(&mut bytes, 60, 1);
	// A zero section-table offset means no sections in the pinned ELFFile,
	// even if the independent e_shnum field is nonzero.
	assert_eq!(parsed(&bytes)["segments"][0]["type"], "PT_DYNAMIC");
	put64(&mut bytes, 40, 64);
	failure(
		&bytes,
		"format",
		"Recorded core failed unchanged upstream structural parsing: expected 8, found 0",
	);
	put64(&mut bytes, 40, u64::MAX);
	// An invalid backing range still comes after section construction.
	put64(&mut bytes, 72, u64::MAX);
	put64(&mut bytes, 96, 1);
	failure(
		&bytes,
		"format",
		"Recorded core failed unchanged upstream structural parsing: Reading section 0 at offset 18446744073709551615 past EOF 120",
	);
}

fn extended_special_core(machine: u16, section_type: u32) -> Vec<u8> {
	let mut bytes = header(machine);
	put64(&mut bytes, 40, 64);
	put16(&mut bytes, 56, 0xffff);
	put16(&mut bytes, 60, 3);
	put16(&mut bytes, 62, 1);
	bytes.resize(256, 0);
	put32(&mut bytes, 68, section_type);
	put32(&mut bytes, 104, 2);
	put32(&mut bytes, 132, 3);
	bytes
}

#[test]
fn recorded_core_extended_special_prefix_reports_exact_entry_size_errors() {
	for (section_type, expected, text) in [
		(4, 24, "Expected sh_entsize of SHT_RELA section to be 24"),
		(9, 16, "Expected sh_entsize of SHT_REL section to be 16"),
		(19, 8, "Expected RELR entry size to be 8, got 0"),
	] {
		let mut bytes = extended_special_core(62, section_type);
		failure(
			&bytes,
			"format",
			&format!("Recorded core failed unchanged upstream structural parsing: {text}"),
		);
		// These constructors perform no relocation payload reads.
		put64(&mut bytes, 120, expected);
		assert_eq!(parsed(&bytes)["segments"], json!([]));
	}
}

#[test]
fn recorded_core_extended_special_wrong_links_keep_reference_labels() {
	for section_type in [2, 11, 0x6fff_fff3, 0x6fff_fffd, 0x6fff_fffe] {
		let bytes = extended_special_core(62, section_type);
		failure(&bytes, "format", "Recorded core failed unchanged upstream structural parsing: SHT_SYMTAB section points at section 2 of type SHT_NULL, expected SHT_STRTAB");
	}
	for section_type in [5, 0x6fff_fff6, 0x6fff_fffc, 0x6fff_ffff] {
		let bytes = extended_special_core(62, section_type);
		failure(&bytes, "format", "Recorded core failed unchanged upstream structural parsing: Section points at section 2 of type SHT_NULL, expected SHT_SYMTAB/SHT_DYNSYM");
	}
	for (machine, linked_type, label) in [
		(62, 0x7000_0001, "SHT_AMD64_UNWIND"),
		(183, 0x7000_0001, "1879048193"),
		(183, 0x7000_0003, "SHT_AARCH64_ATTRIBUTES"),
		(62, 0x7000_0003, "1879048195"),
		(62, 0xffff_ffff, "SHT_HIUSER"),
		(183, 0xdead_beef, "3735928559"),
	] {
		let mut bytes = extended_special_core(machine, 6);
		put32(&mut bytes, 196, linked_type);
		failure(&bytes, "format", &format!(
			"Recorded core failed unchanged upstream structural parsing: Unexpected section type {label}, expected ('SHT_STRTAB', 'SHT_NOBITS', 'SHT_NULL')"
		));
	}
}

#[test]
fn recorded_core_extended_special_prefix_preserves_constructor_order() {
	for section_type in [4, 6, 9, 19] {
		let mut bytes = extended_special_core(62, section_type);
		put64(&mut bytes, 72, 0x800);
		put64(&mut bytes, 88, 256);
		failure(
			&bytes,
			"format",
			"Recorded core failed unchanged upstream structural parsing: expected 4, found 0",
		);
	}
	// Symbol factories validate the link before constructing their own Section.
	let mut bytes = extended_special_core(62, 2);
	put64(&mut bytes, 72, 0x800);
	put64(&mut bytes, 88, 256);
	failure(&bytes, "format", "Recorded core failed unchanged upstream structural parsing: SHT_SYMTAB section points at section 2 of type SHT_NULL, expected SHT_STRTAB");
	// The name string table is constructed before any specialized factory.
	put64(&mut bytes, 136, 0x800);
	put64(&mut bytes, 152, 256);
	failure(
		&bytes,
		"format",
		"Recorded core failed unchanged upstream structural parsing: expected 4, found 0",
	);
}

#[test]
fn recorded_core_extended_special_constructors_keep_link_bounds_and_hash_boundaries() {
	let mut bytes = extended_special_core(62, 2);
	put32(&mut bytes, 104, 4);
	failure(&bytes, "format", "Recorded core failed unchanged upstream structural parsing: Reading section 4 at offset 320 past EOF 256");
	put32(&mut bytes, 104, 2);
	failure(
		&bytes[..255],
		"format",
		"Recorded core failed unchanged upstream structural parsing: expected 8, found 7",
	);
	for section_type in [2, 6, 11, 0x6fff_fff3, 0x6fff_fffd, 0x6fff_fffe] {
		let mut bytes = extended_special_core(62, section_type);
		put32(&mut bytes, 196, 3);
		put64(&mut bytes, 120, 24);
		assert_eq!(parsed(&bytes)["segments"], json!([]));
	}
	for section_type in [5, 0x6fff_fff6, 0x6fff_fffc, 0x6fff_ffff] {
		let mut bytes = extended_special_core(62, section_type);
		put32(&mut bytes, 196, 2);
		put32(&mut bytes, 232, 1);
		put64(&mut bytes, 248, 24);
		if section_type != 0x6fff_fff6 {
			assert_eq!(parsed(&bytes)["segments"], json!([]));
		}
		if matches!(section_type, 5 | 0x6fff_fff6) {
			put64(&mut bytes, 96, 1);
			failure(&bytes, "unsupported-target", &format!(
				"Native recorded-core section validation does not implement the hash-table body for sh_type={section_type}."
			));
		}
	}
}

#[test]
fn recorded_core_dynamic_constructor_fixed_reference_differences_match() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_recorded_core/dynamic-sections-rea-6.8.0.json"
	))
	.unwrap();
	let cases = fixture["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 37);
	for case in cases {
		let encoded = case["input_hex"].as_str().unwrap();
		assert_eq!(encoded.len() % 2, 0);
		let bytes: Vec<u8> = encoded
			.as_bytes()
			.chunks_exact(2)
			.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
			.collect();
		assert_eq!(super::super::rea_provider::sha256(&bytes), case["sha256"]);
		let actual = match parse_recorded_core(&bytes, OUTPUT_LIMIT) {
			Ok(value) => json!({"ok":true, "value":value}),
			Err(error) => json!({"ok":false, "reason":error.reason, "message":error.message}),
		};
		assert_eq!(actual, case["expected"], "original case {}", case["id"]);
	}
}

#[test]
fn recorded_core_dynamic_constructor_stops_at_the_first_matching_section() {
	let mut bytes = core(62, &[]);
	put32(&mut bytes, 64, 2);
	put64(&mut bytes, 40, 120);
	put16(&mut bytes, 60, 4);
	put16(&mut bytes, 62, 1);
	bytes.resize(313, 0);
	put32(&mut bytes, 188, 3);
	put64(&mut bytes, 208, 312);
	put32(&mut bytes, 252, 6);
	put64(&mut bytes, 272, 120);
	put32(&mut bytes, 288, 1);
	assert_eq!(parsed(&bytes)["segments"][0]["type"], "PT_DYNAMIC");
	// The fourth section is truncated, but the matching third ends iteration.
	put64(&mut bytes, 272, 121);
	failure(
		&bytes,
		"format",
		"Recorded core failed unchanged upstream structural parsing: expected 4, found 1",
	);
}

#[test]
fn recorded_core_symbol_constructor_diagnostics_preserve_ascii_repr() {
	for (name, expected) in [
		(b"\0".as_slice(), "''"),
		(b"'\0".as_slice(), "\"'\""),
		(b"\"\0".as_slice(), "'\"'"),
		(b"'\"\\\n\r\t\x7f\0".as_slice(), "'\\'\"\\\\\\n\\r\\t\\x7f'"),
	] {
		let mut bytes = extended_special_core(62, 2);
		put32(&mut bytes, 196, 3);
		put64(&mut bytes, 152, 256);
		bytes.extend_from_slice(name);
		failure(&bytes, "format", &format!(
			"Recorded core failed unchanged upstream structural parsing: Expected entry size of section {expected} to be > 0"
		));
		put64(&mut bytes, 120, 24);
		put64(&mut bytes, 96, 1);
		failure(&bytes, "format", &format!(
			"Recorded core failed unchanged upstream structural parsing: Expected section size to be a multiple of entry size in section {expected}"
		));
	}
	let mut bytes = extended_special_core(62, 2);
	put32(&mut bytes, 196, 3);
	put64(&mut bytes, 152, 256);
	bytes.extend_from_slice("é\0".as_bytes());
	failure(
		&bytes,
		"unsupported-target",
		"Native recorded-core symbol-table diagnostics require an ASCII section name.",
	);
	// A valid symbol table never needs a diagnostic-name representation.
	put64(&mut bytes, 120, 24);
	assert_eq!(parsed(&bytes)["segments"], json!([]));
}

#[test]
fn recorded_core_dynamic_section_work_is_bounded_across_segments() {
	let segments = 513;
	let sections = 512;
	let shoff = 64 + segments * 56;
	let mut bytes = header(62);
	put64(&mut bytes, 32, 64);
	put64(&mut bytes, 40, shoff as u64);
	put16(&mut bytes, 56, segments as u16);
	put16(&mut bytes, 60, sections as u16);
	bytes.resize(shoff + sections * 64, 0);
	for index in 0..segments {
		put32(&mut bytes, 64 + index * 56, 2);
	}
	failure(
		&bytes,
		"resource-limit",
		"Native recorded-core section-constructor work limit exceeded.",
	);
}
