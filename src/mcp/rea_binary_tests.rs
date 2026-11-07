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

//! Independent ELF fixture construction, bounded-result and malformed-range tests.
//! The optional platform compiler emits our source as an object; no object or
//! executable under inspection is ever launched.

use super::inspect_elf_bytes;
#[cfg(target_os = "linux")]
use serde_json::Value;

fn put16(data: &mut [u8], at: usize, value: u16, little: bool) {
	let bytes = if little {
		value.to_le_bytes()
	} else {
		value.to_be_bytes()
	};
	data[at..at + 2].copy_from_slice(&bytes);
}
fn put32(data: &mut [u8], at: usize, value: u32, little: bool) {
	let bytes = if little {
		value.to_le_bytes()
	} else {
		value.to_be_bytes()
	};
	data[at..at + 4].copy_from_slice(&bytes);
}
fn put64(data: &mut [u8], at: usize, value: u64, little: bool) {
	let bytes = if little {
		value.to_le_bytes()
	} else {
		value.to_be_bytes()
	};
	data[at..at + 8].copy_from_slice(&bytes);
}

fn header(bits: u8, little: bool) -> Vec<u8> {
	let size = if bits == 64 { 64 } else { 52 };
	let mut data = vec![0; size];
	data[..4].copy_from_slice(b"\x7fELF");
	data[4] = if bits == 64 { 2 } else { 1 };
	data[5] = if little { 1 } else { 2 };
	data[6] = 1;
	put16(&mut data, 16, 1, little);
	put16(&mut data, 18, if bits == 64 { 62 } else { 3 }, little);
	put32(&mut data, 20, 1, little);
	put16(
		&mut data,
		if bits == 64 { 52 } else { 40 },
		size as u16,
		little,
	);
	data
}

fn append(data: &mut Vec<u8>, payload: &[u8], alignment: usize) -> usize {
	data.resize(data.len().div_ceil(alignment) * alignment, 0);
	let at = data.len();
	data.extend_from_slice(payload);
	at
}

fn fixture(symbol_count: usize, note_count: usize) -> Vec<u8> {
	let mut data = header(64, true);
	data.resize(64 + 7 * 64, 0);
	put64(&mut data, 40, 64, true);
	put16(&mut data, 58, 64, true);
	put16(&mut data, 60, 7, true);
	put16(&mut data, 62, 1, true);
	let section_names = b"\0.shstrtab\0.strtab\0.symtab\0.note.gnu.build-id\0.text\0.bss\0";
	let strings = b"\0native_entry\0external_value\0";
	let mut symbols = vec![0; symbol_count * 24];
	for index in 1..symbol_count {
		let at = index * 24;
		put32(&mut symbols, at, if index == 2 { 14 } else { 1 }, true);
		symbols[at + 4] = 0x12;
		put16(&mut symbols, at + 6, if index == 2 { 0 } else { 5 }, true);
		put64(
			&mut symbols,
			at + 8,
			if index == 2 { 0 } else { 0x20_0000_0000_0001 },
			true,
		);
		put64(&mut symbols, at + 16, 4, true);
	}
	let note = [
		4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', 0, 0xde, 0xad, 0xbe, 0xef,
	];
	let notes = note.repeat(note_count);
	let names_at = append(&mut data, section_names, 1);
	let strings_at = append(&mut data, strings, 1);
	let symbols_at = append(&mut data, &symbols, 8);
	let notes_at = append(&mut data, &notes, 4);
	let text_at = append(&mut data, &[0; 16], 4);
	for (index, name, kind, offset, size, alignment) in [
		(1, 1, 3, names_at, section_names.len(), 1),
		(2, 11, 3, strings_at, strings.len(), 1),
		(3, 19, 2, symbols_at, symbols.len(), 8),
		(4, 27, 7, notes_at, notes.len(), 4),
		(5, 46, 1, text_at, 16, 4),
		(6, 52, 8, 0, 1024, 16),
	] {
		let at = 64 + index * 64;
		put32(&mut data, at, name, true);
		put32(&mut data, at + 4, kind, true);
		put64(&mut data, at + 24, offset as u64, true);
		put64(&mut data, at + 32, size as u64, true);
		put64(&mut data, at + 48, alignment, true);
	}
	put32(&mut data, 64 + 3 * 64 + 40, 2, true);
	put32(
		&mut data,
		64 + 3 * 64 + 44,
		if symbol_count == 0 { 0 } else { 1 },
		true,
	);
	put64(&mut data, 64 + 3 * 64 + 56, 24, true);
	put64(&mut data, 64 + 6 * 64 + 24, u64::MAX - 2, true);
	data
}

fn section_offset(data: &[u8], index: usize) -> usize {
	u64::from_le_bytes(
		data[64 + index * 64 + 24..64 + index * 64 + 32]
			.try_into()
			.unwrap(),
	) as usize
}

#[test]
fn elf_classes_and_byte_orders_are_explicit() {
	for bits in [32, 64] {
		for little in [false, true] {
			let report = inspect_elf_bytes(&header(bits, little)).unwrap();
			assert_eq!(report["word_size_bits"], bits);
			assert_eq!(report["byte_order"], if little { "little" } else { "big" });
			assert!(report["sections"]["rows"].as_array().unwrap().is_empty());
			assert_eq!(report["coverage"]["status"], "partial");
		}
	}
}

#[test]
fn symbols_notes_and_nobits_are_observed_without_execution() {
	let report = inspect_elf_bytes(&fixture(3, 1)).unwrap();
	assert_eq!(report["sections"]["rows"][6]["file_backed"], false);
	assert_eq!(report["symbols"]["rows"][1]["name"]["utf8"], "native_entry");
	assert_eq!(
		report["symbols"]["rows"][1]["value_hex"],
		"0x20000000000001"
	);
	assert_eq!(
		report["symbols"]["rows"][2]["name"]["utf8"],
		"external_value"
	);
	assert_eq!(report["symbols"]["rows"][2]["undefined"], true);
	assert_eq!(report["symbols"]["entry_reference_validation"], "complete");
	assert_eq!(report["notes"]["gnu_build_ids"][0]["bytes_hex"], "deadbeef");
	assert_eq!(report["notes"]["coverage"]["status"], "complete");
	assert!(report["gpu"].is_null());
}

#[test]
fn output_omissions_preserve_counts_and_do_not_claim_completeness() {
	let report = inspect_elf_bytes(&fixture(300, 300)).unwrap();
	let returned = report["symbols"]["rows"].as_array().unwrap().len();
	assert!(returned <= 256);
	assert_eq!(report["symbols"]["coverage"]["declared_records"], "300");
	assert_eq!(
		report["symbols"]["coverage"]["omitted_records"],
		(300 - returned).to_string()
	);
	assert_eq!(report["symbols"]["coverage"]["status"], "partial");
	assert_eq!(report["symbols"]["entry_reference_validation"], "complete");
	assert!(report["notes"]["rows"].as_array().unwrap().len() <= 256);
	assert_eq!(report["notes"]["coverage"]["observed_records"], "300");
	assert_eq!(report["notes"]["coverage"]["status"], "partial");
	assert!(serde_json::to_vec(&report).unwrap().len() < 1_000_000);
}

#[test]
fn malformed_file_ranges_and_names_are_refused() {
	let data = fixture(3, 1);
	for end in [0, 1, 4, 16, 63, 64, 100, data.len() - 1] {
		assert!(inspect_elf_bytes(&data[..end]).is_err());
	}
	let mut bad = data.clone();
	put64(&mut bad, 64 + 5 * 64 + 24, u64::MAX - 1, true);
	assert!(inspect_elf_bytes(&bad)
		.unwrap_err()
		.to_string()
		.contains("overflow"));
	let mut bad = data.clone();
	put32(&mut bad, 64 + 5 * 64, u32::MAX, true);
	assert!(inspect_elf_bytes(&bad)
		.unwrap_err()
		.to_string()
		.contains("string reference"));
	let mut bad = data.clone();
	let names = section_offset(&bad, 1);
	put64(&mut bad, 64 + 5 * 64 + 24, names as u64, true);
	assert!(inspect_elf_bytes(&bad)
		.unwrap_err()
		.to_string()
		.contains("overlap"));
}

#[test]
fn symbol_reference_validation_checks_selected_table_bytes() {
	let data = fixture(3, 1);
	let at = section_offset(&data, 3) + 24;
	let mut bad = data.clone();
	put16(&mut bad, at + 6, 7, true);
	assert!(inspect_elf_bytes(&bad)
		.unwrap_err()
		.to_string()
		.contains("section index"));
	let mut bad = data.clone();
	put16(&mut bad, at + 6, 0xffff, true);
	assert!(inspect_elf_bytes(&bad)
		.unwrap_err()
		.to_string()
		.contains("SHN_XINDEX"));
	let mut bad = data;
	put32(&mut bad, at, u32::MAX, true);
	assert!(inspect_elf_bytes(&bad)
		.unwrap_err()
		.to_string()
		.contains("string reference"));
}

#[test]
fn non_utf8_names_remain_exact_bytes() {
	let mut data = fixture(3, 1);
	let names = section_offset(&data, 2);
	data[names + 1] = 0xff;
	let report = inspect_elf_bytes(&data).unwrap();
	let name = &report["symbols"]["rows"][1]["name"];
	assert!(name["utf8"].is_null());
	assert!(name["bytes_hex"].as_str().unwrap().starts_with("ff"));
}

#[test]
fn compressed_symbol_tables_remain_unknown() {
	let mut data = fixture(3, 1);
	put64(&mut data, 64 + 3 * 64 + 8, 0x800, true);
	let report = inspect_elf_bytes(&data).unwrap();
	assert_eq!(report["symbols"]["skipped_compressed_tables"], 1);
	assert_eq!(report["symbols"]["coverage"]["status"], "partial");
	assert_eq!(report["symbols"]["entry_reference_validation"], "partial");
	assert_eq!(report["symbols"]["uncompressed_declared_symbols"], "0");
}

#[test]
fn gpu_facts_do_not_invent_a_target_or_kernel_inventory() {
	let mut data = fixture(3, 1);
	put16(&mut data, 18, 224, true);
	put32(&mut data, 48, 0x4050, true);
	data[7] = 64;
	data[8] = 2;
	let report = inspect_elf_bytes(&data).unwrap();
	assert_eq!(report["gpu"]["architecture_family"], "amdgpu");
	assert_eq!(report["gpu"]["elf_flags_hex"], "0x4050");
	assert_eq!(report["gpu"]["elf_os_abi"], 64);
	assert!(report["gpu"]["target_architecture"].is_null());
	assert!(report["gpu"]["kernel_inventory"].is_null());
}

#[test]
fn sectionless_program_headers_validate_load_constraints() {
	let mut data = header(64, true);
	data.resize(128, 0);
	put64(&mut data, 32, 64, true);
	put16(&mut data, 54, 56, true);
	put16(&mut data, 56, 1, true);
	put32(&mut data, 64, 1, true);
	put64(&mut data, 72, 120, true);
	put64(&mut data, 80, 0x40_0078, true);
	put64(&mut data, 96, 8, true);
	put64(&mut data, 104, 16, true);
	put64(&mut data, 112, 4096, true);
	let report = inspect_elf_bytes(&data).unwrap();
	assert_eq!(report["program_headers"]["rows"][0]["file_size"], "8");
	put64(&mut data, 104, 4, true);
	assert!(inspect_elf_bytes(&data)
		.unwrap_err()
		.to_string()
		.contains("memory size"));
}

#[test]
fn note_extent_must_fit_its_own_section() {
	let mut data = fixture(3, 1);
	let at = section_offset(&data, 4);
	put32(&mut data, at + 4, u32::MAX, true);
	assert!(inspect_elf_bytes(&data)
		.unwrap_err()
		.to_string()
		.contains("exceed the section"));
}

#[test]
fn unsupported_note_alignment_is_opaque_not_absent() {
	let mut data = fixture(3, 1);
	put64(&mut data, 64 + 4 * 64 + 48, 1, true);
	let report = inspect_elf_bytes(&data).unwrap();
	assert_eq!(report["notes"]["coverage"]["opaque_sections"], 1);
	assert_eq!(report["notes"]["coverage"]["status"], "partial");
}

#[test]
fn extended_section_count_is_decoded_without_expanding_the_result() {
	let mut data = header(64, true);
	data.resize(64 + 65_536 * 64, 0);
	put64(&mut data, 40, 64, true);
	put16(&mut data, 58, 64, true);
	put64(&mut data, 64 + 32, 65_536, true);
	let report = inspect_elf_bytes(&data).unwrap();
	assert_eq!(report["extended_numbering"]["section_count"], true);
	assert_eq!(report["sections"]["coverage"]["declared_records"], "65536");
	assert_eq!(report["sections"]["rows"].as_array().unwrap().len(), 256);
	assert_eq!(report["sections"]["coverage"]["status"], "partial");
}

#[cfg(target_os = "linux")]
#[test]
fn compiler_emitted_owned_object_exposes_declared_function_and_external() {
	let dir = tempfile::tempdir().unwrap();
	let source = dir.path().join("owned_fixture.c");
	let object = dir.path().join("owned_fixture.o");
	std::fs::write(
		&source,
		"extern int external_value;\nint rea_fixture(int x) { return x + external_value; }\n",
	)
	.unwrap();
	let result = std::process::Command::new("cc")
		.args(["-c", "-O0"])
		.arg(&source)
		.arg("-o")
		.arg(&object)
		.output();
	let result = match result {
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			eprintln!("owned compiler fixture not exercised: cc unavailable");
			return;
		}
		other => other.unwrap(),
	};
	assert!(
		result.status.success(),
		"{}",
		String::from_utf8_lossy(&result.stderr)
	);
	let report = inspect_elf_bytes(&std::fs::read(&object).unwrap()).unwrap();
	let rows = report["symbols"]["rows"].as_array().unwrap();
	let find =
		|name: &str| -> &Value { rows.iter().find(|row| row["name"]["utf8"] == name).unwrap() };
	assert_eq!(find("rea_fixture")["undefined"], false);
	assert_eq!(find("external_value")["undefined"], true);
	assert_eq!(report["symbols"]["entry_reference_validation"], "complete");
}

#[test]
fn report_budget_trims_delivery_without_erasing_summary_counts() {
	let mut data = fixture(300, 1);
	let mut names = vec![1u8; 1026];
	names[0] = 0;
	names[1025] = 0;
	let names_at = append(&mut data, &names, 1);
	put64(&mut data, 64 + 2 * 64 + 24, names_at as u64, true);
	put64(&mut data, 64 + 2 * 64 + 32, names.len() as u64, true);
	let report = inspect_elf_bytes(&data).unwrap();
	assert!(serde_json::to_vec(&report).unwrap().len() <= 192 * 1024);
	assert_eq!(report["delivery"]["limited"], true);
	assert_eq!(report["symbols"]["coverage"]["declared_records"], "300");
	assert_eq!(report["symbols"]["entry_reference_validation"], "complete");
	let returned = report["symbols"]["rows"].as_array().unwrap().len();
	assert!(returned < 256);
	assert_eq!(
		report["symbols"]["coverage"]["omitted_records"],
		(300 - returned).to_string()
	);
}

#[test]
fn extended_symbol_section_index_uses_the_linked_table() {
	let mut data = fixture(3, 1);
	let at = append(&mut data, &[0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0], 4);
	put32(&mut data, 64 + 6 * 64 + 4, 18, true);
	put64(&mut data, 64 + 6 * 64 + 24, at as u64, true);
	put64(&mut data, 64 + 6 * 64 + 32, 12, true);
	put32(&mut data, 64 + 6 * 64 + 40, 3, true);
	put64(&mut data, 64 + 6 * 64 + 48, 4, true);
	put64(&mut data, 64 + 6 * 64 + 56, 4, true);
	let symbol = section_offset(&data, 3) + 24;
	put16(&mut data, symbol + 6, 0xffff, true);
	let report = inspect_elf_bytes(&data).unwrap();
	assert_eq!(report["symbols"]["rows"][1]["section_index_raw"], 65535);
	assert_eq!(report["symbols"]["rows"][1]["section_index"], "5");
}
