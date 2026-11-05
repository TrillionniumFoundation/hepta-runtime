// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0

//! Independent ELF byte fixtures and contract boundaries for complete note observations.

use std::io::Write;

use super::*;

fn put16(bytes: &mut [u8], at: usize, value: u16, little: bool) {
	bytes[at..at + 2].copy_from_slice(&if little {
		value.to_le_bytes()
	} else {
		value.to_be_bytes()
	});
}

fn put32(bytes: &mut [u8], at: usize, value: u32, little: bool) {
	bytes[at..at + 4].copy_from_slice(&if little {
		value.to_le_bytes()
	} else {
		value.to_be_bytes()
	});
}

fn put_word(bytes: &mut [u8], at: usize, value: u64, wide: bool, little: bool) {
	if wide {
		bytes[at..at + 8].copy_from_slice(&if little {
			value.to_le_bytes()
		} else {
			value.to_be_bytes()
		});
	} else {
		put32(bytes, at, value as u32, little);
	}
}

fn header(wide: bool, little: bool) -> Vec<u8> {
	let mut bytes = vec![0; if wide { 64 } else { 52 }];
	bytes[..4].copy_from_slice(b"\x7fELF");
	bytes[4] = if wide { 2 } else { 1 };
	bytes[5] = if little { 1 } else { 2 };
	bytes[6] = 1;
	put16(&mut bytes, 16, 3, little);
	put16(&mut bytes, 18, if wide { 62 } else { 3 }, little);
	put32(&mut bytes, 20, 1, little);
	put16(
		&mut bytes,
		if wide { 52 } else { 40 },
		if wide { 64 } else { 52 },
		little,
	);
	bytes
}

fn note(owner: &[u8], descriptor: &[u8], kind: u32, alignment: u32, little: bool) -> Vec<u8> {
	let mut result = vec![0_u8; 12];
	put32(&mut result, 0, owner.len() as u32, little);
	put32(&mut result, 4, descriptor.len() as u32, little);
	put32(&mut result, 8, kind, little);
	result.extend_from_slice(owner);
	while !result.len().is_multiple_of(alignment as usize) {
		result.push(0);
	}
	result.extend_from_slice(descriptor);
	while !result.len().is_multiple_of(alignment as usize) {
		result.push(0);
	}
	result
}

fn image(
	wide: bool,
	little: bool,
	stream: &[u8],
	program: bool,
	names: Option<&[u8]>,
	alignment: u64,
) -> Vec<u8> {
	let mut bytes = header(wide, little);
	let phstride = if wide { 56 } else { 32 };
	let shstride = if wide { 64 } else { 40 };
	let phoff = bytes.len();
	if program {
		bytes.resize(bytes.len() + phstride, 0);
	}
	let shoff = bytes.len();
	if names.is_some() {
		bytes.resize(bytes.len() + 3 * shstride, 0);
	}
	let names_at = bytes.len();
	if let Some(names) = names {
		bytes.extend_from_slice(names);
	}
	let note_at = bytes.len();
	bytes.extend_from_slice(stream);
	if program {
		put_word(
			&mut bytes,
			if wide { 32 } else { 28 },
			phoff as u64,
			wide,
			little,
		);
		put16(
			&mut bytes,
			if wide { 54 } else { 42 },
			phstride as u16,
			little,
		);
		put16(&mut bytes, if wide { 56 } else { 44 }, 1, little);
		put32(&mut bytes, phoff, 4, little);
		put_word(
			&mut bytes,
			phoff + if wide { 8 } else { 4 },
			note_at as u64,
			wide,
			little,
		);
		put_word(
			&mut bytes,
			phoff + if wide { 32 } else { 16 },
			stream.len() as u64,
			wide,
			little,
		);
		put_word(
			&mut bytes,
			phoff + if wide { 48 } else { 28 },
			alignment,
			wide,
			little,
		);
	}
	if let Some(names) = names {
		put_word(
			&mut bytes,
			if wide { 40 } else { 32 },
			shoff as u64,
			wide,
			little,
		);
		put16(
			&mut bytes,
			if wide { 58 } else { 46 },
			shstride as u16,
			little,
		);
		put16(&mut bytes, if wide { 60 } else { 48 }, 3, little);
		put16(&mut bytes, if wide { 62 } else { 50 }, 1, little);
		let string_header = shoff + shstride;
		put32(&mut bytes, string_header + 4, 3, little);
		put_word(
			&mut bytes,
			string_header + if wide { 24 } else { 16 },
			names_at as u64,
			wide,
			little,
		);
		put_word(
			&mut bytes,
			string_header + if wide { 32 } else { 20 },
			names.len() as u64,
			wide,
			little,
		);
		let note_header = shoff + 2 * shstride;
		put32(&mut bytes, note_header, 1, little);
		put32(&mut bytes, note_header + 4, 7, little);
		put_word(
			&mut bytes,
			note_header + if wide { 24 } else { 16 },
			note_at as u64,
			wide,
			little,
		);
		put_word(
			&mut bytes,
			note_header + if wide { 32 } else { 20 },
			stream.len() as u64,
			wide,
			little,
		);
		put_word(
			&mut bytes,
			note_header + if wide { 48 } else { 32 },
			alignment,
			wide,
			little,
		);
	}
	bytes
}

fn inspect(bytes: &[u8]) -> Result<ElfNotesReport, ElfNotesFailure> {
	inspect_limits(bytes, 64 * 1024 * 1024, 32)
}

fn inspect_limits(
	bytes: &[u8],
	max_file_bytes: u64,
	max_entries: u32,
) -> Result<ElfNotesReport, ElfNotesFailure> {
	parse_elf_notes(
		bytes,
		ElfNotesArtifact {
			path: "/admitted/fixture.elf".to_owned(),
			sha256: hex(&Sha256::digest(bytes)),
			bytes: bytes.len() as u64,
		},
		max_file_bytes,
		max_entries,
	)
}

fn compressed_names(
	payload: &[u8],
	declared: u64,
	codec: u32,
	wide: bool,
	little: bool,
) -> Vec<u8> {
	let mut raw = vec![0; if wide { 24 } else { 12 }];
	put32(&mut raw, 0, codec, little);
	put_word(&mut raw, if wide { 8 } else { 4 }, declared, wide, little);
	raw.extend_from_slice(payload);
	raw
}

fn decoded(raw: &[u8], wide: bool, little: bool) -> Result<Vec<u8>, ElfNotesFailure> {
	match compression::decode_names(raw, wide, little, 128, 1024 * 1024)? {
		compression::DecodedNames::Available(bytes) => Ok(bytes),
		compression::DecodedNames::Unsupported(_) => panic!("expected supported names"),
	}
}

fn unhex(value: &str) -> Vec<u8> {
	value
		.as_bytes()
		.chunks_exact(2)
		.map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
		.collect()
}

#[test]
fn absent_notes_preserve_architecture_byte_order_and_absence_limitations() {
	for wide in [false, true] {
		for little in [false, true] {
			let report = inspect(&header(wide, little)).unwrap();
			assert!(report.tables.is_empty());
			assert!(report.entries.is_empty());
			assert_eq!(report.coverage.examined_entries, 0);
			assert_eq!(report.format, if wide { "elf64" } else { "elf32" });
			assert_eq!(report.byte_order, if little { "little" } else { "big" });
			assert_eq!(report.machine, if wide { 62 } else { 3 });
			assert_eq!(
				report.limitations,
				[ABSENT_LIMITATION, EXAMINATION_LIMITATION]
			);
		}
	}
}

#[test]
fn program_and_section_notes_are_complete_independent_observations() {
	for wide in [false, true] {
		for little in [false, true] {
			let stream = note(b"GNU\0", &[0x01, 0x82, 0xff], 3, 8, little);
			let bytes = image(wide, little, &stream, true, Some(b"\0.note.\xff\0"), 8);
			let report = inspect(&bytes).unwrap();
			assert_eq!(report.tables.len(), 2);
			assert_eq!(report.entries.len(), 2);
			assert_eq!(report.tables[0].name, None);
			assert_eq!(report.tables[1].name.as_deref(), Some(".note.ÿ"));
			assert_eq!(report.entries[0].table_kind, ElfNoteTableKind::Program);
			assert_eq!(report.entries[1].table_kind, ElfNoteTableKind::Section);
			assert_eq!(report.entries[0].descriptor, report.entries[1].descriptor);
			assert_eq!(
				report.entries[0].descriptor.location.offset - report.entries[0].location.offset,
				16
			);
			assert_eq!(
				report.entries[0]
					.gnu
					.as_ref()
					.unwrap()
					.build_id_hex
					.as_deref(),
				Some("0182ff")
			);
			assert_eq!(report.entries[0].owner_bytes_hex, "474e5500");
			assert_eq!(report.coverage.examined_entries, 2);
			assert_eq!(
				report.limitations,
				[EXAMINATION_LIMITATION, DUPLICATE_LIMITATION]
			);
		}
	}
}

#[test]
fn abi_tag_uses_file_endianness_and_preserves_unknown_operating_system() {
	for little in [false, true] {
		let mut abi = vec![0; 16];
		for (index, value) in [99, 6, 12, 34].iter().enumerate() {
			put32(&mut abi, index * 4, *value, little);
		}
		let report = inspect(&image(
			false,
			little,
			&note(b"GNU\0", &abi, 1, 4, little),
			true,
			None,
			4,
		))
		.unwrap();
		let decoded = report.entries[0]
			.gnu
			.as_ref()
			.unwrap()
			.abi_tag
			.as_ref()
			.unwrap();
		assert_eq!(
			decoded,
			&ElfGnuAbiTag {
				os: 99,
				os_name: None,
				major: 6,
				minor: 12,
				subminor: 34
			}
		);
	}
}

#[test]
fn latin1_owner_and_gold_preserve_embedded_nuls_and_raw_names() {
	let report = inspect(&image(
		true,
		true,
		&note(b"GNU\0trailing", b"gold\0\xff\0\0", 4, 4, true),
		true,
		None,
		0,
	))
	.unwrap();
	assert_eq!(report.entries[0].owner, "GNU");
	assert_eq!(
		report.entries[0].owner_bytes_hex,
		"474e5500747261696c696e67"
	);
	assert_eq!(
		report.entries[0]
			.gnu
			.as_ref()
			.unwrap()
			.gold_version
			.as_deref(),
		Some("gold\0ÿ")
	);
	let report = inspect(&image(
		true,
		true,
		&note(&[0xff, 0, 0xfe], &[7], 3, 4, true),
		true,
		None,
		16,
	))
	.unwrap();
	assert_eq!(report.entries[0].owner, "ÿ");
	assert_eq!(report.entries[0].type_name, "unknown");
	assert_eq!(report.entries[0].gnu, None);
}

#[test]
fn large_descriptor_has_identity_without_invented_hex_truncation() {
	let descriptor = vec![0x86; 65];
	let report = inspect(&image(
		true,
		true,
		&note(b"other\0", &descriptor, 77, 4, true),
		true,
		None,
		4,
	))
	.unwrap();
	assert_eq!(report.entries[0].descriptor.hex, None);
	assert_eq!(report.entries[0].descriptor.bytes, 65);
	assert_eq!(
		report.entries[0].descriptor.sha256,
		hex(&Sha256::digest(&descriptor))
	);
}

#[test]
fn only_declared_eight_selects_eight_byte_note_alignment() {
	for declared in [0, 1, 3, 4, 7, 8, 16, 128] {
		let alignment = if declared == 8 { 8 } else { 4 };
		let report = inspect(&image(
			true,
			false,
			&note(b"GNU\0", &[1; 4], 5, alignment, false),
			true,
			None,
			declared,
		))
		.unwrap();
		assert_eq!(report.tables[0].alignment, alignment);
		assert_eq!(
			report.entries[0].descriptor.location.offset - report.entries[0].location.offset,
			16
		);
	}
}

#[test]
fn enlarged_native_header_and_entry_stride_remain_admissible() {
	let mut bare = header(true, true);
	bare.resize(80, 0);
	put16(&mut bare, 52, 80, true);
	assert!(inspect(&bare).is_ok());
	let mut bytes = image(true, true, &note(b"GNU\0", &[1], 3, 4, true), true, None, 4);
	bytes.splice(120..120, [0_u8; 8]);
	put16(&mut bytes, 54, 64, true);
	put_word(&mut bytes, 72, 128, true, true);
	assert_eq!(inspect(&bytes).unwrap().entries.len(), 1);
}

#[test]
fn cuda_cubin_vendor_header_version_is_the_only_version_exception() {
	let mut bytes = header(true, true);
	put32(&mut bytes, 20, 12345, true);
	assert_eq!(
		inspect(&bytes).unwrap_err().to_string(),
		"unsupported ELF header version"
	);
	put16(&mut bytes, 18, 190, true);
	bytes[7] = 0x33;
	assert!(inspect(&bytes).is_ok());
	bytes[7] = 0;
	assert!(inspect(&bytes).is_err());
}

#[test]
fn extended_numbering_and_compressed_notes_have_explicit_unsupported_results() {
	let mut bytes = header(true, true);
	put16(&mut bytes, 56, 0xffff, true);
	assert!(matches!(
		inspect(&bytes),
		Err(ElfNotesFailure::Unsupported { .. })
	));
	let mut bytes = image(true, true, &[], false, Some(b"\0.note\0"), 4);
	put_word(&mut bytes, 64 + 2 * 64 + 8, SHF_COMPRESSED, true, true);
	assert_eq!(inspect(&bytes).unwrap_err().to_string(), "Compressed ELF note sections are unsupported; descriptor file offsets require uncompressed note storage.");
}

#[test]
fn unrelated_sections_and_high_flags_do_not_invent_extra_validation() {
	let mut bytes = image(
		true,
		true,
		&note(b"GNU\0", &[1, 2], 3, 4, true),
		false,
		Some(b"\0.note\0"),
		4,
	);
	put32(&mut bytes, 64 + 4, 1, true);
	put_word(&mut bytes, 64 + 24, u64::MAX, true, true);
	put_word(&mut bytes, 64 + 32, u64::MAX, true, true);
	put_word(&mut bytes, 128 + 8, 1 << 63, true, true);
	assert_eq!(inspect(&bytes).unwrap().entries.len(), 1);
}

#[test]
fn unsafe_integer_offsets_and_outside_zero_length_tables_are_rejected() {
	let mut bytes = header(true, true);
	put_word(&mut bytes, 32, MAX_SAFE_INTEGER + 1, true, true);
	assert_eq!(
		inspect(&bytes).unwrap_err().to_string(),
		"ELF offset or size exceeds a safe integer."
	);
	let mut bytes = image(true, true, &[], true, None, 4);
	let outside = bytes.len() as u64 + 1;
	put_word(&mut bytes, 72, outside, true, true);
	assert_eq!(
		inspect(&bytes).unwrap_err().to_string(),
		format!("ELF range {outside} + 0 leaves the artifact.")
	);
}

#[test]
fn unknown_name_compression_keeps_notes_and_ignores_unread_declared_size() {
	let raw = compressed_names(&[], u64::MAX, 99, true, true);
	let mut bytes = image(
		true,
		true,
		&note(b"GNU\0", &[3], 3, 4, true),
		false,
		Some(&raw),
		4,
	);
	put_word(&mut bytes, 128 + 8, SHF_COMPRESSED, true, true);
	let report = inspect(&bytes).unwrap();
	assert_eq!(report.tables[0].name, None);
	assert_eq!(report.entries.len(), 1);
	assert!(report
		.limitations
		.last()
		.unwrap()
		.contains("compression type 99 is unsupported"));
}

#[test]
fn section_name_budget_preserves_values_above_unsigned_64_bit_sum() {
	let raw = compressed_names(&[], u64::MAX, 1, true, true);
	let error = compression::decode_names(&raw, true, true, 128, 1024)
		.err()
		.unwrap();
	assert_eq!(
		error,
		ElfNotesFailure::SectionNamesBudget {
			minimum_required_bytes: u128::from(u64::MAX) + 128,
			max_file_bytes: 1024
		}
	);
	let value = serde_json::to_value(error).unwrap();
	assert_eq!(value["minimum_required_bytes"], "18446744073709551743");
}

#[test]
fn zlib_section_names_obey_endian_size_checksum_and_output_budgets() {
	let text = b"\0.note.good\0";
	let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
	encoder.write_all(text).unwrap();
	let payload = encoder.finish().unwrap();
	for wide in [false, true] {
		for little in [false, true] {
			assert_eq!(
				decoded(
					&compressed_names(&payload, text.len() as u64, 1, wide, little),
					wide,
					little
				)
				.unwrap(),
				text
			);
		}
	}
	let mut corrupt = payload.clone();
	*corrupt.last_mut().unwrap() ^= 1;
	assert_eq!(
		decoded(
			&compressed_names(&corrupt, text.len() as u64, 1, true, true),
			true,
			true
		)
		.unwrap_err()
		.to_string(),
		"ELF compressed section-name table could not be decompressed: incorrect data check"
	);
	assert_eq!(
		decoded(
			&compressed_names(
				&payload[..payload.len() - 1],
				text.len() as u64,
				1,
				true,
				true
			),
			true,
			true
		)
		.unwrap_err()
		.to_string(),
		"ELF compressed section-name table could not be decompressed: unexpected end of file"
	);
	assert!(
		decoded(&compressed_names(&payload, 1, 1, true, true), true, true)
			.unwrap_err()
			.to_string()
			.ends_with("Cannot create a Buffer larger than 1 bytes")
	);
}

#[test]
fn zstandard_checks_complete_checksum_and_retains_fixed_producer_partial_behavior() {
	// Independently produced by Node v22.23.4 zstdCompressSync("hello", checksumFlag=1).
	let bytes = unhex("28b52ffd240529000068656c6c6fa36d9f88");
	for end in 14..=18 {
		assert_eq!(
			decoded(
				&compressed_names(&bytes[..end], 5, 2, true, true),
				true,
				true
			)
			.unwrap(),
			b"hello"
		);
	}
	for end in 9..14 {
		assert_eq!(
			decoded(
				&compressed_names(&bytes[..end], (end - 9) as u64, 2, true, true),
				true,
				true
			)
			.unwrap(),
			&b"hello"[..end - 9]
		);
	}
	let mut corrupt = bytes.clone();
	corrupt[17] ^= 1;
	assert!(
		decoded(&compressed_names(&corrupt, 5, 2, true, true), true, true)
			.unwrap_err()
			.to_string()
			.ends_with("Restored data doesn't match checksum")
	);
	let mut concat = bytes.clone();
	concat.extend_from_slice(&bytes);
	assert_eq!(
		decoded(&compressed_names(&concat, 5, 2, true, true), true, true).unwrap(),
		b"hello"
	);
}

#[test]
fn zstandard_skippable_first_frame_and_large_window_are_not_confused() {
	let mut skip = unhex("502a4d1800000000");
	skip.extend(unhex("28b52ffd200529000068656c6c6f"));
	assert_eq!(
		decoded(&compressed_names(&skip, 0, 2, true, true), true, true).unwrap(),
		Vec::<u8>::new()
	);
	let over_window = unhex("28b52ffd0090010000");
	assert!(decoded(
		&compressed_names(&over_window, 0, 2, true, true),
		true,
		true
	)
	.unwrap_err()
	.to_string()
	.ends_with("Frame requires too much memory for decoding"));
}

#[test]
fn entry_budget_counts_both_tables_and_never_reports_partial_coverage() {
	let bytes = image(
		true,
		true,
		&note(b"GNU\0", &[1], 3, 4, true),
		true,
		Some(b"\0.note\0"),
		4,
	);
	assert_eq!(
		inspect_limits(&bytes, 1 << 20, 1).unwrap_err(),
		ElfNotesFailure::EntryBudget { max_entries: 1 }
	);
}

#[test]
fn physical_hash_and_scan_budgets_are_cached_but_repeated_text_is_charged() {
	let large = [0_u8; 1024];
	let bytes = image(
		true,
		true,
		&note(b"", &large, 99, 4, true),
		true,
		Some(b"\0.note\0"),
		4,
	);
	assert_eq!(inspect(&bytes).unwrap().entries.len(), 2);
	let bytes = image(
		true,
		true,
		&note(b"GNU\0", &large, 4, 4, true),
		true,
		Some(b"\0.note\0"),
		4,
	);
	assert_eq!(
		inspect(&bytes).unwrap().entries[1]
			.gnu
			.as_ref()
			.unwrap()
			.gold_version
			.as_deref(),
		Some("")
	);
	let bytes = image(
		true,
		true,
		&note(b"GNU\0", &large, 3, 4, true),
		true,
		Some(b"\0.note\0"),
		4,
	);
	assert_eq!(
		inspect_limits(&bytes, 512 * 1024 * 1024, 32).unwrap_err(),
		ElfNotesFailure::TextBudget {
			limit_bytes: bytes.len() as u64
		}
	);
}

#[test]
fn note_stream_format_error_precedes_earlier_descriptor_text_budget_failure() {
	let mut stream = note(b"GNU\0", &[0x55; 1024], 3, 4, true);
	let mut impossible = [0_u8; 12];
	put32(&mut impossible, 0, u32::MAX, true);
	stream.extend_from_slice(&impossible);
	let bytes = image(true, true, &stream, true, None, 4);
	assert_eq!(
		inspect(&bytes).unwrap_err().to_string(),
		"ELF note entry exceeds its table."
	);
}

#[test]
fn short_zero_table_padding_is_allowed_but_nonzero_tail_is_malformed() {
	let mut stream = note(b"GNU\0", &[1], 3, 4, true);
	stream.extend([0; 11]);
	assert_eq!(
		inspect(&image(true, true, &stream, true, None, 4))
			.unwrap()
			.entries
			.len(),
		1
	);
	*stream.last_mut().unwrap() = 1;
	assert_eq!(
		inspect(&image(true, true, &stream, true, None, 4))
			.unwrap_err()
			.to_string(),
		"ELF note table has trailing non-zero bytes."
	);
}

#[test]
fn missing_and_unterminated_section_names_are_explicit_limitations() {
	let bytes = image(true, true, &[], false, Some(b"\0unterminated"), 4);
	let report = inspect(&bytes).unwrap();
	assert_eq!(report.tables[0].name, None);
	assert!(report
		.limitations
		.last()
		.unwrap()
		.contains("not NUL-terminated"));
	let mut bytes = image(true, true, &[], false, Some(b"\0ok\0"), 4);
	put32(&mut bytes, 192, 4, true);
	assert!(inspect(&bytes)
		.unwrap()
		.limitations
		.last()
		.unwrap()
		.contains("outside its string table"));
}

#[test]
fn deterministic_header_and_stream_mutations_do_not_panic() {
	let base = image(
		true,
		true,
		&note(b"GNU\0", &[0x43; 20], 3, 8, true),
		true,
		Some(b"\0.note\0"),
		8,
	);
	let mut state = 0x5a31_7d96_u32;
	for _ in 0..2048 {
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		let mut bytes = base.clone();
		let at = state as usize % bytes.len();
		bytes[at] ^= (state >> 24) as u8 | 1;
		if state & 15 == 0 {
			bytes.truncate(at);
		}
		assert!(
			std::panic::catch_unwind(|| inspect(&bytes)).is_ok(),
			"mutation at {at}"
		);
	}
}
