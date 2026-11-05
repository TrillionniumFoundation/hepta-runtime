// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0

//! Bounded section-name decompression with the frozen producer's observable stream semantics.

use std::io::{Cursor, Read};

use ruzstd::decoding::errors::FrameDecoderError;
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use zlib_rs::{Inflate, InflateError, InflateFlush, Status};

use super::{format_failure, read_u32, ElfNotesFailure};

const ZSTD_WINDOW_BYTES: u64 = 128 * 1024 * 1024;
const ZSTD_BLOCK_BYTES: usize = 128 * 1024;

pub(super) enum DecodedNames {
	Available(Vec<u8>),
	Unsupported(u32),
}

fn decompression_failure(message: impl std::fmt::Display) -> ElfNotesFailure {
	format_failure(format!(
		"ELF compressed section-name table could not be decompressed: {message}"
	))
}

fn output_limit(limit: usize) -> ElfNotesFailure {
	decompression_failure(format!("Cannot create a Buffer larger than {limit} bytes"))
}

pub(super) fn decode_names(
	raw: &[u8],
	wide: bool,
	little: bool,
	source_bytes: u64,
	max_file_bytes: u64,
) -> Result<DecodedNames, ElfNotesFailure> {
	let header_bytes = if wide { 24 } else { 12 };
	if raw.len() < header_bytes {
		return Err(format_failure(
			"ELF compressed section-name table header is truncated",
		));
	}
	let kind = read_u32(raw, little);
	if kind != 1 && kind != 2 {
		return Ok(DecodedNames::Unsupported(kind));
	}
	let declared = if wide {
		let word = [
			raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
		];
		if little {
			u64::from_le_bytes(word)
		} else {
			u64::from_be_bytes(word)
		}
	} else {
		u64::from(read_u32(&raw[4..], little))
	};
	if declared > max_file_bytes.saturating_sub(source_bytes) {
		return Err(ElfNotesFailure::SectionNamesBudget {
			minimum_required_bytes: u128::from(source_bytes) + u128::from(declared),
			max_file_bytes,
		});
	}
	let expected = usize::try_from(declared).map_err(|_| ElfNotesFailure::SectionNamesBudget {
		minimum_required_bytes: u128::from(source_bytes) + u128::from(declared),
		max_file_bytes,
	})?;
	let limit = expected.max(1);
	let payload = &raw[header_bytes..];
	let decoded = if kind == 1 {
		inflate_zlib(payload, limit)?
	} else {
		inflate_zstd(payload, limit)?
	};
	if decoded.len() != expected {
		return Err(format_failure(
			"ELF compressed section-name table size is inconsistent",
		));
	}
	Ok(DecodedNames::Available(decoded))
}

fn inflate_zlib(payload: &[u8], limit: usize) -> Result<Vec<u8>, ElfNotesFailure> {
	// The dedicated pure-Rust backend retains zlib's diagnostic categories without changing the
	// existing archive tools' flate2 backend or linking a native zlib library.
	let mut inflater = Inflate::new(true, 15);
	let mut output = Vec::new();
	let mut chunk = [0_u8; 16 * 1024];
	loop {
		let before_in = inflater.total_in();
		let before_out = inflater.total_out();
		let input = &payload[before_in as usize..];
		let status = inflater.decompress(input, &mut chunk, InflateFlush::Finish);
		let written = (inflater.total_out() - before_out) as usize;
		match status {
			Err(error) => {
				let message = if matches!(error, InflateError::NeedDict { .. }) {
					"Missing dictionary"
				} else {
					inflater.error_message().unwrap_or(error.as_str())
				};
				return Err(decompression_failure(message));
			}
			Ok(status) => {
				if written > limit - output.len() {
					return Err(output_limit(limit));
				}
				output.extend_from_slice(&chunk[..written]);
				if status == Status::StreamEnd {
					return Ok(output);
				}
				if before_in == inflater.total_in() && written == 0 {
					return Err(decompression_failure("unexpected end of file"));
				}
			}
		}
	}
}

struct ZstdHeader {
	header_bytes: usize,
	content_size: Option<u64>,
	window_bytes: u64,
	checksum: bool,
}

fn zstd_header(payload: &[u8]) -> Result<Option<ZstdHeader>, ElfNotesFailure> {
	let magic = [0x28, 0xb5, 0x2f, 0xfd];
	let skip_magic = [0x50, 0x2a, 0x4d, 0x18];
	let prefix = payload.len().min(4);
	let normal = payload[..prefix] == magic[..prefix];
	let skip = payload
		.first()
		.is_some_and(|byte| (0x50..=0x5f).contains(byte))
		&& payload[1..prefix] == skip_magic[1..prefix];
	if !normal && !skip {
		return Err(decompression_failure("Unknown frame descriptor"));
	}
	// The fixed Node producer consumes one frame, including a skippable first frame. It also
	// returns the available output on incomplete input; a declared-size check follows decoding.
	if skip || payload.len() < 5 {
		return Ok(None);
	}
	let descriptor = payload[4];
	let single = descriptor & 0x20 != 0;
	let dictionary_bytes = match descriptor & 3 {
		0 => 0,
		1 => 1,
		2 => 2,
		_ => 4,
	};
	let content_bytes = match descriptor >> 6 {
		0 => usize::from(single),
		1 => 2,
		2 => 4,
		_ => 8,
	};
	let dictionary_at = 5 + usize::from(!single);
	let content_at = dictionary_at + dictionary_bytes;
	let header_bytes = content_at + content_bytes;
	if payload.len() < header_bytes {
		return Ok(None);
	}
	if descriptor & 8 != 0 {
		return Err(decompression_failure("Unsupported frame parameter"));
	}
	if payload[dictionary_at..content_at]
		.iter()
		.any(|&byte| byte != 0)
	{
		return Err(decompression_failure("Dictionary mismatch"));
	}
	let content_size = if content_bytes == 0 {
		None
	} else {
		let mut size = 0_u64;
		for (index, &byte) in payload[content_at..header_bytes].iter().enumerate() {
			size |= u64::from(byte) << (index * 8);
		}
		if content_bytes == 2 {
			size += 256;
		}
		Some(size)
	};
	let window_bytes = if single {
		content_size.unwrap_or(0)
	} else {
		let window = payload[5];
		let base = 1_u64 << (10 + (window >> 3));
		base + (base / 8) * u64::from(window & 7)
	};
	if window_bytes > ZSTD_WINDOW_BYTES {
		return Err(decompression_failure(
			"Frame requires too much memory for decoding",
		));
	}
	Ok(Some(ZstdHeader {
		header_bytes,
		content_size,
		window_bytes,
		checksum: descriptor & 4 != 0,
	}))
}

fn zstd_failure(error: FrameDecoderError) -> ElfNotesFailure {
	match error {
		FrameDecoderError::WindowSizeTooBig { .. } => {
			decompression_failure("Frame requires too much memory for decoding")
		}
		FrameDecoderError::DictNotProvided { .. } => decompression_failure("Dictionary mismatch"),
		_ => decompression_failure("Data corruption detected"),
	}
}

fn drain(
	decoder: &mut FrameDecoder,
	output: &mut Vec<u8>,
	limit: usize,
) -> Result<(), ElfNotesFailure> {
	let mut chunk = [0_u8; 16 * 1024];
	loop {
		let written = decoder
			.read(&mut chunk)
			.map_err(|_| decompression_failure("Data corruption detected"))?;
		if written == 0 {
			break;
		}
		if written > limit - output.len() {
			return Err(output_limit(limit));
		}
		output.extend_from_slice(&chunk[..written]);
	}
	Ok(())
}

fn decode_block(
	decoder: &mut FrameDecoder,
	input: impl Read,
	allow_missing_checksum: bool,
) -> Result<(), ElfNotesFailure> {
	match decoder.decode_blocks(input, BlockDecodingStrategy::UptoBlocks(1)) {
		Ok(_) => Ok(()),
		Err(FrameDecoderError::FailedToReadChecksum(_)) if allow_missing_checksum => Ok(()),
		Err(error) => Err(zstd_failure(error)),
	}
}

fn finish_partial(
	decoder: &mut FrameDecoder,
	output: &mut Vec<u8>,
	limit: usize,
) -> Result<(), ElfNotesFailure> {
	// Flush retained history without copying or extending target input. The synthetic empty
	// final block is solely a decoder adapter for the producer's incomplete-stream behavior.
	decode_block(decoder, &[1_u8, 0, 0][..], true)?;
	drain(decoder, output, limit)
}

fn inflate_zstd(payload: &[u8], limit: usize) -> Result<Vec<u8>, ElfNotesFailure> {
	let Some(header) = zstd_header(payload)? else {
		return Ok(Vec::new());
	};
	let mut decoder = FrameDecoder::new();
	decoder.set_max_window_size(ZSTD_WINDOW_BYTES);
	decoder
		.init(Cursor::new(&payload[..header.header_bytes]))
		.map_err(zstd_failure)?;
	let mut output = Vec::new();
	let mut at = header.header_bytes;
	loop {
		if payload.len() - at < 3 {
			finish_partial(&mut decoder, &mut output, limit)?;
			return Ok(output);
		}
		let packed = u32::from(payload[at])
			| (u32::from(payload[at + 1]) << 8)
			| (u32::from(payload[at + 2]) << 16);
		let last = packed & 1 != 0;
		let block_type = (packed >> 1) & 3;
		let size = (packed >> 3) as usize;
		if block_type == 3 || size > ZSTD_BLOCK_BYTES || size as u64 > header.window_bytes {
			return Err(decompression_failure("Data corruption detected"));
		}
		let encoded_bytes = if block_type == 1 { 1 } else { size };
		let body_at = at + 3;
		if encoded_bytes > payload.len() - body_at {
			if block_type == 0 {
				// libzstd exposes an available raw-block prefix even before the entire block arrives.
				let available = payload.len() - body_at;
				let packed = ((available as u32) << 3) | 1;
				let prefix = [
					(packed & 255) as u8,
					((packed >> 8) & 255) as u8,
					((packed >> 16) & 255) as u8,
				];
				decode_block(
					&mut decoder,
					Cursor::new(prefix).chain(Cursor::new(&payload[body_at..])),
					true,
				)?;
				drain(&mut decoder, &mut output, limit)?;
			} else {
				finish_partial(&mut decoder, &mut output, limit)?;
			}
			return Ok(output);
		}
		let body_end = body_at + encoded_bytes;
		let complete_checksum = last && header.checksum && payload.len() - body_end >= 4;
		let block_end = body_end + if complete_checksum { 4 } else { 0 };
		decode_block(
			&mut decoder,
			Cursor::new(&payload[at..block_end]),
			last && header.checksum && !complete_checksum,
		)?;
		drain(&mut decoder, &mut output, limit)?;
		if last {
			if header
				.content_size
				.is_some_and(|size| size != output.len() as u64)
			{
				return Err(decompression_failure("Data corruption detected"));
			}
			if complete_checksum
				&& decoder.get_checksum_from_data() != decoder.get_calculated_checksum()
			{
				return Err(decompression_failure(
					"Restored data doesn't match checksum",
				));
			}
			return Ok(output);
		}
		at = body_end;
	}
}
