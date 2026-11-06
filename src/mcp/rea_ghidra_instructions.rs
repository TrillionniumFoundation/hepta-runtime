// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Complete selected-function Listing observations and their original REA value projection.
//! Bounds refuse the observation; they never turn a truncated list into a complete window.

use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::{sha256, valid_address};

const MAX_ROWS: usize = 4096;
const MAX_TEXT_BYTES: usize = 65536;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub(super) const LIMITATIONS: [&str; 5] = [
	"Instruction text and ordering are Ghidra-specific representations.",
	"The fast path does not invoke the decompiler or scan whole-program names and strings.",
	"Completeness covers the selected function's observed Listing after the fixed restricted analyzer profile; it does not prove complete machine-code discovery.",
	"The original provider's terminal-call and Borland SEH boundary heuristics are not reproduced by this bounded ELF adapter.",
	"The byte rows describe Ghidra's initialized instruction memory, including loader adjustments; they are not file-offset mappings.",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Coordinate {
	space: Option<String>,
	offset: u64,
}

#[derive(Debug)]
struct BodyRange {
	start: Coordinate,
	end: u64,
}

fn object<'a>(value: &'a Value, fields: &[&str], what: &str) -> Result<&'a Map<String, Value>> {
	let result = value
		.as_object()
		.with_context(|| format!("{what} is not an object"))?;
	if result.len() != fields.len() || fields.iter().any(|field| !result.contains_key(*field)) {
		bail!("{what} omitted or added fields");
	}
	Ok(result)
}

fn text<'a>(value: &'a Value, maximum: usize, what: &str) -> Result<&'a str> {
	let result = value
		.as_str()
		.with_context(|| format!("{what} is not text"))?;
	if result.is_empty() || result.len() > maximum || result.contains(['\0', '\r', '\n']) {
		bail!("{what} is empty, multiline or outside its byte budget");
	}
	Ok(result)
}

fn boolean(value: &Value, what: &str) -> Result<bool> {
	value
		.as_bool()
		.with_context(|| format!("{what} is not a boolean"))
}

// Named spaces follow the original observed-address spelling grammar. Uppercase
// redundant escapes such as %41 remain valid; this parser neither decodes names
// nor merges aliases. The Java producer itself escapes only non-unreserved bytes.
// The hexadecimal offset is canonical and selected ELF entries use the default space.
fn coordinate(value: &str) -> Result<Coordinate> {
	let (space, offset) = match value.rsplit_once(':') {
		Some((space, offset)) => {
			if space.is_empty() || space.len() > 1024 {
				bail!("Ghidra named address space is empty or too long");
			}
			let bytes = space.as_bytes();
			let mut index = 0;
			while index < bytes.len() {
				let byte = bytes[index];
				if byte.is_ascii_alphanumeric() || b"._~-".contains(&byte) {
					index += 1;
				} else if byte == b'%'
					&& index + 2 < bytes.len()
					&& bytes[index + 1..=index + 2]
						.iter()
						.all(|value| value.is_ascii_digit() || (b'A'..=b'F').contains(value))
				{
					index += 3;
				} else {
					bail!("Ghidra named address space violates uppercase-percent spelling");
				}
			}
			(Some(space.to_owned()), offset)
		}
		None => (None, value),
	};
	if !valid_address(offset) {
		bail!("Ghidra instruction coordinate is not canonical");
	}
	Ok(Coordinate {
		space,
		offset: u64::from_str_radix(&offset[2..], 16).context("Ghidra address overflows")?,
	})
}

fn body(value: &Value, entry: &Coordinate) -> Result<Vec<BodyRange>> {
	object(
		value,
		&[
			"available",
			"provenance",
			"ranges",
			"total_bytes",
			"span_bytes",
			"non_contiguous",
			"contains_entry",
		],
		"Ghidra complete function body",
	)?;
	if value["available"] != true || value["provenance"] != "ghidra-function-body-address-set" {
		bail!("Ghidra complete function-body provenance is absent");
	}
	let rows = value["ranges"]
		.as_array()
		.context("Ghidra body ranges are absent")?;
	if rows.len() > MAX_ROWS {
		bail!("Ghidra complete function-body range budget exceeded");
	}
	let mut result = Vec::with_capacity(rows.len());
	let mut bounds: BTreeMap<Option<String>, (u64, u64)> = BTreeMap::new();
	let mut closed = BTreeSet::new();
	let mut previous_space: Option<Option<String>> = None;
	let mut total = 0u128;
	let mut contains_entry = false;
	for row in rows {
		object(row, &["start", "end"], "Ghidra inclusive body range")?;
		let start = coordinate(text(&row["start"], 1050, "Ghidra body range start")?)?;
		let end = coordinate(text(&row["end"], 1050, "Ghidra body range end")?)?;
		if start.space != end.space || end.offset < start.offset {
			bail!("Ghidra inclusive body range has incompatible coordinates");
		}
		if let Some(previous) = &previous_space {
			if previous != &start.space {
				closed.insert(previous.clone());
			}
		}
		if closed.contains(&start.space) {
			bail!("Ghidra complete body reopens an already closed address space");
		}
		if let Some(previous) = bounds.get_mut(&start.space) {
			if previous
				.1
				.checked_add(1)
				.is_none_or(|last| start.offset <= last)
			{
				bail!("Ghidra body ranges overlap, are adjacent or are unordered");
			}
			previous.1 = end.offset;
		} else {
			bounds.insert(start.space.clone(), (start.offset, end.offset));
		}
		contains_entry |= start.space == entry.space
			&& start.offset <= entry.offset
			&& entry.offset <= end.offset;
		total += u128::from(end.offset) - u128::from(start.offset) + 1;
		if total > u128::from(MAX_SAFE_INTEGER) {
			bail!("Ghidra body byte count exceeds exact JSON integer range");
		}
		previous_space = Some(start.space.clone());
		result.push(BodyRange {
			start,
			end: end.offset,
		});
	}
	let span = if bounds.is_empty() {
		Some(0u64)
	} else if bounds.len() == 1 {
		let (start, end) = bounds
			.values()
			.next()
			.context("Ghidra body bounds absent")?;
		let span = u128::from(*end) - u128::from(*start) + 1;
		if span > u128::from(MAX_SAFE_INTEGER) {
			bail!("Ghidra function span exceeds exact JSON integer range");
		}
		Some(span as u64)
	} else {
		None
	};
	if value["total_bytes"].as_u64() != Some(total as u64)
		|| value["span_bytes"] != serde_json::to_value(span)?
		|| value["non_contiguous"].as_bool() != Some(rows.len() > 1)
		|| value["contains_entry"].as_bool() != Some(contains_entry)
		|| !contains_entry
	{
		bail!("Ghidra complete body counts, span or selected entry disagree with its inclusive ranges");
	}
	Ok(result)
}

fn symbol(value: &Value) -> Result<()> {
	if value.is_null() {
		return Ok(());
	}
	object(
		value,
		&["primary", "dynamic", "external", "type", "source"],
		"Ghidra symbol metadata",
	)?;
	for field in ["primary", "dynamic", "external"] {
		boolean(&value[field], "Ghidra symbol classification")?;
	}
	text(&value["type"], 128, "Ghidra symbol type")?;
	if !matches!(
		value["source"].as_str(),
		Some("default" | "analysis" | "ai" | "imported" | "user_defined")
	) {
		bail!("Ghidra symbol source is not an observed supported SourceType");
	}
	Ok(())
}

pub(super) fn validate(observation: &Value, selected: &str) -> Result<()> {
	if observation["upstream_operation"] != "read_function_instructions"
		|| observation["instruction_provenance"] != "ghidra-listing"
		|| observation["instruction_scope"] != "selected_function_body_address_set"
		|| observation["instructions_complete"] != true
		|| observation["omitted_instructions"] != 0
		|| observation["decompilation_performed"] != false
		|| observation["decompiler_invoked"] != false
		|| observation["instruction_timeout_seconds"] != 10
	{
		bail!("Ghidra instruction window lacks complete non-decompiler semantics");
	}
	let window = &observation["instruction_window"];
	object(
		window,
		&["procedure", "instructions", "limitations"],
		"Ghidra instruction window",
	)?;
	let procedure = &window["procedure"];
	object(
		procedure,
		&["address", "name", "symbol", "classification", "body"],
		"Ghidra instruction procedure identity",
	)?;
	if procedure["address"] != selected {
		bail!("Ghidra instruction window selected another procedure");
	}
	text(&procedure["name"], 1024, "Ghidra complete procedure name")?;
	symbol(&procedure["symbol"])?;
	let classification = &procedure["classification"];
	object(
		classification,
		&["external", "thunk", "thunk_target", "provenance"],
		"Ghidra instruction procedure classification",
	)?;
	let thunk = boolean(&classification["thunk"], "Ghidra thunk classification")?;
	if classification["external"] != false
		|| classification["provenance"] != "ghidra-function-manager"
		|| (!thunk && !classification["thunk_target"].is_null())
	{
		bail!("Ghidra instruction procedure is not an internal observed function");
	}
	if !classification["thunk_target"].is_null() {
		coordinate(text(
			&classification["thunk_target"],
			1050,
			"Ghidra thunk target",
		)?)?;
	}
	let ranges = body(&procedure["body"], &coordinate(selected)?)?;
	let complete_name = text(&procedure["name"], 1024, "Ghidra complete procedure name")?;
	if observation["function"]["entry_address"] != selected
		|| observation["function"]["external"] != false
		|| observation["function"]["thunk"].as_bool() != Some(thunk)
		|| observation["function"]["name_sha256"] != sha256(complete_name.as_bytes())
		|| observation["function"]["body_address_count"]
			!= procedure["body"]["total_bytes"].to_string()
	{
		bail!(
			"Ghidra complete instruction procedure differs from the selected function observation"
		);
	}
	let limitations = window["limitations"]
		.as_array()
		.context("Ghidra instruction limitations absent")?;
	if limitations.len() != LIMITATIONS.len()
		|| limitations
			.iter()
			.zip(LIMITATIONS)
			.any(|(actual, expected)| actual.as_str() != Some(expected))
	{
		bail!("Ghidra instruction window omitted its declared profile limitations");
	}
	let rows = window["instructions"]
		.as_array()
		.context("Ghidra instruction list absent")?;
	let bytes = observation["instruction_bytes"]
		.as_array()
		.context("Ghidra instruction bytes absent")?;
	if rows.len() > MAX_ROWS
		|| rows.len() != bytes.len()
		|| observation["instruction_count"].as_u64() != Some(rows.len() as u64)
	{
		bail!("Ghidra complete instruction/byte row counts disagree");
	}
	let mut complete_text = Vec::with_capacity(rows.len());
	let mut text_bytes = 0usize;
	let mut previous: Option<(usize, u64)> = None;
	for (row, encoded) in rows.iter().zip(bytes) {
		let line = text(row, 4096, "Ghidra complete Listing line")?;
		text_bytes = text_bytes
			.checked_add(if complete_text.is_empty() { 0 } else { 1 })
			.and_then(|count| count.checked_add(line.len()))
			.context("Ghidra joined instruction text byte count overflows")?;
		if text_bytes > MAX_TEXT_BYTES {
			bail!("Ghidra complete instruction text exceeds its fixed byte budget");
		}
		let (at, instruction) = line
			.split_once(": ")
			.context("Ghidra Listing line lacks address separator")?;
		if instruction.is_empty() {
			bail!("Ghidra Listing line has no instruction text");
		}
		let at = coordinate(at)?;
		object(
			encoded,
			&["address", "length", "bytes_hex"],
			"Ghidra instruction byte row",
		)?;
		if encoded["address"].as_str() != line.split_once(": ").map(|(address, _)| address) {
			bail!("Ghidra instruction text/byte coordinates disagree");
		}
		let length = encoded["length"]
			.as_u64()
			.context("Ghidra instruction length absent")?;
		let hex = encoded["bytes_hex"]
			.as_str()
			.context("Ghidra instruction bytes absent")?;
		if length == 0
			|| length > 1024
			|| hex.len() != length as usize * 2
			|| !hex
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
		{
			bail!("Ghidra instruction bytes disagree with its bounded length");
		}
		let end = at
			.offset
			.checked_add(length - 1)
			.context("Ghidra instruction endpoint overflows")?;
		let range_index = ranges
			.iter()
			.position(|range| {
				range.start.space == at.space && range.start.offset <= at.offset && end <= range.end
			})
			.context("Ghidra instruction crosses or lies outside the selected complete body")?;
		if previous.is_some_and(|(index, last)| {
			range_index < index || (range_index == index && at.offset <= last)
		}) {
			bail!("Ghidra instruction rows overlap or are unordered");
		}
		previous = Some((range_index, end));
		complete_text.push(line);
	}
	let text = complete_text.join("\n");
	if text.len() != text_bytes
		|| text.len() > MAX_TEXT_BYTES
		|| observation["instruction_text_utf8_bytes"].as_u64() != Some(text.len() as u64)
		|| observation["instruction_text_sha256"] != sha256(text.as_bytes())
	{
		bail!("Ghidra complete instruction text identity differs");
	}
	Ok(())
}

#[cfg(test)]
#[path = "rea_ghidra_instructions_tests.rs"]
mod tests;
