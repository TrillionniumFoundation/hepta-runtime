// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Revision 4 checks for exact body membership, reference accounting and external functions.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;

use super::{counted_rows, function_row, is_sha256, sha256, valid_address};

const MAX_BODY_RANGES: usize = 128;

pub(super) fn validate_analysis_options(observation: &Value) -> Result<()> {
	if observation["language_id"] != "x86:LE:64:default"
		|| observation["compiler_spec_id"] != "gcc"
		|| observation["enabled_analyzers"] != serde_json::json!(super::ANALYZERS_1214_V4)
		|| observation["disabled_analyzers"] != serde_json::json!(super::DISABLED_ANALYZERS_1214_V4)
		|| observation["disabled_analyzer_count"].as_u64() != Some(4)
		|| observation["disabled_analyzers_sha256"]
			!= sha256(&serde_json::to_vec(&super::DISABLED_ANALYZERS_1214_V4)?)
		|| observation["analysis_options_format"] != super::OPTIONS_FORMAT_1214_V4
		|| observation["analysis_option_count"].as_u64() != Some(146)
		|| observation["analysis_options_sha256"] != super::OPTIONS_SHA256_1214_V4
		|| observation["analysis_options_unchanged"] != true
		|| observation["no_return_repair_applied"] != false
	{
		bail!("Ghidra revision 4 requires its fixed x86_64/gcc default-option identity");
	}
	Ok(())
}

pub(super) fn validate_native_cleanup(observation: &Value, selected_decompile: bool) -> Result<()> {
	let children = observation["native_children"]
		.as_array()
		.context("Ghidra native child observations absent")?;
	if observation["decompilation_scope"] != "explicit_selected_function"
		|| observation["auto_analysis_may_decompile"] != true
		|| observation["native_child_cleanup_scope"] != "private_bridge_jvm_all_descendants"
		|| observation["native_helper_observation_scope"] != "live_descendants_at_phase_boundaries"
		|| observation["native_child_cleanup_confirmed"] != true
		|| children.len() > 64
		|| observation["observed_native_children"].as_u64() != Some(children.len() as u64)
	{
		bail!("Ghidra native helper scope, count or cleanup confirmation is inconsistent");
	}
	let mut identities = BTreeSet::new();
	let mut decompilers = 0u64;
	let mut candidates = 0u64;
	for child in children {
		let pid = child["pid"].as_u64().context("native child PID absent")?;
		let parent = child["parent_pid"]
			.as_u64()
			.context("native parent PID absent")?;
		let ticks = child["start_ticks"]
			.as_str()
			.context("native start ticks absent")?;
		let tick_value = ticks.parse::<u64>().context("invalid native start ticks")?;
		let started = child["start_instant"]
			.as_str()
			.context("native start instant absent")?;
		let command = child["command"]
			.as_str()
			.context("native child command absent")?;
		let candidate = child["explicit_decompiler_candidate"]
			.as_bool()
			.context("native role inference absent")?;
		let phase = child["first_observed_phase"]
			.as_str()
			.context("native observation phase absent")?;
		let decompiler = command.rsplit('/').next() == Some("decompile");
		let role = if candidate {
			"explicit_decompiler_candidate"
		} else if decompiler {
			"auto_analysis_decompiler_candidate"
		} else {
			"other_engine_helper"
		};
		if pid == 0
			|| pid > u64::from(u32::MAX)
			|| parent == 0
			|| parent == pid
			|| tick_value == 0
			|| tick_value.to_string() != ticks
			|| !identities.insert((pid, tick_value))
			|| started.is_empty()
			|| started.len() > 64
			|| !started.ends_with('Z')
			|| command.is_empty()
			|| command.len() > 4096
			|| child["role_attribution"] != "phase_and_executable_inference"
			|| child["role"] != role
			|| !matches!(
				phase,
				"after_analysis"
					| "before_selected_decompiler_open"
					| "selected_decompiler_open"
					| "before_program_release"
					| "after_program_release"
			) || (candidate && (!decompiler || phase != "selected_decompiler_open"))
			|| child["state_before_cleanup"]
				.as_str()
				.is_none_or(|value| value.is_empty() || value.len() > 32)
			|| !child["term_sent"].is_boolean()
			|| !child["kill_sent"].is_boolean()
			|| child["exit_confirmed"] != true
			|| !matches!(
				child["final_state"].as_str(),
				Some("absent" | "identity_changed")
			) || (!child["failure"].is_null()
			&& child["failure"]
				.as_str()
				.is_none_or(|value| value.len() > 2048))
		{
			bail!("Ghidra native helper identity, inferred role or final exit is inconsistent");
		}
		if decompiler {
			decompilers += 1;
		}
		if candidate {
			candidates += 1;
		}
	}
	if observation["observed_native_decompiler_children"].as_u64() != Some(decompilers)
		|| observation["observed_explicit_decompiler_candidates"].as_u64() != Some(candidates)
		|| (selected_decompile && decompilers == 0)
		|| (!selected_decompile && candidates != 0)
	{
		bail!("Ghidra native decompiler observations disagree with the selected operation");
	}
	Ok(())
}

fn offset(address: &str) -> Result<u64> {
	if !valid_address(address) {
		bail!("Ghidra memory offset is not canonical");
	}
	u64::from_str_radix(&address[2..], 16).context("Ghidra memory offset is outside u64")
}

fn observed_offset(value: &Value) -> Result<u64> {
	offset(value.as_str().context("Ghidra memory address absent")?)
}

fn names(row: &Value) -> Result<()> {
	for (field, maximum) in [("name", 1024), ("signature", 4096)] {
		let text = row[field].as_str().context("Ghidra function text absent")?;
		let complete = row[format!("{field}_complete")]
			.as_bool()
			.context("Ghidra function text completeness absent")?;
		let digest = row[format!("{field}_sha256")]
			.as_str()
			.context("Ghidra function text digest absent")?;
		if text.len() > maximum
			|| !is_sha256(digest)
			|| (complete && digest != sha256(text.as_bytes()))
		{
			bail!("Ghidra function text digest or budget is inconsistent");
		}
	}
	if !row["thunk"].is_boolean() {
		bail!("Ghidra function thunk flag absent");
	}
	Ok(())
}

pub(super) fn validate_selected(observation: &Value, selected: &str) -> Result<()> {
	let row = &observation["function"];
	function_row(row, None)?;
	names(row)?;
	let selected_offset = offset(selected)?;
	let entry = observed_offset(&row["entry_address"])?;
	let ranges = row["body_ranges"]
		.as_array()
		.context("Ghidra selected function ranges absent")?;
	if ranges.is_empty()
		|| ranges.len() > MAX_BODY_RANGES
		|| row["body_range_count"].as_u64() != Some(ranges.len() as u64)
		|| row["body_ranges_complete"] != true
	{
		bail!("Ghidra selected function requires its complete bounded body ranges");
	}
	let mut previous_end = None;
	let mut first_start = None;
	let mut count = 0u128;
	let mut contains_selected = false;
	let mut contains_entry = false;
	for range in ranges {
		if range.as_object().is_none_or(|object| object.len() != 2) {
			bail!("Ghidra body range must contain only its two endpoints");
		}
		let start = observed_offset(&range["min_address"])?;
		let end = observed_offset(&range["max_address"])?;
		if start > end || previous_end.is_some_and(|previous| start <= previous) {
			bail!("Ghidra body ranges overlap or are not in address order");
		}
		first_start.get_or_insert(start);
		previous_end = Some(end);
		count += u128::from(end) - u128::from(start) + 1;
		contains_selected |= start <= selected_offset && selected_offset <= end;
		contains_entry |= start <= entry && entry <= end;
	}
	let declared_count = row["body_address_count"]
		.as_str()
		.context("Ghidra body address count absent")?;
	let resolution = if selected_offset == entry {
		"entry"
	} else {
		"containing"
	};
	if !contains_selected
		|| !contains_entry
		|| count > u128::from(u64::MAX)
		|| declared_count != count.to_string()
		|| Some(observed_offset(&row["body_min_address"])?) != first_start
		|| Some(observed_offset(&row["body_max_address"])?) != previous_end
		|| observation["function_resolution"] != resolution
	{
		bail!("Ghidra requested address, resolved entry or complete body ranges disagree");
	}
	Ok(())
}

pub(super) fn validate_functions(observation: &Value) -> Result<()> {
	if observation["function_inventory_scope"] != "internal_and_external_separate" {
		bail!("Ghidra revision 4 must keep internal and external inventories distinct");
	}
	let internal = observation["functions"]
		.as_array()
		.context("Ghidra internal function rows absent")?;
	let mut internal_entries = BTreeSet::new();
	for row in internal {
		function_row(row, None)?;
		names(row)?;
		if !internal_entries.insert(observed_offset(&row["entry_address"])?) {
			bail!("Ghidra internal function inventory duplicates an entry");
		}
	}
	counted_rows(
		observation,
		"external_functions",
		"returned_external_functions",
		128,
	)?;
	let external = observation["external_functions"]
		.as_array()
		.context("Ghidra external function rows absent")?;
	let mut external_entries = BTreeSet::new();
	for row in external {
		let address = row["entry_address"]
			.as_str()
			.and_then(|value| value.strip_prefix("EXTERNAL:"))
			.context("Ghidra external entry must retain its EXTERNAL address space")?;
		if row["external"] != true || !external_entries.insert(offset(address)?) {
			bail!("Ghidra external function identity is inconsistent or duplicated");
		}
		names(row)?;
	}
	for (scan, returned, omitted, complete) in [
		(
			"scanned_functions",
			"returned_functions",
			"omitted_functions_in_scan",
			"function_scan_complete",
		),
		(
			"scanned_external_functions",
			"returned_external_functions",
			"omitted_external_functions_in_scan",
			"external_function_scan_complete",
		),
	] {
		let scanned = observation[scan]
			.as_u64()
			.context("Ghidra function scan count absent")?;
		let returned = observation[returned]
			.as_u64()
			.context("Ghidra returned count absent")?;
		let complete = observation[complete]
			.as_bool()
			.context("Ghidra function completeness absent")?;
		if scanned > 4096
			|| scanned < returned
			|| (!complete && scanned != 4096)
			|| observation[omitted].as_u64() != Some(scanned - returned)
		{
			bail!("Ghidra function inventory counts or completeness are inconsistent");
		}
	}
	Ok(())
}

fn encoded_reference_space(space: &str) -> String {
	const HEX: &[u8; 16] = b"0123456789ABCDEF";
	let mut encoded = String::new();
	for byte in space.bytes() {
		if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-') {
			encoded.push(char::from(byte));
		} else {
			encoded.push('%');
			encoded.push(char::from(HEX[usize::from(byte >> 4)]));
			encoded.push(char::from(HEX[usize::from(byte & 15)]));
		}
	}
	encoded
}

fn reference_endpoint<'a>(
	row: &'a Value,
	address_field: &str,
	space_field: &str,
) -> Result<(&'a str, &'a str, u64)> {
	let address = row[address_field]
		.as_str()
		.context("Ghidra reference address absent")?;
	let space = row[space_field]
		.as_str()
		.filter(|value| !value.is_empty())
		.context("Ghidra reference address space absent")?;
	let value = if space == "ram" {
		address
	} else {
		let prefix = format!("{}:", encoded_reference_space(space));
		address
			.strip_prefix(&prefix)
			.context("Ghidra reference space prefix is not its canonical UTF-8 encoding")?
	};
	Ok((address, space, offset(value)?))
}

fn reference_in_selected_scope(observation: &Value, address: u64) -> Result<bool> {
	let function = &observation["function"];
	if address == observed_offset(&function["entry_address"])? {
		return Ok(true);
	}
	for range in function["body_ranges"]
		.as_array()
		.context("Ghidra reference body ranges absent")?
	{
		if observed_offset(&range["min_address"])? <= address
			&& address <= observed_offset(&range["max_address"])?
		{
			return Ok(true);
		}
	}
	Ok(false)
}

pub(super) fn validate_xrefs(observation: &Value) -> Result<()> {
	for (field, expected) in [
		("incoming_scope", "selected_function_body_and_entry"),
		("outgoing_scope", "selected_function_body_and_entry"),
		("reference_default_address_space", "ram"),
		(
			"reference_address_format",
			"default-space-hex-or-utf8-space-unsigned64.v1",
		),
		("reference_filter", "exclude-isEntryPointReference"),
		("reference_deduplication", "from,to,type,operand,primary"),
		(
			"reference_order",
			"ghidra-address-from-to-type-operand-primary",
		),
		(
			"reference_scan_accounting",
			"raw-includes-entrypoint-filter-and-duplicates.v1",
		),
	] {
		if observation[field] != expected {
			bail!("Ghidra revision 4 reference scope or encoding is inconsistent");
		}
	}
	for direction in ["incoming", "outgoing"] {
		let rows_field = format!("{direction}_references");
		counted_rows(
			observation,
			&rows_field,
			&format!("returned_{direction}_references"),
			128,
		)?;
		let rows = observation[&rows_field]
			.as_array()
			.context("Ghidra reference rows absent")?;
		let count = |field: &str| -> Result<u64> {
			observation[field]
				.as_u64()
				.context("Ghidra reference accounting requires unsigned integer counts")
		};
		let raw = count(&format!("scanned_{direction}_references"))?;
		let filtered = count(&format!("filtered_{direction}_entry_point_references"))?;
		let duplicate = count(&format!("duplicate_{direction}_references_in_scan"))?;
		let unique = count(&format!("unique_{direction}_references_in_scan"))?;
		let omitted = count(&format!("omitted_{direction}_references_in_scan"))?;
		let budget_omitted = count(&format!("budget_omitted_{direction}_references"))?;
		let returned = rows.len() as u64;
		let complete = observation[format!("{direction}_scan_complete")]
			.as_bool()
			.context("Ghidra reference scan completeness absent")?;
		if raw > 4096
			|| filtered > raw
			|| duplicate > raw
			|| unique > raw
			|| (duplicate != 0 && unique == 0)
			|| filtered
				.checked_add(duplicate)
				.and_then(|sum| sum.checked_add(unique))
				!= Some(raw)
			|| returned.checked_add(budget_omitted) != Some(unique)
			|| raw.checked_sub(returned) != Some(omitted)
			|| (!complete && raw != 4096)
		{
			bail!("Ghidra raw, filtered, duplicate, unique or budget reference counts disagree");
		}
		let mut identities = BTreeSet::new();
		for row in rows {
			let (from, from_space, from_offset) =
				reference_endpoint(row, "from_address", "from_space")?;
			let (to, to_space, to_offset) = reference_endpoint(row, "to_address", "to_space")?;
			let kind = row["reference_type"]
				.as_str()
				.filter(|value| !value.is_empty())
				.context("Ghidra reference type name absent")?;
			let operand = i32::try_from(
				row["operand_index"]
					.as_i64()
					.context("Ghidra reference operand absent")?,
			)
			.context("Ghidra reference operand exceeds the Java integer range")?;
			let primary = row["primary"]
				.as_bool()
				.context("Ghidra reference primary flag absent")?;
			let (owned_space, owned_offset) = if direction == "incoming" {
				(to_space, to_offset)
			} else {
				(from_space, from_offset)
			};
			if row["entry_point_reference"] != false
				|| !row["call"].is_boolean()
				|| row["source_type"].as_str().is_none_or(str::is_empty)
				|| owned_space != "ram"
				|| !reference_in_selected_scope(observation, owned_offset)?
				|| !identities.insert((from, to, kind, operand, primary))
			{
				bail!("Ghidra reference is synthetic, duplicated or outside the selected body and entry");
			}
		}
		// Ordering uses Ghidra Address.compareTo, including its address-space semantics.
		// The fixed engine oracle checks that order; encoded names cannot reconstruct it here.
	}
	Ok(())
}

#[cfg(test)]
#[path = "rea_ghidra_contract_v4_tests.rs"]
mod tests;
