// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Shared admission and observation checks for bounded Ghidra analysis.
//! Legacy and revision 2 bridges retain their bytes; revision 3 selects the fixed Ghidra 12.1.4 engine.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use super::{is_sha256, sha256, ReaStaticRequest, StaticOperation, StaticProvider, WorkerRequest};

pub(crate) const ANALYSIS_PROFILE: &str = "hepta.ghidra.elf-functions.v1";
pub(crate) const ANALYSIS_PROFILE_1214: &str = "hepta.ghidra.12.1.4.elf-functions.v1";
pub(crate) const ANALYZERS: [&str; 4] = [
	"Disassemble Entry Points",
	"Function Start Search",
	"Stack",
	"Subroutine References",
];

pub(crate) fn operation_name(operation: StaticOperation) -> Result<&'static str> {
	match operation {
		StaticOperation::Inventory => Ok("inventory"),
		StaticOperation::Functions => Ok("functions"),
		StaticOperation::Function => Ok("function"),
		StaticOperation::Decompile => Ok("decompile"),
		StaticOperation::Xrefs => Ok("xrefs"),
		_ => bail!("unsupported fixed Ghidra operation"),
	}
}

pub(crate) fn bridge(operation: StaticOperation, revision: Option<u32>) -> Result<&'static str> {
	match (revision, operation) {
		(None, StaticOperation::Inventory) => Ok(include_str!("rea_ghidra_bridge.java")),
		(Some(2), StaticOperation::Inventory) => Ok(include_str!("rea_ghidra_inventory_v2.java")),
		(Some(2), operation) => {
			operation_name(operation)?;
			Ok(include_str!("rea_ghidra_analysis_bridge.java"))
		}
		(Some(3), StaticOperation::Inventory) => {
			Ok(include_str!("rea_ghidra_inventory_1214_v3.java"))
		}
		(Some(3), operation) => {
			operation_name(operation)?;
			Ok(include_str!("rea_ghidra_analysis_1214_v3.java"))
		}
		_ => bail!("Ghidra operation requires an admitted bridge revision"),
	}
}

pub(crate) fn valid_address(address: &str) -> bool {
	let Some(hex) = address.strip_prefix("0x") else {
		return false;
	};
	!hex.is_empty()
		&& hex.len() <= 16
		&& (hex == "0" || !hex.starts_with('0'))
		&& hex
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn validate_selection(
	provider: StaticProvider,
	request: &ReaStaticRequest,
) -> Result<()> {
	let selected = matches!(
		request.operation,
		StaticOperation::Function | StaticOperation::Decompile | StaticOperation::Xrefs
	);
	if provider == StaticProvider::Ghidra && selected {
		if !request
			.function_address
			.as_deref()
			.is_some_and(valid_address)
		{
			bail!("Ghidra selected-function operations require one canonical lowercase 0x entry address");
		}
	} else if request.function_address.is_some() {
		bail!("a function address is admitted only for a selected Ghidra function operation");
	}
	Ok(())
}

fn function_row(row: &Value, expected: Option<&str>) -> Result<()> {
	let address = row["entry_address"]
		.as_str()
		.context("Ghidra function entry absent")?;
	if !valid_address(address)
		|| expected.is_some_and(|value| value != address)
		|| row["external"] != false
		|| row["name"].as_str().is_none_or(|s| s.len() > 1024)
		|| row["name_sha256"].as_str().is_none_or(|s| !is_sha256(s))
	{
		bail!("Ghidra function observation is not bound to a bounded internal entry");
	}
	Ok(())
}

fn counted_rows(observation: &Value, rows: &str, returned: &str, maximum: usize) -> Result<()> {
	let values = observation[rows]
		.as_array()
		.context("Ghidra observation rows absent")?;
	if values.len() > maximum || observation[returned].as_u64() != Some(values.len() as u64) {
		bail!("Ghidra observation row count is inconsistent");
	}
	Ok(())
}

pub(crate) fn validate_observation(
	observation: &Value,
	input: &WorkerRequest,
	source_bytes: u64,
) -> Result<()> {
	let operation = input.request.operation;
	let name = operation_name(operation)?;
	let engine = input
		.profile
		.ghidra_engine
		.as_ref()
		.context("Ghidra installation identity absent")?;
	let revision = engine.bridge_revision;
	let (version, release_sha256) = super::engine_profile::release_identity(revision)?;
	bridge(operation, revision)?;
	if engine.engine_version != version
		|| engine.release_archive_sha256 != release_sha256
		|| observation["engine_version"] != version
		|| observation["operation"] != name
		|| observation["target_executed"] != false
		|| observation["external_libraries_loaded"] != false
		|| observation["project_saved"] != false
	{
		bail!("Ghidra observation does not match its admitted fixed semantics");
	}
	if operation == StaticOperation::Inventory {
		let schema = if revision.is_some() {
			"hepta.rea.ghidra-observation.v2"
		} else {
			"hepta.rea.ghidra-observation.v1"
		};
		if revision.is_some()
			&& (observation["bridge_revision"].as_u64() != revision.map(u64::from)
				|| observation["source_sha256"] != input.request.artifact_sha256
				|| observation["source_bytes"].as_u64() != Some(source_bytes))
		{
			bail!("Ghidra inventory bridge or source identity mismatch");
		}
		if observation["schema"] != schema
			|| observation["auto_analysis_performed"] != false
			|| observation["decompilation_performed"] != false
		{
			bail!("Ghidra inventory must preserve its original import-only semantics");
		}
		return Ok(());
	}
	validate_selection(input.profile.provider, &input.request)?;
	let analysis_profile = if revision == Some(3) {
		ANALYSIS_PROFILE_1214
	} else {
		ANALYSIS_PROFILE
	};
	if observation["schema"] != "hepta.rea.ghidra-analysis.v1"
		|| observation["bridge_revision"].as_u64() != revision.map(u64::from)
		|| observation["analysis_profile"] != analysis_profile
		|| observation["enabled_analyzers"] != json!(ANALYZERS)
		|| observation["analysis_completed"] != true
		|| observation["auto_analysis_performed"] != true
		|| observation["decompilation_performed"] != (operation == StaticOperation::Decompile)
		|| observation["source_semantics_validated"] != false
		|| observation["source_sha256"] != input.request.artifact_sha256
		|| observation["source_bytes"].as_u64() != Some(source_bytes)
		|| source_bytes > input.profile.max_artifact_bytes
		|| observation["function_address_requested"]
			!= serde_json::to_value(&input.request.function_address)?
		|| observation["coverage"] != "partial"
	{
		bail!("Ghidra analysis identity, completion, selected address or coverage mismatch");
	}
	if operation == StaticOperation::Functions {
		counted_rows(observation, "functions", "returned_functions", 128)?;
		for row in observation["functions"]
			.as_array()
			.context("Ghidra function rows absent")?
		{
			function_row(row, None)?;
		}
		let scanned = observation["scanned_functions"]
			.as_u64()
			.context("Ghidra scan count absent")?;
		let returned = observation["returned_functions"]
			.as_u64()
			.context("Ghidra return count absent")?;
		if scanned > 4096
			|| scanned < returned
			|| observation["omitted_functions_in_scan"].as_u64() != Some(scanned - returned)
			|| observation["function_scan_complete"].as_bool().is_none()
		{
			bail!("Ghidra function scan counts or completeness are inconsistent");
		}
	} else {
		function_row(
			&observation["function"],
			input.request.function_address.as_deref(),
		)?;
	}
	if operation == StaticOperation::Xrefs {
		for prefix in ["incoming", "outgoing"] {
			counted_rows(
				observation,
				&format!("{prefix}_references"),
				&format!("returned_{prefix}_references"),
				128,
			)?;
			let scanned = observation[format!("scanned_{prefix}_references")]
				.as_u64()
				.context("Ghidra xref scan count absent")?;
			let returned = observation[format!("returned_{prefix}_references")]
				.as_u64()
				.context("Ghidra xref return count absent")?;
			if scanned > 4096
				|| scanned < returned
				|| observation[format!("omitted_{prefix}_references_in_scan")].as_u64()
					!= Some(scanned - returned)
				|| observation[format!("{prefix}_scan_complete")]
					.as_bool()
					.is_none()
			{
				bail!("Ghidra cross-reference counts or completeness are inconsistent");
			}
		}
	}
	if operation == StaticOperation::Decompile {
		let code = observation["c_code"]
			.as_str()
			.context("Ghidra C observation absent")?;
		let complete = observation["c_code_complete"]
			.as_bool()
			.context("Ghidra C completeness absent")?;
		let total = observation["c_code_utf8_bytes"]
			.as_u64()
			.context("Ghidra C byte count absent")?;
		if code.len() > 32768
			|| total < code.len() as u64
			|| total > 1024 * 1024
			|| observation["c_code_preview_sha256"] != sha256(code.as_bytes())
			|| observation["c_code_sha256"]
				.as_str()
				.is_none_or(|s| !is_sha256(s))
			|| (complete
				&& (total != code.len() as u64
					|| observation["c_code_sha256"] != sha256(code.as_bytes())))
			|| observation["decompilation_completed"] != true
			|| observation["native_child_cleanup_confirmed"] != true
			|| observation["observed_native_children"]
				.as_u64()
				.is_none_or(|count| count == 0)
		{
			bail!("Ghidra decompilation output, digest, completeness or cleanup mismatch");
		}
	}
	Ok(())
}

#[cfg(test)]
#[path = "rea_ghidra_contract_tests.rs"]
mod tests;
