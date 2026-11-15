// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Deterministic selected-field mapping from the retained, pinned GNU output.
//! This is not an independent ELF parser or an upstream Evidence conversion.

use super::{StaticOperation, StaticProvider};
use serde_json::{json, Value};

const MAX_OBSERVATIONS: usize = 64;

pub(crate) fn selected_fields(
	provider: StaticProvider,
	operation: StaticOperation,
	stdout: &str,
	backend_success: bool,
) -> Value {
	let supported = backend_success
		&& provider == StaticProvider::GnuReadelf
		&& matches!(operation, StaticOperation::Headers | StaticOperation::Notes);
	let mut observations = Vec::new();
	let mut candidates = 0usize;
	let mut unmapped = 0usize;
	if supported {
		for (index, line) in stdout.lines().enumerate() {
			let Some((label, value)) = line.trim().split_once(':') else {
				continue;
			};
			let value = value.trim();
			let field = match (operation, label) {
				(StaticOperation::Headers, "Class") => "elf_class",
				(StaticOperation::Headers, "Data") => "elf_data_encoding",
				(StaticOperation::Headers, "OS/ABI") => "elf_os_abi",
				(StaticOperation::Headers, "ABI Version") => "elf_abi_version",
				(StaticOperation::Headers, "Type") => "elf_type",
				(StaticOperation::Headers, "Machine") => "elf_machine_label",
				(StaticOperation::Headers, "Entry point address") => "elf_entry_point_text",
				(StaticOperation::Notes, "Build ID") => "gnu_build_id_hex",
				_ => continue,
			};
			candidates += 1;
			if value.is_empty()
				|| value.len() > 512
				|| (field == "gnu_build_id_hex"
					&& (!value.len().is_multiple_of(2)
						|| !value.bytes().all(|b| b.is_ascii_hexdigit())))
			{
				unmapped += 1;
				continue;
			}
			if observations.len() < MAX_OBSERVATIONS {
				observations.push(json!({"field":field,"value":value,"stdout_line":index+1}));
			}
		}
	}
	let retained = observations.len();
	json!({
		"schema":"hepta.rea.static-summary.v1",
		"scope":"selected_gnu_readelf_text_fields",
		"mapping_supported":supported,
		"observations":observations,
		"candidate_count":candidates,"unmapped_candidate_count":unmapped,
		"truncated":candidates.saturating_sub(unmapped)>retained,
		"independent_binary_validation":false,"upstream_contract_equivalent":false,
		"limitations":["Values are observations of retained GNU stdout and identify their original line",
			"No ELF physical ranges, note descriptor hashes, table completeness or loader behavior are inferred",
			"An absent mapped field is not proof of absence from the artifact"]
	})
}

#[cfg(test)]
#[path = "rea_static_summary_tests.rs"]
mod tests;
