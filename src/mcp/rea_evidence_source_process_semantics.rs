// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Cross-field commitments, ordering, journal and finalization invariants.

use super::*;

pub(super) fn validate(capture: &Value, v: &mut Validation<'_>) -> SourceResult<()> {
	issue(
		v,
		capture["settlement"]["cleanup_outcome"] != "failed",
		"settlement.cleanup_outcome",
		"verified captures cannot contain failed cleanup",
	);
	commitments(capture, v)?;
	ordering(capture, v);
	journal(capture, v);
	lifecycle(capture, v);
	coverage::validate(capture, v);
	Ok(())
}

fn commitments(capture: &Value, v: &mut Validation<'_>) -> SourceResult<()> {
	let manifest = &capture["manifest"];
	issue(
		v,
		js_equal(
			manifest["scenario"].get("executable_sha256"),
			manifest.get("selected_executable_sha256"),
		),
		"manifest.selected_executable_sha256",
		"selected executable commitment does not match the scenario projection",
	);
	let identity = &manifest["executable_identity"];
	let agrees = if identity["state"] == "path_metadata_unchanged" {
		js_equal(
			manifest.get("executable_sha256"),
			manifest.get("selected_executable_sha256"),
		) && identity["reason"].is_null()
	} else {
		manifest["executable_sha256"].is_null() && !identity["reason"].is_null()
	};
	issue(
		v,
		agrees,
		"manifest.executable_identity",
		"launch identity and executable digest do not agree",
	);
	for (field, digest) in [
		(
			"full_scenario_sha256",
			record_digest(&manifest["scenario"])?,
		),
		(
			"comparison_contract_sha256",
			record_digest(&manifest["comparison_contract"])?,
		),
		(
			"normalization_sha256",
			normalization_digest(&capture["normalization"])?,
		),
	] {
		issue(
			v,
			manifest[field].as_str() == Some(&digest),
			&format!("manifest.{field}"),
			"commitment does not match its canonical value",
		);
	}
	Ok(())
}

fn ordered(values: &[Value], field: &str) -> bool {
	values
		.windows(2)
		.all(|pair| number(&pair[1][field]) >= number(&pair[0][field]))
}

fn ordering(capture: &Value, v: &mut Validation<'_>) {
	for name in ["frames", "rendered_frames", "interaction_events"] {
		issue(
			v,
			rows(&capture[name])
				.iter()
				.enumerate()
				.all(|(index, item)| number(&item["sequence"]) == index as f64),
			name,
			"sequence values must be contiguous from zero",
		);
	}
	for name in ["frames", "rendered_frames", "process_samples"] {
		issue(
			v,
			ordered(rows(&capture[name]), "at_ms"),
			name,
			"timestamps must be ordered",
		);
	}
	issue(
		v,
		ordered(rows(&capture["interaction_events"]), "dispatched_at_ms"),
		"interaction_events",
		"dispatch timestamps must be ordered",
	);
}

fn journal(capture: &Value, v: &mut Validation<'_>) {
	let journal = rows(&capture["event_journal"]);
	if journal.is_empty() {
		return;
	}
	let mut references = BTreeSet::new();
	for (position, entry) in journal.iter().enumerate() {
		let collection = entry["collection"].as_str().unwrap_or("");
		let size = if collection == "lifecycle" {
			2
		} else {
			rows(&capture[collection]).len()
		};
		issue(
			v,
			number(&entry["capture_order"]) == position as f64,
			&format!("event_journal.{position}.capture_order"),
			"capture order must be contiguous from zero",
		);
		let index = number(&entry["index"]);
		issue(
			v,
			index < size as f64,
			&format!("event_journal.{position}.index"),
			"journal reference is outside its capture collection",
		);
		// JavaScript String(-0) is "0" and JSON numeric spelling is not identity.
		let bits = if index == 0.0 {
			0.0f64.to_bits()
		} else {
			index.to_bits()
		};
		issue(
			v,
			references.insert((collection, bits)),
			&format!("event_journal.{position}"),
			"journal references must be unique",
		);
	}
	let size: usize = COLLECTIONS
		.iter()
		.map(|collection| {
			if *collection == "lifecycle" {
				2
			} else {
				rows(&capture[*collection]).len()
			}
		})
		.sum();
	issue(
		v,
		journal.len() == size,
		"event_journal",
		"nonempty journal must reference every captured observation",
	);
}

fn lifecycle(capture: &Value, v: &mut Validation<'_>) {
	let checkpoints = rows(&capture["filesystem_checkpoints"]);
	issue(
		v,
		checkpoints.len() == 2
			&& checkpoints[0]["name"] == "before"
			&& checkpoints[1]["name"] == "after_settlement",
		"filesystem_checkpoints",
		"capture must include initial and final filesystem snapshots",
	);
	issue(
		v,
		ordered(checkpoints, "at_ms"),
		"filesystem_checkpoints",
		"filesystem snapshot times must be ordered",
	);
	issue(
		v,
		!checkpoints.iter().any(|item| item["truncated"] == true) || capture["truncated"] == true,
		"truncated",
		"filesystem snapshot truncation must propagate to the capture",
	);
	issue(
		v,
		capture["exit"]["reason"] == "exited" || capture["exit"]["code"].is_null(),
		"exit",
		"deadline termination cannot declare a normal exit code",
	);
	if let Some(message) = finalization_issue(
		&capture["exit"],
		&capture["manifest"]["scenario"],
		&capture["manifest"]["comparison_contract"],
	) {
		issue(v, false, "exit", message);
	}
}

fn finalization_issue(exit: &Value, scenario: &Value, comparison: &Value) -> Option<&'static str> {
	if !js_equal(
		scenario.get("finalization_ms"),
		comparison.get("finalization_ms"),
	) {
		return Some("comparison_contract finalization_ms must match the committed scenario");
	}
	let Some(finalization) = exit.get("finalization") else {
		return if matches!(exit["reason"].as_str(), Some("timeout" | "idle_timeout"))
			&& scenario
				.get("finalization_ms")
				.and_then(Value::as_f64)
				.is_some_and(|value| value > 0.0)
		{
			Some("a deadline exit under a committed finalization_ms requires finalization evidence")
		} else {
			None
		};
	};
	if exit["reason"] == "exited" {
		return Some("finalization requires a deadline exit reason");
	}
	let signals = rows(&finalization["signals"]);
	if signals
		.first()
		.is_none_or(|first| first["signal"] != "SIGTERM")
	{
		return Some("finalization signals must start with SIGTERM");
	}
	let kills: Vec<_> = signals
		.iter()
		.enumerate()
		.filter(|(_, signal)| signal["signal"] == "SIGKILL")
		.collect();
	if kills.len() > 1
		|| kills
			.first()
			.is_some_and(|(index, _)| *index != signals.len() - 1)
	{
		return Some("finalization may contain at most one final SIGKILL");
	}
	if !ordered(signals, "sent_at_ms") {
		return Some("finalization signal attempt times must not decrease");
	}
	if signals
		.iter()
		.filter(|signal| signal["signal"] == "SIGTERM")
		.count()
		!= 1
	{
		return Some("finalization must attempt SIGTERM exactly once");
	}
	if kills.first().is_some_and(|(_, signal)| {
		number(&signal["sent_at_ms"]) < number(&finalization["requested_ms"])
	}) && exit["reason"] != "cancelled"
	{
		return Some("finalization SIGKILL cannot precede the requested interval");
	}
	if finalization["elapsed_ms"].is_null() {
		return Some("finalization requires an observed elapsed_ms");
	}
	if !finalization["exit_code"].is_null()
		&& !exit["signal"].is_null()
		&& number(&exit["signal"]) != 0.0
	{
		return Some("finalization exit_code requires an exit not caused by a signal");
	}
	if signals
		.last()
		.is_some_and(|last| number(&finalization["elapsed_ms"]) < number(&last["sent_at_ms"]))
	{
		return Some("finalization elapsed_ms cannot precede the last signal attempt");
	}
	if !js_equal(
		scenario.get("finalization_ms"),
		finalization.get("requested_ms"),
	) {
		return Some("finalization must match the committed finalization_ms");
	}
	None
}
