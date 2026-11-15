// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Producer accounting and filesystem omissions for frozen process captures.

use super::*;

const ENUMERATION: &[&str] = &[
	"identity_changed",
	"directory_unavailable",
	"entry_unavailable",
	"symlink_not_followed",
];
const ENUMERATION_REASONS: &[&str] = &[
	"files_limit",
	"depth_limit",
	"identity_changed",
	"directory_unavailable",
	"entry_unavailable",
	"symlink_not_followed",
];

pub(super) fn details(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	for key in ["raw_terminal", "rendered_terminal"] {
		retention(map.get(key), &child(path, key), v);
	}
	if let Some(value) = map.get("normalized_terminal") {
		let p = child(path, "normalized_terminal");
		if let Some(map) = v.object(Some(value), &p) {
			let keys = &["budget_bytes", "retained_bytes", "omitted_frames"];
			integers(map, keys, &p, false, v);
			v.process_unknown(map, keys, &p);
		}
	}
	for key in ["filesystem_before", "filesystem_after"] {
		filesystem(map.get(key), &child(path, key), v);
	}
	let p = child(path, "process");
	if let Some(map) = v.object(map.get("process"), &p) {
		integer(
			map.get("sample_limit"),
			&child(&p, "sample_limit"),
			Some(false),
			v,
		);
		boolean(
			map.get("sampling_partial"),
			&child(&p, "sampling_partial"),
			v,
		);
		integer(
			map.get("retained_samples"),
			&child(&p, "retained_samples"),
			Some(false),
			v,
		);
		boolean(
			map.get("sample_limit_reached"),
			&child(&p, "sample_limit_reached"),
			v,
		);
		integer(
			map.get("sampling_failures"),
			&child(&p, "sampling_failures"),
			Some(false),
			v,
		);
		if map.get("first_sampling_failure") != Some(&Value::Null) {
			v.string(
				map.get("first_sampling_failure"),
				&child(&p, "first_sampling_failure"),
				false,
			);
		}
		v.choice(map.get("coverage"), &child(&p, "coverage"), &["sampled"]);
		v.process_unknown(
			map,
			&[
				"sample_limit",
				"sampling_partial",
				"retained_samples",
				"sample_limit_reached",
				"sampling_failures",
				"first_sampling_failure",
				"coverage",
			],
			&p,
		);
	}
	v.process_unknown(
		map,
		&[
			"raw_terminal",
			"rendered_terminal",
			"normalized_terminal",
			"filesystem_before",
			"filesystem_after",
			"process",
		],
		path,
	);
}

fn retention(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	integers(
		map,
		&[
			"budget_bytes",
			"observed_bytes",
			"retained_bytes",
			"observed_frames",
			"retained_frames",
		],
		path,
		false,
		v,
	);
	for key in ["unknown_size_frames", "normalization_over_budget_frames"] {
		if let Some(value) = map.get(key) {
			integer(Some(value), &child(path, key), Some(false), v);
		}
	}
	v.process_unknown(
		map,
		&[
			"budget_bytes",
			"observed_bytes",
			"retained_bytes",
			"observed_frames",
			"retained_frames",
			"unknown_size_frames",
			"normalization_over_budget_frames",
		],
		path,
	);
}

fn filesystem(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	integers(map, &["files_limit", "depth_limit"], path, false, v);
	boolean(
		map.get("enumeration_truncated"),
		&child(path, "enumeration_truncated"),
		v,
	);
	let p = child(path, "enumeration_reasons");
	if let Some(values) = v.array(map.get("enumeration_reasons"), &p) {
		for (index, value) in values.iter().enumerate() {
			v.choice(Some(value), &child(&p, index), ENUMERATION_REASONS);
		}
	}
	array(
		map.get("enumeration_omissions"),
		&child(path, "enumeration_omissions"),
		v,
		enumeration,
	);
	if let Some(value) = map.get("unobserved_subtrees") {
		array(
			Some(value),
			&child(path, "unobserved_subtrees"),
			v,
			unobserved,
		);
	}
	integers(map, &["hash_budget_bytes", "hashed_bytes"], path, false, v);
	array(
		map.get("hash_omissions"),
		&child(path, "hash_omissions"),
		v,
		hash_omission,
	);
	v.process_unknown(
		map,
		&[
			"files_limit",
			"depth_limit",
			"enumeration_truncated",
			"enumeration_reasons",
			"enumeration_omissions",
			"unobserved_subtrees",
			"hash_budget_bytes",
			"hashed_bytes",
			"hash_omissions",
		],
		path,
	);
}

fn enumeration(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	v.string(map.get("path"), &child(path, "path"), false);
	v.choice(map.get("reason"), &child(path, "reason"), ENUMERATION);
	if map.get("system_code") != Some(&Value::Null) {
		v.string(map.get("system_code"), &child(path, "system_code"), false);
	}
	v.process_unknown(map, &["path", "reason", "system_code"], path);
}

fn unobserved(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	v.string(map.get("path"), &child(path, "path"), false);
	v.choice(
		map.get("reason"),
		&child(path, "reason"),
		&["symlink_not_followed", "observer_owned"],
	);
	v.process_unknown(map, &["path", "reason"], path);
}

fn hash_omission(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	v.string(map.get("path"), &child(path, "path"), false);
	integers(
		map,
		&["size_bytes", "remaining_budget_bytes"],
		path,
		false,
		v,
	);
	v.choice(
		map.get("reason"),
		&child(path, "reason"),
		&[
			"file_bytes_budget",
			"file_changed_or_short_read",
			"file_unavailable",
		],
	);
	if map.get("system_code") != Some(&Value::Null) {
		v.string(map.get("system_code"), &child(path, "system_code"), false);
	}
	v.process_unknown(
		map,
		&[
			"path",
			"size_bytes",
			"remaining_budget_bytes",
			"reason",
			"system_code",
		],
		path,
	);
}

fn filesystem_truncated(coverage: &Value) -> bool {
	coverage["enumeration_truncated"] == true
		|| !rows(&coverage["enumeration_omissions"]).is_empty()
		|| !rows(&coverage["hash_omissions"]).is_empty()
}

fn truncated(details: &Value) -> bool {
	["raw_terminal", "rendered_terminal"].iter().any(|key| {
		number(&details[*key]["observed_frames"]) > number(&details[*key]["retained_frames"])
	}) || number(&details["normalized_terminal"]["omitted_frames"]) > 0.0
		|| number(&details["rendered_terminal"]["unknown_size_frames"]) > 0.0
		|| filesystem_truncated(&details["filesystem_before"])
		|| filesystem_truncated(&details["filesystem_after"])
		|| details["process"]["sampling_partial"] == true
}

pub(super) fn validate(capture: &Value, v: &mut Validation<'_>) {
	let details = &capture["truncation_details"];
	let process = &details["process"];
	issue(
		v,
		number(&process["retained_samples"]) == rows(&capture["process_samples"]).len() as f64
			&& number(&process["retained_samples"]) <= number(&process["sample_limit"])
			&& process["sampling_partial"].as_bool()
				== Some(
					process["sample_limit_reached"] == true
						|| number(&process["sampling_failures"]) > 0.0,
				) && (number(&process["sampling_failures"]) == 0.0)
			== process["first_sampling_failure"].is_null(),
		"truncation_details.process",
		"sampling coverage must agree with retained samples and observed failures",
	);
	issue(
		v,
		capture["truncated"].as_bool() == Some(truncated(details)),
		"truncation_details",
		"aggregate truncation must match producer coverage",
	);
	issue(
		v,
		number(&details["rendered_terminal"]["normalization_over_budget_frames"])
			<= number(&details["rendered_terminal"]["unknown_size_frames"]),
		"truncation_details.rendered_terminal.normalization_over_budget_frames",
		"normalization omissions must be a subset of unknown-size rendered frames",
	);
	let raw_bytes = rows(&capture["frames"])
		.iter()
		.map(|frame| bytes(frame.get("raw_data").unwrap_or(&frame["data"])))
		.sum::<f64>();
	let rendered_bytes = rows(&capture["rendered_frames"])
		.iter()
		.fold(0.0, |total, frame| {
			rows(&frame["lines"])
				.iter()
				.fold(total + bytes(&frame["serialized_state"]), |sum, line| {
					sum + bytes(line)
				})
		});
	for (name, count, stored_bytes) in [
		(
			"raw_terminal",
			rows(&capture["frames"]).len() as f64,
			raw_bytes,
		),
		(
			"rendered_terminal",
			rows(&capture["rendered_frames"]).len() as f64,
			rendered_bytes,
		),
	] {
		let retention = &details[name];
		issue(
			v,
			number(&retention["retained_frames"]) == count
				&& number(&retention["observed_frames"]) >= count
				&& number(&retention["retained_bytes"]) == stored_bytes
				&& number(&retention["observed_bytes"]) >= number(&retention["retained_bytes"])
				&& (number(&retention["observed_frames"]) > count
					|| number(&retention["observed_bytes"])
						== number(&retention["retained_bytes"]))
				&& number(&retention["retained_bytes"]) <= number(&retention["budget_bytes"])
				&& number(&retention["unknown_size_frames"])
					<= number(&retention["observed_frames"])
						- number(&retention["retained_frames"]),
			&format!("truncation_details.{name}"),
			"retained observations and budget accounting do not agree",
		);
	}
	if let Some(normalized) = details.get("normalized_terminal") {
		let budget = capture["manifest"]["scenario"]["limits"]
			.get("output_bytes")
			.and_then(Value::as_f64)
			.filter(|value| {
				value.fract() == 0.0 && *value > 0.0 && *value <= 9_007_199_254_740_991.0
			});
		issue(
			v,
			budget.is_some(),
			"manifest.scenario.limits.output_bytes",
			"committed process scenario must include an explicit valid output_bytes budget",
		);
		if let Some(budget) = budget {
			let retained = rows(&capture["frames"])
				.iter()
				.map(|frame| bytes(&frame["data"]))
				.sum::<f64>();
			issue(v, number(&normalized["budget_bytes"]) == budget && number(&normalized["retained_bytes"]) == retained
				&& number(&normalized["retained_bytes"]) <= number(&normalized["budget_bytes"])
				&& number(&normalized["omitted_frames"]) <= number(&details["raw_terminal"]["observed_frames"]) - number(&details["raw_terminal"]["retained_frames"]),
				"truncation_details.normalized_terminal", "normalized terminal retention must agree with the committed budget and retained frames");
		}
	}
	for (name, files, index) in [
		("filesystem_before", rows(&capture["files_before"]), 0),
		("filesystem_after", rows(&capture["files_after"]), 1),
	] {
		validate_filesystem(
			name,
			&details[name],
			files,
			rows(&capture["filesystem_checkpoints"]).get(index),
			v,
		);
	}
}

fn validate_filesystem(
	name: &str,
	coverage: &Value,
	files: &[Value],
	checkpoint: Option<&Value>,
	v: &mut Validation<'_>,
) {
	let mut unhashed = BTreeMap::new();
	let mut types = BTreeMap::new();
	for file in files {
		let path = file["path"].as_str().unwrap_or("");
		types.insert(path, &file["type"]);
		if file["type"] == "file" && file["sha256"].is_null() {
			unhashed.insert(path, file);
		}
	}
	let omissions = rows(&coverage["hash_omissions"]);
	let distinct: BTreeSet<_> = omissions
		.iter()
		.filter_map(|omission| omission["path"].as_str())
		.collect();
	issue(
		v,
		omissions.len() == unhashed.len()
			&& distinct.len() == unhashed.len()
			&& omissions.iter().all(|omission| {
				unhashed
					.get(omission["path"].as_str().unwrap_or(""))
					.is_some_and(|file| number(&file["size"]) == number(&omission["size_bytes"]))
					&& number(&omission["remaining_budget_bytes"])
						<= number(&coverage["hash_budget_bytes"])
					&& if omission["reason"] == "file_unavailable" {
						!omission["system_code"].is_null()
					} else {
						omission["system_code"].is_null()
					}
			}),
		&format!("truncation_details.{name}.hash_omissions"),
		"every retained regular file without a digest must have one matching omission reason",
	);
	let omissions = rows(&coverage["enumeration_omissions"]);
	let reasons = rows(&coverage["enumeration_reasons"]);
	let distinct: BTreeSet<_> = omissions
		.iter()
		.filter_map(|omission| omission["path"].as_str())
		.collect();
	issue(v, distinct.len() == omissions.len()
		&& ["entry_unavailable", "symlink_not_followed"].iter().all(|reason|
			!reasons.iter().any(|value| value == reason) || omissions.iter().any(|omission| omission["reason"] == *reason))
		&& omissions.iter().all(|omission| {
			if !reasons.contains(&omission["reason"]) { return false; }
			let entry_type = types.get(omission["path"].as_str().unwrap_or("")).copied();
			match omission["reason"].as_str() {
				Some("symlink_not_followed") => entry_type.is_some_and(|value| value == "symlink") && omission["system_code"].is_null(),
				Some("directory_unavailable") => entry_type.is_some_and(|value| value == "directory") && !omission["system_code"].is_null(),
				_ => (entry_type.is_none() || entry_type.is_some_and(|value| value == "directory"))
					&& if omission["reason"] == "entry_unavailable" { !omission["system_code"].is_null() } else { omission["system_code"].is_null() },
			}
		}), &format!("truncation_details.{name}.enumeration_omissions"), "every enumeration omission must identify an unavailable entry, retained directory or unfollowed symlink, with a matching reason and system error only for unavailable reads");
	let hashed = files
		.iter()
		.filter(|file| file["type"] == "file" && !file["sha256"].is_null())
		.map(|file| number(&file["size"]))
		.sum::<f64>();
	issue(
		v,
		number(&coverage["hashed_bytes"]) == hashed
			&& number(&coverage["hashed_bytes"]) <= number(&coverage["hash_budget_bytes"])
			&& files.len() as f64 <= number(&coverage["files_limit"]),
		&format!("truncation_details.{name}"),
		"filesystem budget accounting does not match retained observations",
	);
	let truncated = coverage["enumeration_truncated"] == true
		|| !omissions.is_empty()
		|| !rows(&coverage["hash_omissions"]).is_empty();
	issue(
		v,
		coverage["enumeration_truncated"].as_bool() == Some(!reasons.is_empty())
			&& checkpoint.and_then(|value| value["truncated"].as_bool()) == Some(truncated),
		&format!("truncation_details.{name}"),
		"filesystem checkpoint truncation must match enumeration and digest coverage",
	);
}
