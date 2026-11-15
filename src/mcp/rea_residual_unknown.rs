// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Authenticate frozen REA residual-unknown revisions and complete histories.
//! This is a child of rea_evidence_source so shape diagnostics use the same
//! original-order validator. The domain contract is from the MIT-licensed
//! rea-agents 6.8.0 residualUnknown.js and evidenceBundle.js; see REA-MIT.txt.
//! File admission and blocking-owner cancellation remain with the caller.

use super::{
	checked_string, child, digest_fields, SourceResult, Validation, AUTHORITY, CONFIDENCE,
	ISOLATION,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const FIELDS: &[&str] = &[
	"unknown_id",
	"revision",
	"previous_revision_digest",
	"revision_digest",
	"scope_digest",
	"question",
	"status",
	"severity",
	"domain",
	"comparison_conclusion_scope",
	"supporting_evidence_ids",
	"contradicting_evidence_ids",
	"required_authority",
	"required_confidence",
	"required_environment",
	"recommended_probes",
	"relationships",
	"resolution",
	"mutation_evidence_ids",
];
const DIMENSIONS: &[&str] = &[
	"identity",
	"pseudocode",
	"assembly",
	"comments",
	"calls",
	"references",
	"strings_names",
	"cfg",
];

// ECMAScript WhiteSpace + LineTerminator. Rust is_whitespace includes NEL and
// excludes BOM, so using it would change both normalization and stable IDs.
fn js_space(c: char) -> bool {
	matches!(
		c,
		'\u{0009}'..='\u{000d}'
			| '\u{0020}'
			| '\u{00a0}'
			| '\u{1680}'
			| '\u{2000}'..='\u{200a}'
			| '\u{2028}'
			| '\u{2029}'
			| '\u{202f}'
			| '\u{205f}'
			| '\u{3000}'
			| '\u{feff}'
	)
}

fn trim_field(map: &mut Map<String, Value>, key: &str) {
	if let Some(Value::String(text)) = map.get_mut(key) {
		let trimmed = text.trim_matches(js_space);
		if trimmed.len() != text.len() {
			*text = trimmed.to_owned();
		}
	}
}

fn normalize(value: &mut Value) {
	let Some(map) = value.as_object_mut() else {
		return;
	};
	// Zod's fixed object parser omits an own __proto__ key. Only strip known
	// schema objects: arbitrary nested payloads are not normalization targets.
	map.remove("__proto__");
	for key in ["question", "domain"] {
		trim_field(map, key);
	}
	for key in ["comparison_conclusion_scope", "required_environment"] {
		if let Some(object) = map.get_mut(key).and_then(Value::as_object_mut) {
			object.remove("__proto__");
		}
	}
	if let Some(values) = map
		.get_mut("recommended_probes")
		.and_then(Value::as_array_mut)
	{
		for value in values {
			if let Some(probe) = value.as_object_mut() {
				probe.remove("__proto__");
				trim_field(probe, "rationale");
			}
		}
	}
	if let Some(resolution) = map.get_mut("resolution").and_then(Value::as_object_mut) {
		resolution.remove("__proto__");
		trim_field(resolution, "rationale");
	}
	if let Some(relationships) = map.get_mut("relationships").and_then(Value::as_array_mut) {
		for relationship in relationships {
			if let Some(object) = relationship.as_object_mut() {
				object.remove("__proto__");
			}
		}
	}
}

fn collapsed_question(text: &str) -> String {
	let mut result = String::with_capacity(text.len());
	let mut separator = false;
	for c in text.chars() {
		if js_space(c) {
			separator = !result.is_empty();
		} else {
			if separator {
				result.push(' ');
			}
			result.push(c);
			separator = false;
		}
	}
	result
}

fn stable_id(value: &Value) -> SourceResult<String> {
	let question = Value::String(collapsed_question(checked_string(&value["question"])?));
	let domain = Value::String(
		checked_string(&value["domain"])?
			.trim_matches(js_space)
			.to_owned(),
	);
	let mut fields = Vec::with_capacity(4);
	if let Some(scope) = value.get("comparison_conclusion_scope") {
		fields.push(("comparison_conclusion_scope", scope));
	}
	fields.extend([
		("domain", &domain),
		("question", &question),
		("scope_digest", &value["scope_digest"]),
	]);
	Ok(format!("unk_{}", digest_fields(&fields)?))
}

fn revision_digest(map: &Map<String, Value>) -> SourceResult<String> {
	// Strict shape admitted only these ASCII field names. Their BTreeMap order
	// is consequently the RFC 8785 UTF-16 order; nested values use its writer.
	let fields: Vec<_> = map
		.iter()
		.filter(|(key, _)| key.as_str() != "revision_digest")
		.map(|(key, value)| (key.as_str(), value))
		.collect();
	digest_fields(&fields)
}

fn revision(value: Option<&Value>, path: &[Value], validation: &mut Validation<'_>) {
	let Some(number) = value.and_then(Value::as_f64) else {
		validation.invalid_type(value, path, "number");
		return;
	};
	if number.fract() != 0.0 {
		validation.invalid_type(value, path, "int");
		return;
	}
	if number > 9_007_199_254_740_991.0 {
		validation.add(
			path,
			"Too big: expected int to be <=9007199254740991".into(),
			vec![json!({"path":path,"reason":"out_of_range","maximum":9007199254740991u64})],
			false,
		);
	}
	if number < -9_007_199_254_740_991.0 {
		validation.add(
			path,
			"Too small: expected int to be >=-9007199254740991".into(),
			vec![json!({"path":path,"reason":"out_of_range","minimum":-9007199254740991i64})],
			false,
		);
	}
	if number < 1.0 {
		validation.add(
			path,
			"Too small: expected number to be >=1".into(),
			vec![json!({"path":path,"reason":"out_of_range","minimum":1})],
			false,
		);
	}
}

fn ids(value: Option<&Value>, path: &[Value], minimum: bool, validation: &mut Validation<'_>) {
	if let Some(values) = validation.array(value, path) {
		for (index, id) in values.iter().enumerate() {
			validation.digest(Some(id), &child(path, index), "ev_");
		}
	}
	if minimum {
		validation.min_length(value, path, 1);
	}
}

fn trimmed_text(value: Option<&Value>, path: &[Value], validation: &mut Validation<'_>) {
	validation.string(value, path, false);
	validation.min_length(value, path, 1);
}

fn environment(value: Option<&Value>, path: &[Value], validation: &mut Validation<'_>) {
	if value == Some(&Value::Null) {
		return;
	}
	let Some(map) = validation.object(value, path) else {
		return;
	};
	for key in ["id", "platform", "architecture"] {
		if map.get(key) != Some(&Value::Null) {
			validation.string(map.get(key), &child(path, key), true);
		}
	}
	if map.get("isolation") != Some(&Value::Null) {
		validation.choice(map.get("isolation"), &child(path, "isolation"), ISOLATION);
	}
	validation.unknown(map, &["id", "platform", "architecture", "isolation"], path);
}

fn comparison_scope(value: &Value, path: &[Value], validation: &mut Validation<'_>) {
	let start = validation.issues.len();
	let Some(map) = validation.object(Some(value), path) else {
		return;
	};
	validation.digest(
		map.get("comparison_evidence_id"),
		&child(path, "comparison_evidence_id"),
		"ev_",
	);
	let dimension_path = child(path, "dimensions");
	if let Some(values) = validation.array(map.get("dimensions"), &dimension_path) {
		for (index, value) in values.iter().enumerate() {
			if value
				.as_str()
				.is_some_and(|s| s == "overall" || DIMENSIONS.contains(&s))
			{
				continue;
			}
			let item_path = child(&dimension_path, index);
			validation.add(
				&item_path,
				"Invalid input".into(),
				vec![
					json!({"path":item_path,"reason":"invalid_value","expected":["overall"]}),
					json!({"path":item_path,"reason":"invalid_value","expected":DIMENSIONS}),
				],
				true,
			);
		}
	}
	validation.min_length(map.get("dimensions"), &dimension_path, 1);
	validation.unknown(map, &["comparison_evidence_id", "dimensions"], path);
	if !validation.aborted_from(start)
		&& validation.gap.is_none()
		&& map
			.get("dimensions")
			.and_then(Value::as_array)
			.is_some_and(|values| {
				values
					.windows(2)
					.any(|pair| pair[0].as_str() >= pair[1].as_str())
			}) {
		validation.custom(
			path,
			"Comparison dimensions must be sorted and unique",
			false,
		);
	}
}

fn resolution(value: Option<&Value>, path: &[Value], validation: &mut Validation<'_>) {
	if value == Some(&Value::Null) {
		return;
	}
	let Some(map) = validation.object(value, path) else {
		return;
	};
	if !validation.discriminator(
		map.get("disposition"),
		&child(path, "disposition"),
		&["verified", "withdrawn", "out-of-scope"],
	) {
		return;
	}
	trimmed_text(map.get("rationale"), &child(path, "rationale"), validation);
	ids(
		map.get("evidence_ids"),
		&child(path, "evidence_ids"),
		map["disposition"] == "verified",
		validation,
	);
	validation.unknown(map, &["disposition", "rationale", "evidence_ids"], path);
}

fn array_contains(value: &Value, candidate: &Value) -> bool {
	value
		.as_array()
		.is_some_and(|values| values.contains(candidate))
}

fn repeated(values: &Value) -> bool {
	let mut seen = BTreeSet::new();
	values
		.as_array()
		.is_some_and(|values| values.iter().any(|v| !seen.insert(v.as_str())))
}

fn refine(value: &Value, path: &[Value], validation: &mut Validation<'_>) -> SourceResult<()> {
	let Some(map) = value.as_object() else {
		return Err(super::internal("validated residual unknown changed shape"));
	};
	if map["revision_digest"].as_str() != Some(&revision_digest(map)?) {
		validation.custom(
			&child(path, "revision_digest"),
			"Residual unknown revision digest does not match",
			false,
		);
	}
	if map["unknown_id"].as_str() != Some(&stable_id(value)?) {
		validation.custom(
			&child(path, "unknown_id"),
			"Residual unknown ID does not match its immutable identity",
			false,
		);
	}
	if (map["revision"].as_f64() == Some(1.0)) != map["previous_revision_digest"].is_null() {
		validation.custom(
			&child(path, "previous_revision_digest"),
			"Only the first revision has no predecessor",
			false,
		);
	}
	if (map["status"] == "resolved") == map["resolution"].is_null() {
		validation.custom(
			&child(path, "resolution"),
			"Only resolved unknowns carry a resolution",
			false,
		);
	}
	if map["status"] == "contradicted"
		&& map["contradicting_evidence_ids"]
			.as_array()
			.is_some_and(Vec::is_empty)
	{
		validation.custom(
			&child(path, "contradicting_evidence_ids"),
			"Contradicted status requires contradicting evidence",
			false,
		);
	}
	if map["relationships"]
		.as_array()
		.is_some_and(|values| values.iter().any(|r| r["unknown_id"] == map["unknown_id"]))
	{
		validation.custom(
			&child(path, "relationships"),
			"An unknown cannot relate to itself",
			false,
		);
	}
	for key in [
		"supporting_evidence_ids",
		"contradicting_evidence_ids",
		"mutation_evidence_ids",
	] {
		if repeated(&map[key]) {
			validation.custom(path, "Evidence IDs must be unique", false);
		}
	}
	if let Some(scope) = map.get("comparison_conclusion_scope") {
		let comparison = &scope["comparison_evidence_id"];
		if !array_contains(&map["supporting_evidence_ids"], comparison)
			&& !array_contains(&map["contradicting_evidence_ids"], comparison)
		{
			validation.custom(
				&child(path, "comparison_conclusion_scope"),
				"Scoped comparison Evidence must support or contradict the unknown",
				false,
			);
		}
		if map["domain"] != "function-comparison" {
			validation.custom(
				&child(path, "comparison_conclusion_scope"),
				"Comparison conclusion scope requires function-comparison domain",
				false,
			);
		}
	}
	let contradicting: BTreeSet<_> = map["contradicting_evidence_ids"]
		.as_array()
		.into_iter()
		.flatten()
		.filter_map(Value::as_str)
		.collect();
	if map["supporting_evidence_ids"]
		.as_array()
		.is_some_and(|values| {
			values
				.iter()
				.filter_map(Value::as_str)
				.any(|id| contradicting.contains(id))
		}) {
		validation.custom(
			path,
			"Evidence cannot simultaneously support and contradict",
			false,
		);
	}
	let mut seen = BTreeSet::new();
	if map["relationships"].as_array().is_some_and(|values| {
		values
			.iter()
			.any(|r| !seen.insert((r["type"].as_str(), r["unknown_id"].as_str())))
	}) {
		validation.custom(
			&child(path, "relationships"),
			"Relationships must be unique",
			false,
		);
	}
	Ok(())
}

pub(super) fn validate_shape(
	value: &mut Value,
	path: &[Value],
	validation: &mut Validation<'_>,
) -> SourceResult<()> {
	normalize(value);
	let start = validation.issues.len();
	let Some(map) = validation.object(Some(value), path) else {
		return Ok(());
	};
	validation.digest(map.get("unknown_id"), &child(path, "unknown_id"), "unk_");
	revision(map.get("revision"), &child(path, "revision"), validation);
	for key in [
		"previous_revision_digest",
		"revision_digest",
		"scope_digest",
	] {
		if key == "revision_digest" || map.get(key) != Some(&Value::Null) {
			validation.digest(map.get(key), &child(path, key), "");
		}
	}
	trimmed_text(map.get("question"), &child(path, "question"), validation);
	validation.choice(
		map.get("status"),
		&child(path, "status"),
		&[
			"open",
			"investigating",
			"blocked",
			"contradicted",
			"resolved",
		],
	);
	validation.choice(
		map.get("severity"),
		&child(path, "severity"),
		&["low", "medium", "high", "critical"],
	);
	trimmed_text(map.get("domain"), &child(path, "domain"), validation);
	if let Some(scope) = map.get("comparison_conclusion_scope") {
		comparison_scope(
			scope,
			&child(path, "comparison_conclusion_scope"),
			validation,
		);
	}
	for key in ["supporting_evidence_ids", "contradicting_evidence_ids"] {
		ids(map.get(key), &child(path, key), false, validation);
	}
	if map.get("required_authority") != Some(&Value::Null) {
		validation.choice(
			map.get("required_authority"),
			&child(path, "required_authority"),
			AUTHORITY,
		);
	}
	validation.choice(
		map.get("required_confidence"),
		&child(path, "required_confidence"),
		CONFIDENCE,
	);
	environment(
		map.get("required_environment"),
		&child(path, "required_environment"),
		validation,
	);
	let probes_path = child(path, "recommended_probes");
	if let Some(probes) = validation.array(map.get("recommended_probes"), &probes_path) {
		for (index, probe) in probes.iter().enumerate() {
			let path = child(&probes_path, index);
			if let Some(probe) = validation.object(Some(probe), &path) {
				validation.string(probe.get("operation"), &child(&path, "operation"), true);
				trimmed_text(
					probe.get("rationale"),
					&child(&path, "rationale"),
					validation,
				);
				validation.unknown(probe, &["operation", "rationale"], &path);
			}
		}
	}
	let relationships_path = child(path, "relationships");
	if let Some(relationships) = validation.array(map.get("relationships"), &relationships_path) {
		for (index, relationship) in relationships.iter().enumerate() {
			let path = child(&relationships_path, index);
			if let Some(relationship) = validation.object(Some(relationship), &path) {
				validation.choice(
					relationship.get("type"),
					&child(&path, "type"),
					&["depends-on", "related-to", "contradicts"],
				);
				validation.digest(
					relationship.get("unknown_id"),
					&child(&path, "unknown_id"),
					"unk_",
				);
				validation.unknown(relationship, &["type", "unknown_id"], &path);
			}
		}
	}
	resolution(
		map.get("resolution"),
		&child(path, "resolution"),
		validation,
	);
	ids(
		map.get("mutation_evidence_ids"),
		&child(path, "mutation_evidence_ids"),
		true,
		validation,
	);
	validation.unknown(map, FIELDS, path);
	if !validation.aborted_from(start) && validation.gap.is_none() {
		refine(value, path, validation)?;
	}
	Ok(())
}

fn graph_string(value: &Value) -> Result<&str, String> {
	value
		.as_str()
		.ok_or_else(|| "Residual unknown graph requires validated strings".into())
}

fn graph_array(value: &Value) -> Result<&[Value], String> {
	value
		.as_array()
		.map(Vec::as_slice)
		.ok_or_else(|| "Residual unknown graph requires validated arrays".into())
}

fn confidence_rank(value: &Value) -> Option<u8> {
	match value.as_str() {
		Some("observed") => Some(3),
		Some("derived") => Some(2),
		Some("inferred") => Some(1),
		_ => None,
	}
}

fn evidence_qualifies(unknown: &Value, evidence: &Value) -> bool {
	if !unknown["required_authority"].is_null()
		&& unknown["required_authority"] != evidence["authority"]
	{
		return false;
	}
	let (Some(actual), Some(required)) = (
		confidence_rank(&evidence["confidence"]),
		confidence_rank(&unknown["required_confidence"]),
	) else {
		return false;
	};
	if actual < required {
		return false;
	}
	let required = &unknown["required_environment"];
	required.is_null()
		|| (!evidence["environment"].is_null()
			&& ["id", "platform", "architecture", "isolation"]
				.iter()
				.all(|key| {
					required[*key].is_null() || required[*key] == evidence["environment"][*key]
				}))
}

fn verify_resolution(unknown: &Value, records: &BTreeMap<&str, &Value>) -> Result<(), String> {
	let id = graph_string(&unknown["unknown_id"])?;
	if !graph_array(&unknown["contradicting_evidence_ids"])?.is_empty() {
		return Err(format!(
			"Residual unknown {id} retains contradicting evidence"
		));
	}
	// The schema has already validated these IDs. A borrowed set avoids
	// repeatedly scanning all support when resolution IDs are long or repeated,
	// while preserving the original order of resolution qualification checks.
	let supporting: BTreeSet<_> = graph_array(&unknown["supporting_evidence_ids"])?
		.iter()
		.filter_map(Value::as_str)
		.collect();
	for evidence_id in graph_array(&unknown["resolution"]["evidence_ids"])? {
		let key = graph_string(evidence_id)?;
		if supporting.contains(key)
			&& records.get(key).is_some_and(|evidence| {
				evidence["predicate_type"] != "rea.residual-unknown-mutation"
					&& evidence_qualifies(unknown, evidence)
			}) {
			return Ok(());
		}
	}
	Err(format!(
		"Residual unknown {id} has no qualifying resolution evidence"
	))
}

fn reject_cycles(heads: &[&Value], indices: &BTreeMap<&str, usize>) -> Result<(), String> {
	let mut visited = BTreeSet::new();
	let mut active = BTreeSet::new();
	for (root, head) in heads.iter().enumerate() {
		if visited.contains(&root) {
			continue;
		}
		active.insert(root);
		let mut pending = vec![(root, graph_array(&head["relationships"])?, 0usize)];
		while let Some((index, relationships, next)) = pending.last_mut() {
			if *next == relationships.len() {
				let completed = *index;
				pending.pop();
				active.remove(&completed);
				visited.insert(completed);
				continue;
			}
			let relationship = &relationships[*next];
			*next += 1;
			if relationship["type"] != "depends-on" {
				continue;
			}
			let key = graph_string(&relationship["unknown_id"])?;
			let Some(&dependency) = indices.get(key) else {
				return Err("Residual unknown dependency graph is inconsistent".into());
			};
			if active.contains(&dependency) {
				return Err("Residual unknown dependency graph contains a cycle".into());
			}
			if visited.contains(&dependency) {
				continue;
			}
			let Some(head) = heads.get(dependency) else {
				return Err("Residual unknown dependency graph is inconsistent".into());
			};
			active.insert(dependency);
			pending.push((dependency, graph_array(&head["relationships"])?, 0));
		}
	}
	Ok(())
}

/// Shapes have already been normalized and checked. Preserve first-seen ID
/// order like the original Map, then inspect every revision before head cycles.
pub(super) fn validate_graph(unknowns: &[&Value], records: &[&Value]) -> Result<(), String> {
	let mut evidence_by_id = BTreeMap::new();
	for record in records {
		evidence_by_id.insert(graph_string(&record["evidence_id"])?, *record);
	}
	let mut indices = BTreeMap::<&str, usize>::new();
	let mut histories: Vec<Vec<&Value>> = Vec::new();
	for unknown in unknowns {
		let id = graph_string(&unknown["unknown_id"])?;
		let index = if let Some(&index) = indices.get(id) {
			index
		} else {
			let index = histories.len();
			histories.push(Vec::new());
			indices.insert(id, index);
			index
		};
		histories[index].push(unknown);
	}
	let mut heads = Vec::with_capacity(histories.len());
	for history in &mut histories {
		history.sort_by(|left, right| {
			left["revision"]
				.as_f64()
				.partial_cmp(&right["revision"].as_f64())
				.unwrap_or(std::cmp::Ordering::Equal)
		});
		for (index, revision) in history.iter().enumerate() {
			let id = graph_string(&revision["unknown_id"])?;
			if revision["revision"].as_f64() != Some((index + 1) as f64) {
				return Err(format!("Residual unknown {id} revision history has a gap"));
			}
			if index > 0
				&& revision["previous_revision_digest"] != history[index - 1]["revision_digest"]
			{
				return Err(format!("Residual unknown {id} revision chain is broken"));
			}
		}
		let Some(head) = history.last() else {
			return Err("Residual unknown revision history is empty".into());
		};
		heads.push(*head);
	}
	for unknown in unknowns {
		let mut references = Vec::with_capacity(4);
		for key in [
			"supporting_evidence_ids",
			"contradicting_evidence_ids",
			"mutation_evidence_ids",
		] {
			references.push(graph_array(&unknown[key])?);
		}
		if !unknown["resolution"].is_null() {
			references.push(graph_array(&unknown["resolution"]["evidence_ids"])?);
		}
		for ids in references {
			for id in ids {
				let id = graph_string(id)?;
				if !evidence_by_id.contains_key(id) {
					return Err(format!("Residual unknown references missing evidence {id}"));
				}
			}
		}
		for relationship in graph_array(&unknown["relationships"])? {
			let id = graph_string(&relationship["unknown_id"])?;
			if !indices.contains_key(id) {
				return Err(format!("Residual unknown references missing unknown {id}"));
			}
		}
		if unknown["resolution"]["disposition"] == "verified" {
			verify_resolution(unknown, &evidence_by_id)?;
		}
	}
	reject_cycles(&heads, &indices)
}

#[cfg(test)]
#[path = "rea_residual_unknown_tests.rs"]
mod tests;
