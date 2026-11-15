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

//! Bounded HAR facts and exact-record comparisons. No JavaScript is evaluated,
//! no URL is opened, and repeated requests retain their original occurrences.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::{InspectWebCaptureParams, ReplayWebEntryParams};

pub(super) const MAX_ENTRIES: usize = 10_000;
pub(super) const MAX_URL_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub(super) struct Capture {
	pub sha256: String,
	pub byte_length: usize,
	pub entries: Vec<Entry>,
}

#[derive(Debug)]
pub(super) struct Entry {
	pub index: usize,
	pub method: String,
	pub url: String,
	pub status: u16,
	pub mime_type: String,
	pub request_sha256: String,
	pub response_sha256: String,
	pub response: Value,
	pub request_headers: Option<usize>,
	pub response_headers: Option<usize>,
}

pub(super) fn hex(bytes: &[u8]) -> String {
	let mut output = String::with_capacity(bytes.len().saturating_mul(2));
	for byte in bytes {
		let _ = write!(output, "{byte:02x}");
	}
	output
}

pub(super) fn digest(bytes: &[u8]) -> String {
	hex(&Sha256::digest(bytes))
}

fn value_digest(value: &Value) -> Result<String> {
	// serde_json without preserve_order serializes object members in key order.
	// This identity is explicitly Hepta parsed-JSON identity, not REA Evidence.
	Ok(digest(&serde_json::to_vec(value)?))
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
	value
		.as_object()
		.ok_or_else(|| anyhow!("saved HAR {label} must be an object"))
}

fn string<'a>(object: &'a Map<String, Value>, name: &str, max: usize) -> Result<&'a str> {
	let value = object
		.get(name)
		.and_then(Value::as_str)
		.ok_or_else(|| anyhow!("saved HAR requires string {name}"))?;
	if value.len() > max {
		bail!("saved HAR {name} exceeds its retained text limit");
	}
	Ok(value)
}

pub(super) fn validate_method(method: &str) -> Result<()> {
	if method.is_empty()
		|| method.len() > 32
		|| !method
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_\x60|~".contains(&byte))
	{
		bail!("saved HAR method must be a nonempty bounded HTTP token");
	}
	Ok(())
}

fn header_count(object: &Map<String, Value>) -> Result<Option<usize>> {
	let Some(headers) = object.get("headers") else {
		return Ok(None);
	};
	let headers = headers
		.as_array()
		.ok_or_else(|| anyhow!("saved HAR headers must be an array"))?;
	if headers.len() > 1024 {
		bail!("saved HAR header list exceeds 1024 entries");
	}
	for header in headers {
		let header = self::object(header, "header")?;
		let name = string(header, "name", 4096)?;
		if name.is_empty() {
			bail!("saved HAR header name is empty");
		}
		string(header, "value", 64 * 1024)?;
	}
	Ok(Some(headers.len()))
}

pub(super) fn parse_capture(bytes: &[u8], expected: Option<&str>) -> Result<Capture> {
	if bytes.len() > super::MAX_FILE_BYTES as usize {
		bail!("saved HAR exceeds the 8 MiB source limit");
	}
	let sha256 = digest(bytes);
	if expected.is_some_and(|expected| expected != sha256) {
		bail!("saved HAR source SHA-256 changed; obtain a new first-page identity");
	}
	let mut document = crate::mcp::rea_evidence::parse_unique_json(bytes)?;
	let log = document
		.as_object_mut()
		.and_then(|root| root.get_mut("log"))
		.and_then(Value::as_object_mut)
		.ok_or_else(|| anyhow!("saved HAR requires a log object"))?;
	if log.get("version").and_then(Value::as_str) != Some("1.2") {
		bail!("saved HAR reader supports explicit version 1.2 only");
	}
	let entries = match log.remove("entries") {
		Some(Value::Array(entries)) => entries,
		_ => bail!("saved HAR requires an entries array"),
	};
	if entries.len() > MAX_ENTRIES {
		bail!("saved HAR exceeds the 10000-entry limit");
	}
	let mut observed = Vec::with_capacity(entries.len());
	for (index, mut value) in entries.into_iter().enumerate() {
		let entry = value
			.as_object_mut()
			.ok_or_else(|| anyhow!("saved HAR entry {index} must be an object"))?;
		let request = entry
			.remove("request")
			.ok_or_else(|| anyhow!("saved HAR entry {index} is missing its request"))?;
		let response = entry
			.remove("response")
			.ok_or_else(|| anyhow!("saved HAR entry {index} is missing its response"))?;
		let request_object = object(&request, "request")?;
		let method = string(request_object, "method", 32)?.to_owned();
		validate_method(&method)?;
		let url = string(request_object, "url", MAX_URL_BYTES)?.to_owned();
		if url.is_empty() || url.chars().any(char::is_control) {
			bail!("saved HAR request URL is empty or contains control characters");
		}
		let request_headers = header_count(request_object)?;
		let response_object = object(&response, "response")?;
		let status = response_object
			.get("status")
			.and_then(Value::as_u64)
			.filter(|status| *status <= 599)
			.ok_or_else(|| anyhow!("saved HAR response status must be an integer 0..=599"))?
			as u16;
		let response_headers = header_count(response_object)?;
		let content = response_object
			.get("content")
			.ok_or_else(|| anyhow!("saved HAR response requires content declarations"))?;
		let content = object(content, "response content")?;
		let mime_type = string(content, "mimeType", 1024)?.to_owned();
		if let Some(text) = content.get("text") {
			if !text.is_string() {
				bail!("saved HAR content.text must be a string when present");
			}
		}
		if let Some(encoding) = content.get("encoding") {
			if encoding.as_str().is_none_or(|value| value.len() > 64) {
				bail!("saved HAR content.encoding must be a bounded string");
			}
		}
		if let Some(size) = content.get("size") {
			if size.as_u64().is_none() {
				bail!("saved HAR content.size must be a nonnegative integer when present");
			}
		}
		observed.push(Entry {
			index,
			method,
			url,
			status,
			mime_type,
			request_sha256: value_digest(&request)?,
			response_sha256: value_digest(&response)?,
			response,
			request_headers,
			response_headers,
		});
	}
	Ok(Capture {
		sha256,
		byte_length: bytes.len(),
		entries: observed,
	})
}

fn source(capture: &Capture) -> Value {
	json!({
		"sha256": capture.sha256,
		"byte_length": capture.byte_length,
		"identity_scope": "complete_saved_file",
		"format": "har",
		"version": "1.2"
	})
}

fn summary(entry: &Entry) -> Value {
	let content = &entry.response["content"];
	json!({
		"entry_index": entry.index,
		"method": entry.method,
		"url": entry.url,
		"status": entry.status,
		"mime_type": entry.mime_type,
		"request_sha256": entry.request_sha256,
		"response_sha256": entry.response_sha256,
		"request_header_count": entry.request_headers,
		"response_header_count": entry.response_headers,
		"body_recorded": content.get("text").is_some(),
		"recorded_text_bytes": content.get("text").and_then(Value::as_str).map(str::len),
		"declared_content_size": content.get("size"),
		"har_content_encoding": content.get("encoding")
	})
}

fn limitations() -> Value {
	json!([
		"Only saved HAR 1.2 observations are inspected; no browser, JavaScript, network request or application transition is executed.",
		"Captured requests and responses do not establish complete endpoint behavior, causation, live state, API compatibility or successful effects.",
		"Only selected HAR fields are validated; this is not complete HAR-schema validation.",
		"Request and response digests cover parsed JSON with sorted object keys and preserved array order, not wire bytes or REA Evidence.",
		"Missing content.text remains unknown; encoded content is retained as recorded and is not decoded, decompressed or verified."
	])
}

pub(super) fn inspect(capture: &Capture, params: &InspectWebCaptureParams) -> Result<Value> {
	let selected: Vec<_> = capture
		.entries
		.iter()
		.filter(|entry| {
			params
				.method
				.as_ref()
				.is_none_or(|method| method == &entry.method)
				&& params.url.as_ref().is_none_or(|url| url == &entry.url)
				&& params.status.is_none_or(|status| status == entry.status)
		})
		.collect();
	if params.offset > selected.len() {
		bail!("saved HAR page offset exceeds the matching entry count");
	}
	let rows: Vec<_> = selected
		.iter()
		.skip(params.offset)
		.take(params.limit)
		.map(|entry| summary(entry))
		.collect();
	let end = params.offset + rows.len();
	Ok(json!({
		"record_format": "hepta.rea-web-capture.v1",
		"rea_evidence_compatible": false,
		"source": source(capture),
		"entry_count": capture.entries.len(),
		"matched_count": selected.len(),
		"offset": params.offset,
		"next_offset": (end < selected.len()).then_some(end),
		"entries": rows,
		"coverage": {
			"saved_entry_inventory": "complete_within_supported_limits",
			"response_body_presence": "recorded",
			"live_behavior": "unobserved"
		},
		"limitations": limitations()
	}))
}

fn keyed(capture: &Capture) -> BTreeMap<(String, usize), &Entry> {
	let mut occurrences = BTreeMap::<&str, usize>::new();
	let mut result = BTreeMap::new();
	for entry in &capture.entries {
		let occurrence = occurrences.entry(&entry.request_sha256).or_default();
		result.insert((entry.request_sha256.clone(), *occurrence), entry);
		*occurrence += 1;
	}
	result
}

pub(super) fn compare(
	before: &Capture,
	after: &Capture,
	offset: usize,
	limit: usize,
) -> Result<Value> {
	let mut old = keyed(before);
	let mut changes = BTreeMap::new();
	let mut unchanged = 0_usize;
	let mut added = 0_usize;
	let mut removed = 0_usize;
	let mut changed = 0_usize;
	for (key, next) in keyed(after) {
		match old.remove(&key) {
			Some(previous) if previous.response_sha256 == next.response_sha256 => {
				unchanged += 1;
			}
			Some(previous) => {
				changed += 1;
				changes.insert(key, (Some(previous), Some(next)));
			}
			None => {
				added += 1;
				changes.insert(key, (None, Some(next)));
			}
		}
	}
	for (key, previous) in old {
		removed += 1;
		changes.insert(key, (Some(previous), None));
	}
	if offset > changes.len() {
		bail!("saved HAR comparison offset exceeds the difference count");
	}
	// Only the selected page materializes JSON summaries; a large difference
	// set retains references instead of cloning every URL and metadata row.
	let rows: Vec<_> = changes
		.iter()
		.skip(offset)
		.take(limit)
		.map(|(key, (previous, next))| {
			let kind = match (previous, next) {
				(Some(_), Some(_)) => "recorded_response_changed",
				(None, Some(_)) => "recorded_request_added",
				_ => "recorded_request_removed",
			};
			json!({
				"kind": kind,
				"request_sha256": key.0,
				"request_occurrence": key.1,
				"before": previous.map(summary),
				"after": next.map(summary)
			})
		})
		.collect();
	let end = offset + rows.len();
	Ok(json!({
		"record_format": "hepta.rea-web-comparison.v1",
		"rea_evidence_compatible": false,
		"before_source": source(before),
		"after_source": source(after),
		"matching": "complete_recorded_request_json_sha256_then_occurrence_order",
		"comparison_scope": "complete_recorded_response_json",
		"counts": {
			"unchanged": unchanged,
			"added": added,
			"removed": removed,
			"changed": changed
		},
		"difference_count": changes.len(),
		"offset": offset,
		"next_offset": (end < changes.len()).then_some(end),
		"differences": rows,
		"limitations": limitations()
	}))
}

pub(super) fn replay(capture: &Capture, params: &ReplayWebEntryParams) -> Result<Value> {
	let entry = capture
		.entries
		.get(params.entry_index)
		.ok_or_else(|| anyhow!("saved HAR entry index is outside the captured inventory"))?;
	let content = &entry.response["content"];
	let body = match content.get("text").and_then(Value::as_str) {
		Some(text) => {
			let bytes = text.as_bytes();
			if params.body_offset > bytes.len() {
				bail!("saved HAR body offset exceeds the recorded representation");
			}
			let end = params
				.body_offset
				.saturating_add(params.body_length)
				.min(bytes.len());
			let selected = &bytes[params.body_offset..end];
			json!({
				"recorded": true,
				"representation": "utf8_bytes_of_har_content_text",
				"har_encoding": content.get("encoding"),
				"representation_sha256": digest(bytes),
				"representation_byte_length": bytes.len(),
				"offset": params.body_offset,
				"length": selected.len(),
				"bytes_hex": hex(selected),
				"next_offset": (end < bytes.len()).then_some(end),
				"decoded_payload_verified": false
			})
		}
		None => {
			if params.body_offset != 0 {
				bail!("saved HAR contains no response body representation to offset into");
			}
			json!({
				"recorded": false,
				"representation": null,
				"decoded_payload_verified": false
			})
		}
	};
	let mut response_metadata = entry.response.clone();
	response_metadata
		.get_mut("content")
		.and_then(Value::as_object_mut)
		.context("validated saved HAR content became unavailable")?
		.remove("text");
	Ok(json!({
		"record_format": "hepta.rea-web-recorded-response.v1",
		"rea_evidence_compatible": false,
		"source": source(capture),
		"entry": summary(entry),
		"response_metadata": response_metadata,
		"body": body,
		"network_requests": 0,
		"javascript_executed": false,
		"application_state_inferred": false,
		"replay_scope": "selected_saved_response_only",
		"limitations": limitations()
	}))
}
