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

//! Strict bounded parsing of Android binary XML declarations and the JAR
//! manifest main section. No Java/Android code, resource table or path runs.

use super::{ApplicationKind, MAX_MANIFEST_BYTES, MAX_ROWS};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::Instant;

const NONE: u32 = u32::MAX;
const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";
const MAX_STRINGS: usize = 65_536;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_DECODED_STRING_BYTES: usize = 8 * 1024 * 1024;
const MAX_REFERENCE_BYTES: usize = 32 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct ManifestReport {
	pub format: &'static str,
	pub summary: Value,
	pub components: Vec<Value>,
	pub permissions: Vec<Value>,
	pub attributes: Vec<Value>,
}

pub(super) fn parse(
	bytes: &[u8],
	kind: ApplicationKind,
	deadline: Instant,
) -> Result<ManifestReport> {
	if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
		bail!("application manifest is empty or exceeds 4 MiB");
	}
	match kind {
		ApplicationKind::Apk => parse_axml(bytes, deadline),
		ApplicationKind::Jar => parse_jar(bytes, deadline),
	}
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
	Ok(u16::from_le_bytes(
		bytes
			.get(offset..offset.saturating_add(2))
			.ok_or_else(|| anyhow!("truncated Android binary XML u16"))?
			.try_into()?,
	))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
	Ok(u32::from_le_bytes(
		bytes
			.get(offset..offset.saturating_add(4))
			.ok_or_else(|| anyhow!("truncated Android binary XML u32"))?
			.try_into()?,
	))
}

struct Chunk<'a> {
	kind: u16,
	header: usize,
	bytes: &'a [u8],
}

fn chunk_at(bytes: &[u8], offset: usize) -> Result<Chunk<'_>> {
	let kind = u16_at(bytes, offset)?;
	let header = usize::from(u16_at(bytes, offset + 2)?);
	let size = usize::try_from(u32_at(bytes, offset + 4)?)?;
	if header < 8 || size < header || size % 4 != 0 || header % 4 != 0 {
		bail!("Android binary XML chunk has an invalid size or alignment");
	}
	let end = offset
		.checked_add(size)
		.ok_or_else(|| anyhow!("Android XML chunk extent overflow"))?;
	Ok(Chunk {
		kind,
		header,
		bytes: bytes
			.get(offset..end)
			.ok_or_else(|| anyhow!("Android XML chunk exceeds the manifest"))?,
	})
}

fn utf8_length(bytes: &[u8], position: &mut usize) -> Result<usize> {
	let first = *bytes
		.get(*position)
		.ok_or_else(|| anyhow!("truncated Android UTF-8 length"))?;
	*position += 1;
	if first & 0x80 == 0 {
		Ok(usize::from(first))
	} else {
		let second = *bytes
			.get(*position)
			.ok_or_else(|| anyhow!("truncated Android UTF-8 length"))?;
		*position += 1;
		Ok((usize::from(first & 0x7f) << 8) | usize::from(second))
	}
}

fn utf16_length(bytes: &[u8], position: &mut usize) -> Result<usize> {
	let first = u16_at(bytes, *position)?;
	*position += 2;
	if first & 0x8000 == 0 {
		Ok(usize::from(first))
	} else {
		let second = u16_at(bytes, *position)?;
		*position += 2;
		Ok((usize::from(first & 0x7fff) << 16) | usize::from(second))
	}
}

fn string_pool(chunk: &Chunk<'_>) -> Result<Vec<String>> {
	if chunk.kind != 1 || chunk.header != 28 {
		bail!("APK binary XML requires a standard string-pool header");
	}
	let count = usize::try_from(u32_at(chunk.bytes, 8)?)?;
	let styles = u32_at(chunk.bytes, 12)?;
	let flags = u32_at(chunk.bytes, 16)?;
	let start = usize::try_from(u32_at(chunk.bytes, 20)?)?;
	let style_start = u32_at(chunk.bytes, 24)?;
	if count > MAX_STRINGS || styles != 0 || style_start != 0 || flags & !0x101 != 0 {
		bail!("APK string pool exceeds its count or uses unsupported styles/flags");
	}
	let table_end = chunk
		.header
		.checked_add(
			count
				.checked_mul(4)
				.ok_or_else(|| anyhow!("APK string table overflow"))?,
		)
		.ok_or_else(|| anyhow!("APK string table overflow"))?;
	if start < table_end || start > chunk.bytes.len() || start % 4 != 0 {
		bail!("APK string data overlaps its index or exceeds the chunk");
	}
	let data = &chunk.bytes[start..];
	let mut decoded_bytes = 0_usize;
	let mut strings = Vec::with_capacity(count);
	for index in 0..count {
		let mut position = usize::try_from(u32_at(chunk.bytes, chunk.header + index * 4)?)?;
		let value = if flags & 0x100 != 0 {
			let units = utf8_length(data, &mut position)?;
			let length = utf8_length(data, &mut position)?;
			if length > MAX_STRING_BYTES || units > MAX_STRING_BYTES {
				bail!("APK string exceeds 64 KiB");
			}
			let end = position
				.checked_add(length)
				.ok_or_else(|| anyhow!("APK UTF-8 extent overflow"))?;
			let text = std::str::from_utf8(
				data.get(position..end)
					.ok_or_else(|| anyhow!("truncated APK UTF-8 string"))?,
			)
			.context("APK string is not UTF-8")?;
			if data.get(end) != Some(&0) || text.encode_utf16().count() != units {
				bail!("APK UTF-8 terminator or UTF-16 length is inconsistent");
			}
			text.to_owned()
		} else {
			if position % 2 != 0 {
				bail!("APK UTF-16 string offset is misaligned");
			}
			let units = utf16_length(data, &mut position)?;
			if units > MAX_STRING_BYTES {
				bail!("APK UTF-16 string exceeds its unit budget");
			}
			let byte_length = units
				.checked_mul(2)
				.ok_or_else(|| anyhow!("APK UTF-16 extent overflow"))?;
			let end = position
				.checked_add(byte_length)
				.ok_or_else(|| anyhow!("APK UTF-16 extent overflow"))?;
			let raw = data
				.get(position..end)
				.ok_or_else(|| anyhow!("truncated APK UTF-16 string"))?;
			if u16_at(data, end)? != 0 {
				bail!("APK UTF-16 string has no terminating zero");
			}
			let units = raw
				.as_chunks::<2>()
				.0
				.iter()
				.map(|word| u16::from_le_bytes([word[0], word[1]]))
				.collect::<Vec<_>>();
			String::from_utf16(&units)
				.context("APK string contains an unpaired UTF-16 surrogate")?
		};
		if value.len() > MAX_STRING_BYTES || value.contains('\0') {
			bail!("APK decoded string is oversized or contains NUL");
		}
		decoded_bytes = decoded_bytes
			.checked_add(value.len())
			.ok_or_else(|| anyhow!("APK decoded string budget overflow"))?;
		if decoded_bytes > MAX_DECODED_STRING_BYTES {
			bail!("APK decoded string pool exceeds 8 MiB");
		}
		strings.push(value);
	}
	Ok(strings)
}

fn string(strings: &[String], index: u32) -> Result<&str> {
	strings
		.get(index as usize)
		.map(String::as_str)
		.ok_or_else(|| anyhow!("APK string index is outside its pool"))
}

fn optional_string(strings: &[String], index: u32) -> Result<Option<&str>> {
	if index == NONE {
		Ok(None)
	} else {
		Ok(Some(string(strings, index)?))
	}
}

struct Budget {
	referenced: usize,
	retained: usize,
	deadline: Instant,
}

impl Budget {
	fn reference(&mut self, text: &str) -> Result<()> {
		self.referenced = self
			.referenced
			.checked_add(text.len())
			.ok_or_else(|| anyhow!("APK referenced text budget overflow"))?;
		if self.referenced > MAX_REFERENCE_BYTES || Instant::now() >= self.deadline {
			bail!("APK declarations exceed referenced-text or work budget");
		}
		Ok(())
	}

	fn retain(&mut self, value: &Value) -> Result<()> {
		self.retained = self
			.retained
			.checked_add(serde_json::to_vec(value)?.len())
			.ok_or_else(|| anyhow!("application declaration storage budget overflow"))?;
		if self.retained > MAX_RETAINED_BYTES {
			bail!("application declarations exceed 16 MiB retained JSON budget");
		}
		Ok(())
	}
}

struct Attribute<'a> {
	namespace: Option<&'a str>,
	name: &'a str,
	raw: Option<&'a str>,
	string_value: Option<&'a str>,
	value_type: u8,
	data: u32,
	resource_id: Option<u32>,
	offset: usize,
}

impl Attribute<'_> {
	fn typed(&self) -> Value {
		match self.value_type {
			0 => json!({"type":"null","data":self.data}),
			1 => {
				json!({"type":"reference","resource_id":format!("0x{:08x}", self.data),"resolved":false})
			}
			2 => {
				json!({"type":"attribute_reference","resource_id":format!("0x{:08x}", self.data),"resolved":false})
			}
			3 => json!({"type":"string","value":self.string_value}),
			7 => {
				json!({"type":"dynamic_reference","resource_id":format!("0x{:08x}", self.data),"resolved":false})
			}
			8 => {
				json!({"type":"dynamic_attribute_reference","resource_id":format!("0x{:08x}", self.data),"resolved":false})
			}
			16 => json!({"type":"int_decimal","value":self.data as i32}),
			17 => json!({"type":"int_hex","value":format!("0x{:08x}", self.data)}),
			18 => json!({"type":"boolean","value":self.data != 0,"data":self.data}),
			other => {
				json!({"type":"uninterpreted","type_code":other,"data_hex":format!("0x{:08x}", self.data)})
			}
		}
	}

	fn report(&self) -> Value {
		json!({
			"namespace":self.namespace,"name":self.name,"raw_value":self.raw,
			"typed_value":self.typed(),"resource_id":self.resource_id.map(|id| format!("0x{id:08x}")),
			"source_byte_offset":self.offset
		})
	}
}

fn parse_attributes<'a>(
	chunk: &Chunk<'_>,
	chunk_offset: usize,
	strings: &'a [String],
	resource_ids: &[u32],
	active_namespaces: &[(u32, u32, usize)],
	budget: &mut Budget,
) -> Result<Vec<Attribute<'a>>> {
	if chunk.header != 16 || chunk.bytes.len() < 36 {
		bail!("APK start-element chunk has an unsupported header");
	}
	let extension = chunk.header;
	let start = usize::from(u16_at(chunk.bytes, extension + 8)?);
	let size = usize::from(u16_at(chunk.bytes, extension + 10)?);
	let count = usize::from(u16_at(chunk.bytes, extension + 12)?);
	if start != 20 || size != 20 || count > 128 {
		bail!("APK attributes have unsupported extensions or exceed 128 per element");
	}
	for offset in [14, 16, 18] {
		if usize::from(u16_at(chunk.bytes, extension + offset)?) > count {
			bail!("APK special attribute index exceeds the attribute list");
		}
	}
	let first = extension + start;
	if first + count * size != chunk.bytes.len() {
		bail!("APK attribute array does not match its chunk extent");
	}
	let mut names = HashSet::new();
	let mut attributes = Vec::with_capacity(count);
	for index in 0..count {
		let offset = first + index * size;
		let namespace = optional_string(strings, u32_at(chunk.bytes, offset)?)?;
		let name_index = u32_at(chunk.bytes, offset + 4)?;
		let name = string(strings, name_index)?;
		if name.is_empty() {
			bail!("APK attribute name is empty");
		}
		let raw = optional_string(strings, u32_at(chunk.bytes, offset + 8)?)?;
		if u16_at(chunk.bytes, offset + 12)? != 8 || chunk.bytes.get(offset + 14) != Some(&0) {
			bail!("APK typed attribute has an unsupported value header");
		}
		let value_type = *chunk
			.bytes
			.get(offset + 15)
			.ok_or_else(|| anyhow!("truncated APK value type"))?;
		let data = u32_at(chunk.bytes, offset + 16)?;
		let string_value = if value_type == 3 {
			Some(string(strings, data)?)
		} else {
			None
		};
		budget.reference(name)?;
		for text in [namespace, raw, string_value].into_iter().flatten() {
			budget.reference(text)?;
		}
		if let Some(namespace) = namespace {
			if !active_namespaces
				.iter()
				.any(|(_, uri, _)| string(strings, *uri).is_ok_and(|active| active == namespace))
			{
				bail!("APK attribute namespace has no active declaration");
			}
		}
		if !names.insert((namespace, name)) {
			bail!("APK element contains duplicate namespace/name attributes");
		}
		attributes.push(Attribute {
			namespace,
			name,
			raw,
			string_value,
			value_type,
			data,
			resource_id: resource_ids.get(name_index as usize).copied(),
			offset: chunk_offset + offset,
		});
	}
	Ok(attributes)
}

fn declared(attributes: &[Attribute<'_>], namespace: Option<&str>, name: &str) -> Option<Value> {
	attributes
		.iter()
		.find(|attribute| attribute.namespace == namespace && attribute.name == name)
		.map(Attribute::typed)
}

fn parse_axml(bytes: &[u8], deadline: Instant) -> Result<ManifestReport> {
	let root = chunk_at(bytes, 0)?;
	if root.kind != 3 || root.header != 8 || root.bytes.len() != bytes.len() {
		bail!("APK manifest must be one complete standard Android binary XML document");
	}
	let pool = chunk_at(bytes, root.header)?;
	let strings = string_pool(&pool)?;
	let mut position = root.header + pool.bytes.len();
	let mut resource_ids = Vec::new();
	let mut saw_resource_map = false;
	let mut stack: Vec<(u32, u32, usize)> = Vec::new();
	let mut namespaces: Vec<(u32, u32, usize)> = Vec::new();
	let mut namespace_events = 0_usize;
	let mut seen_root = false;
	let mut closed_root = false;
	let mut nodes = 0_usize;
	let mut cdata_nodes = 0_usize;
	let mut applications = 0_usize;
	let mut summary = json!({});
	let mut sdk = Vec::new();
	let mut components = Vec::new();
	let mut permissions = Vec::new();
	let mut attributes = Vec::new();
	let mut budget = Budget {
		referenced: 0,
		retained: 0,
		deadline,
	};
	while position < bytes.len() {
		if Instant::now() >= deadline {
			bail!("APK manifest exceeded its parsing deadline");
		}
		let chunk = chunk_at(bytes, position)?;
		if chunk.kind == 0x180 {
			if saw_resource_map || seen_root || !namespaces.is_empty() || chunk.header != 8 {
				bail!("APK resource map is duplicated, misplaced or extended");
			}
			let count = (chunk.bytes.len() - chunk.header) / 4;
			if count > strings.len() {
				bail!("APK resource map exceeds its string pool");
			}
			resource_ids = (0..count)
				.map(|index| u32_at(chunk.bytes, chunk.header + index * 4))
				.collect::<Result<Vec<_>>>()?;
			saw_resource_map = true;
		} else {
			if chunk.header != 16 {
				bail!("APK XML node has an unsupported header");
			}
			optional_string(&strings, u32_at(chunk.bytes, 12)?)?;
			match chunk.kind {
				0x100 | 0x101 => {
					if chunk.bytes.len() != 24 {
						bail!("APK namespace chunk has an invalid extent");
					}
					let prefix = u32_at(chunk.bytes, 16)?;
					let uri = u32_at(chunk.bytes, 20)?;
					if let Some(prefix) = optional_string(&strings, prefix)? {
						budget.reference(prefix)?;
					}
					let uri_text = string(&strings, uri)?;
					budget.reference(uri_text)?;
					if uri_text.is_empty() {
						bail!("APK namespace URI is empty");
					}
					namespace_events += 1;
					if namespace_events > 512 {
						bail!("APK manifest exceeds its namespace event budget");
					}
					if chunk.kind == 0x100 {
						if closed_root || namespaces.len() >= 64 {
							bail!("APK namespace is misplaced or exceeds active namespace budget");
						}
						namespaces.push((prefix, uri, stack.len()));
					} else if namespaces.pop() != Some((prefix, uri, stack.len())) {
						bail!("APK namespace end does not match its start or element depth");
					}
				}
				0x102 => {
					if closed_root || stack.len() >= 64 {
						bail!("APK contains a second root or exceeds 64 element levels");
					}
					let ns_index = u32_at(chunk.bytes, 16)?;
					let name_index = u32_at(chunk.bytes, 20)?;
					let namespace = optional_string(&strings, ns_index)?;
					let name = string(&strings, name_index)?;
					budget.reference(name)?;
					if name.is_empty() {
						bail!("APK element name is empty");
					}
					if let Some(namespace) = namespace {
						budget.reference(namespace)?;
						if !namespaces.iter().any(|(_, uri, _)| {
							string(&strings, *uri).is_ok_and(|active| active == namespace)
						}) {
							bail!("APK element namespace has no active declaration");
						}
					}
					if stack.is_empty() {
						if seen_root || namespace.is_some() || name != "manifest" {
							bail!("APK document root must be one unqualified manifest element");
						}
						seen_root = true;
					}
					nodes += 1;
					if nodes > MAX_ROWS {
						bail!("APK manifest exceeds 20000 elements");
					}
					let parsed = parse_attributes(
						&chunk,
						position,
						&strings,
						&resource_ids,
						&namespaces,
						&mut budget,
					)?;
					if attributes.len().saturating_add(parsed.len()) > MAX_ROWS {
						bail!("APK manifest exceeds 20000 attribute declarations");
					}
					let line = u32_at(chunk.bytes, 8)?;
					for attribute in &parsed {
						let row = json!({
							"element":name,"element_namespace":namespace,"element_depth":stack.len(),
							"source_chunk_offset":position,"source_line":line,"attribute":attribute.report()
						});
						budget.retain(&row)?;
						attributes.push(row);
					}
					if stack.is_empty() {
						summary = json!({
							"package":declared(&parsed, None, "package"),
							"version_code":declared(&parsed, Some(ANDROID_NS), "versionCode"),
							"version_name":declared(&parsed, Some(ANDROID_NS), "versionName")
						});
						budget.retain(&summary)?;
					}
					let parent_name = stack
						.last()
						.map(|(_, index, _)| string(&strings, *index))
						.transpose()?;
					let top_level = namespace.is_none() && stack.len() == 1;
					if top_level && name == "application" {
						applications += 1;
					}
					if top_level && name == "uses-sdk" {
						if sdk.len() >= 32 {
							bail!("APK has more than 32 SDK declarations");
						}
						let row = json!({
							"source_chunk_offset":position,
							"min_sdk":declared(&parsed, Some(ANDROID_NS), "minSdkVersion"),
							"target_sdk":declared(&parsed, Some(ANDROID_NS), "targetSdkVersion"),
							"max_sdk":declared(&parsed, Some(ANDROID_NS), "maxSdkVersion")
						});
						budget.retain(&row)?;
						sdk.push(row);
					}
					let component = namespace.is_none()
						&& stack.len() == 2
						&& parent_name == Some("application")
						&& matches!(
							name,
							"activity" | "activity-alias" | "service" | "receiver" | "provider"
						);
					let permission = top_level
						&& matches!(
							name,
							"uses-permission"
								| "uses-permission-sdk-23"
								| "uses-permission-sdk-m"
								| "permission" | "permission-group"
								| "permission-tree"
						);
					if component || permission {
						let row = json!({
							"element":name,"source_chunk_offset":position,"source_line":line,
							"name_declaration":declared(&parsed, Some(ANDROID_NS), "name"),
							"attributes":parsed.iter().map(Attribute::report).collect::<Vec<_>>()
						});
						budget.retain(&row)?;
						if component {
							components.push(row);
						} else {
							permissions.push(row);
						}
					}
					stack.push((ns_index, name_index, position));
				}
				0x103 => {
					if chunk.bytes.len() != 24 {
						bail!("APK end-element chunk has an invalid extent");
					}
					let namespace = u32_at(chunk.bytes, 16)?;
					let name = u32_at(chunk.bytes, 20)?;
					optional_string(&strings, namespace)?;
					string(&strings, name)?;
					let (expected_namespace, expected_name, _) = stack
						.pop()
						.ok_or_else(|| anyhow!("APK element ends without a matching start"))?;
					if namespace != expected_namespace || name != expected_name {
						bail!("APK end element does not match its start");
					}
					if namespaces.iter().any(|(_, _, depth)| *depth > stack.len()) {
						bail!("APK element ended with an unclosed inner namespace");
					}
					if stack.is_empty() {
						closed_root = true;
					}
				}
				0x104 => {
					if chunk.bytes.len() != 28
						|| stack.is_empty()
						|| u16_at(chunk.bytes, 20)? != 8
						|| chunk.bytes.get(22) != Some(&0)
					{
						bail!("APK CDATA node is malformed or outside the root");
					}
					budget.reference(string(&strings, u32_at(chunk.bytes, 16)?)?)?;
					if chunk.bytes.get(23) == Some(&3) {
						budget.reference(string(&strings, u32_at(chunk.bytes, 24)?)?)?;
					}
					cdata_nodes += 1;
					if cdata_nodes > MAX_ROWS {
						bail!("APK exceeds its CDATA node budget");
					}
				}
				_ => bail!("APK binary XML contains an unsupported chunk type"),
			}
		}
		position += chunk.bytes.len();
	}
	if !seen_root || !closed_root || !stack.is_empty() || !namespaces.is_empty() {
		bail!("APK binary XML has an incomplete root or namespace scope");
	}
	let object = summary
		.as_object_mut()
		.ok_or_else(|| anyhow!("APK summary is unavailable"))?;
	object.insert("sdk_declarations".into(), json!(sdk));
	object.insert("application_declaration_count".into(), json!(applications));
	object.insert(
		"component_declaration_count".into(),
		json!(components.len()),
	);
	object.insert(
		"permission_declaration_count".into(),
		json!(permissions.len()),
	);
	object.insert("element_count".into(), json!(nodes));
	object.insert(
		"attribute_declaration_count".into(),
		json!(attributes.len()),
	);
	object.insert("uninterpreted_cdata_nodes".into(), json!(cdata_nodes));
	object.insert("resource_ids_resolved".into(), json!(false));
	Ok(ManifestReport {
		format: "android_binary_xml_declarations",
		summary,
		components,
		permissions,
		attributes,
	})
}

struct JarHeader {
	name: String,
	value: Vec<u8>,
	line: usize,
	offset: usize,
}

fn finish_header(
	header: JarHeader,
	attributes: &mut Vec<Value>,
	budget: &mut Budget,
) -> Result<()> {
	let value =
		String::from_utf8(header.value).context("JAR unfolded main attribute is not UTF-8")?;
	if value.contains('\0') {
		bail!("JAR main attribute contains NUL");
	}
	let row = json!({
		"name":header.name,"value":value,"source_first_line":header.line,
		"source_byte_offset":header.offset
	});
	budget.retain(&row)?;
	attributes.push(row);
	Ok(())
}

fn jar_value(attributes: &[Value], name: &str) -> Option<String> {
	attributes
		.iter()
		.find(|row| {
			row["name"]
				.as_str()
				.is_some_and(|value| value.eq_ignore_ascii_case(name))
		})
		.and_then(|row| row["value"].as_str())
		.map(str::to_owned)
}

fn parse_jar(bytes: &[u8], deadline: Instant) -> Result<ManifestReport> {
	let mut position = 0_usize;
	let mut line_number = 0_usize;
	let mut attributes = Vec::new();
	let mut names = HashSet::new();
	let mut pending: Option<JarHeader> = None;
	let mut terminated = false;
	let mut budget = Budget {
		referenced: 0,
		retained: 0,
		deadline,
	};
	while position < bytes.len() {
		if Instant::now() >= deadline {
			bail!("JAR manifest exceeded its parsing deadline");
		}
		let start = position;
		let end = position
			+ bytes[position..]
				.iter()
				.position(|byte| *byte == b'\r' || *byte == b'\n')
				.ok_or_else(|| anyhow!("JAR main section has an unterminated physical line"))?;
		let line = &bytes[start..end];
		position = end + 1;
		if bytes[end] == b'\r' && bytes.get(position) == Some(&b'\n') {
			position += 1;
		}
		line_number += 1;
		if line.len() > 72 {
			bail!("JAR physical main-section line exceeds 72 bytes");
		}
		if line.is_empty() {
			if let Some(header) = pending.take() {
				finish_header(header, &mut attributes, &mut budget)?;
			}
			terminated = true;
			break;
		}
		if line.first() == Some(&b' ') {
			let header = pending
				.as_mut()
				.ok_or_else(|| anyhow!("JAR continuation has no preceding attribute"))?;
			if header.value.len().saturating_add(line.len() - 1) > 65_535 {
				bail!("JAR unfolded attribute exceeds 65535 bytes");
			}
			// Unfold bytes before UTF-8 decoding: jar may split a multibyte
			// code point at the physical 72-byte boundary.
			header.value.extend_from_slice(&line[1..]);
			continue;
		}
		if let Some(header) = pending.take() {
			finish_header(header, &mut attributes, &mut budget)?;
		}
		if names.len() >= 256 {
			bail!("JAR main section exceeds 256 attributes");
		}
		let colon = line
			.iter()
			.position(|byte| *byte == b':')
			.ok_or_else(|| anyhow!("JAR main attribute has no colon"))?;
		let name_bytes = &line[..colon];
		if name_bytes.is_empty()
			|| name_bytes.len() > 70
			|| !name_bytes[0].is_ascii_alphanumeric()
			|| !name_bytes
				.iter()
				.all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
			|| line.get(colon + 1) != Some(&b' ')
		{
			bail!("JAR main attribute has an invalid name or separator");
		}
		let name = std::str::from_utf8(name_bytes)?.to_owned();
		if name.eq_ignore_ascii_case("Name") {
			bail!("JAR per-entry Name attribute appeared in the main section");
		}
		if !names.insert(name.to_ascii_lowercase()) {
			bail!("JAR main section contains duplicate case-insensitive attribute names");
		}
		pending = Some(JarHeader {
			name,
			value: line[colon + 2..].to_vec(),
			line: line_number,
			offset: start,
		});
	}
	if !terminated {
		bail!("JAR main section must end with an empty line");
	}
	if attributes
		.first()
		.and_then(|row| row["name"].as_str())
		.is_none_or(|name| !name.eq_ignore_ascii_case("Manifest-Version"))
	{
		bail!("JAR main section must begin with Manifest-Version");
	}
	let version = jar_value(&attributes, "Manifest-Version")
		.ok_or_else(|| anyhow!("JAR version is unavailable"))?;
	if version.is_empty()
		|| !version
			.split('.')
			.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
	{
		bail!("JAR Manifest-Version is not a numeric dotted version");
	}
	let summary = json!({
		"manifest_version":version,"main_class":jar_value(&attributes,"Main-Class"),
		"automatic_module_name":jar_value(&attributes,"Automatic-Module-Name"),
		"class_path_declaration":jar_value(&attributes,"Class-Path"),
		"multi_release_declaration":jar_value(&attributes,"Multi-Release"),
		"main_attribute_count":attributes.len(),"main_section_bytes":position,
		"unparsed_per_entry_bytes":bytes.len()-position,
		"class_files_inspected":false
	});
	Ok(ManifestReport {
		format: "jar_manifest_main_section",
		summary,
		components: Vec::new(),
		permissions: Vec::new(),
		attributes,
	})
}
