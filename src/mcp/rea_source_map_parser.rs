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

//! Source-map JSON, checked Base64 VLQ and indexed-section decoding. The
//! representation preserves original indexes and coincident mapping ambiguity.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

use super::{
	analysis_identity, sha256, validate_request, GeneratedPosition, SourceMapCollection,
	WorkerRequest, MAX_MAPPINGS, MAX_RESPONSE_BYTES, PROFILE,
};

#[path = "rea_source_map_content.rs"]
mod content;

const MAX_DECLARATIONS: usize = 16_384;
const MAX_SECTIONS: usize = 256;
const MAX_SECTION_DEPTH: usize = 8;
const MAX_TEXT_FIELD: usize = 16 * 1024;
const MAX_GENERATED_LINES: usize = 1_000_000;

// Struct deserialization rejects duplicate recognized members. Unknown extension
// members are ignored, as required for extensible source-map documents.
#[derive(Deserialize)]
struct RawMap {
	version: u32,
	file: Option<String>,
	#[serde(rename = "sourceRoot")]
	source_root: Option<String>,
	sources: Option<Vec<Option<String>>>,
	names: Option<Vec<String>>,
	mappings: Option<String>,
	#[serde(rename = "sourcesContent")]
	sources_content: Option<Vec<Option<String>>>,
	#[serde(rename = "ignoreList")]
	ignore_list: Option<Vec<usize>>,
	#[serde(rename = "x_google_ignoreList")]
	google_ignore_list: Option<Vec<usize>>,
	sections: Option<Vec<Section>>,
}

#[derive(Deserialize)]
struct Section {
	offset: Offset,
	map: Option<Box<RawMap>>,
	url: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
struct Offset {
	line: u32,
	column: u32,
}

#[derive(Clone)]
struct Source {
	section: String,
	local_index: usize,
	name: Option<String>,
	root: Option<String>,
	content_sha256: Option<String>,
	content_bytes: Option<usize>,
	content_index: Option<content::LineIndex>,
	ignored: bool,
}

#[derive(Clone)]
struct Name {
	section: String,
	local_index: usize,
	value: String,
}

#[derive(Clone)]
struct Mapping {
	line: u32,
	column: u32,
	source: Option<usize>,
	original_line: Option<u32>,
	original_column: Option<u32>,
	name: Option<usize>,
	section: String,
}

#[derive(Default)]
struct Decoded {
	sources: Vec<Source>,
	names: Vec<Name>,
	mappings: Vec<Mapping>,
	sections: usize,
	leaf_maps: usize,
	embedded_lines: usize,
}

fn short_text(value: Option<&str>) -> Result<()> {
	if value.is_some_and(|v| v.len() > MAX_TEXT_FIELD) {
		bail!("source-map declaration exceeds 16 KiB");
	}
	Ok(())
}

fn base64_digit(byte: u8) -> Result<u32> {
	match byte {
		b'A'..=b'Z' => Ok(u32::from(byte - b'A')),
		b'a'..=b'z' => Ok(u32::from(byte - b'a') + 26),
		b'0'..=b'9' => Ok(u32::from(byte - b'0') + 52),
		b'+' => Ok(62),
		b'/' => Ok(63),
		_ => bail!("invalid source-map Base64 VLQ character"),
	}
}

fn vlq(bytes: &[u8], cursor: &mut usize) -> Result<i64> {
	let mut value = 0_u64;
	for digit in 0..7 {
		let encoded = *bytes.get(*cursor).context("unterminated source-map VLQ")?;
		*cursor += 1;
		let part = base64_digit(encoded)?;
		value |= u64::from(part & 31) << (digit * 5);
		if value > u64::from(u32::MAX) {
			bail!("source-map VLQ exceeds 32 bits");
		}
		if part & 32 == 0 {
			let magnitude = (value >> 1) as i64;
			// ECMA-426 reserves signed zero for the minimum signed 32-bit value.
			return Ok(if value == 1 {
				i64::from(i32::MIN)
			} else if value & 1 == 1 {
				-magnitude
			} else {
				magnitude
			});
		}
	}
	bail!("source-map VLQ exceeds seven encoded digits")
}

fn add_delta(previous: i64, delta: i64, field: &str) -> Result<i64> {
	let result = previous
		.checked_add(delta)
		.context("source-map delta overflow")?;
	if !(0..i64::from(u32::MAX)).contains(&result) {
		bail!("source-map {field} is negative or exceeds the bounded coordinate range");
	}
	Ok(result)
}

fn offset_position(line: u32, column: u32, offset: Offset) -> Result<(u32, u32)> {
	let global_line = line
		.checked_add(offset.line)
		.context("source-map section line overflow")?;
	if global_line == u32::MAX {
		bail!("source-map section line cannot be represented one-based");
	}
	let global_column = if line == 0 {
		column
			.checked_add(offset.column)
			.context("source-map section column overflow")?
	} else {
		column
	};
	Ok((global_line, global_column))
}

fn decode_leaf(map: RawMap, offset: Offset, section: &str, decoded: &mut Decoded) -> Result<()> {
	let sources = map.sources.unwrap_or_default();
	let names = map.names.unwrap_or_default();
	let content = map.sources_content.unwrap_or_default();
	let ignore_list = map
		.ignore_list
		.or(map.google_ignore_list)
		.unwrap_or_default();
	if decoded.sources.len() + sources.len() > MAX_DECLARATIONS
		|| decoded.names.len() + names.len() > MAX_DECLARATIONS
		|| content.len() > MAX_DECLARATIONS
		|| ignore_list.len() > MAX_DECLARATIONS
	{
		bail!("source-map declarations exceed 16384 rows");
	}
	if ignore_list.iter().any(|&index| index >= sources.len()) {
		bail!("source-map ignoreList index is outside sources");
	}
	let ignored: BTreeSet<_> = ignore_list.into_iter().collect();
	let source_start = decoded.sources.len();
	let name_start = decoded.names.len();
	let source_count = sources.len();
	let name_count = names.len();
	for (index, name) in sources.into_iter().enumerate() {
		short_text(name.as_deref())?;
		let source_content = content.get(index).and_then(Option::as_deref);
		let content_index = source_content
			.map(|text| content::LineIndex::from_text(text, &mut decoded.embedded_lines))
			.transpose()?;
		decoded.sources.push(Source {
			section: section.to_owned(),
			local_index: index,
			name,
			root: map.source_root.clone(),
			content_sha256: source_content.map(|s| sha256(s.as_bytes())),
			content_bytes: source_content.map(str::len),
			content_index,
			ignored: ignored.contains(&index),
		});
	}
	for (index, value) in names.into_iter().enumerate() {
		short_text(Some(&value))?;
		decoded.names.push(Name {
			section: section.to_owned(),
			local_index: index,
			value,
		});
	}
	let mappings = map
		.mappings
		.context("regular source map requires a mappings string")?;
	let mut source = 0_i64;
	let mut original_line = 0_i64;
	let mut original_column = 0_i64;
	let mut name = 0_i64;
	for (line, encoded_line) in mappings.split(';').enumerate() {
		if line >= MAX_GENERATED_LINES {
			bail!("source-map mappings exceed 1000000 generated lines");
		}
		let mut column = 0_i64;
		if encoded_line.is_empty() {
			continue;
		}
		for segment in encoded_line.split(',') {
			if decoded.mappings.len() >= MAX_MAPPINGS {
				bail!("source-map mappings exceed 200000 segments");
			}
			let bytes = segment.as_bytes();
			let mut cursor = 0;
			let mut fields = [0_i64; 5];
			let mut length = 0;
			while cursor < bytes.len() {
				if length == fields.len() {
					bail!("source-map segment has more than five fields");
				}
				fields[length] = vlq(bytes, &mut cursor)?;
				length += 1;
			}
			if !matches!(length, 1 | 4 | 5) {
				bail!("source-map segment must contain one, four or five fields");
			}
			column = add_delta(column, fields[0], "generated column")?;
			let (global_line, global_column) = offset_position(line as u32, column as u32, offset)?;
			let mut mapping = Mapping {
				line: global_line,
				column: global_column,
				source: None,
				original_line: None,
				original_column: None,
				name: None,
				section: section.to_owned(),
			};
			if length >= 4 {
				source = add_delta(source, fields[1], "source index")?;
				original_line = add_delta(original_line, fields[2], "original line")?;
				original_column = add_delta(original_column, fields[3], "original column")?;
				if source as usize >= source_count {
					bail!("source-map source index is outside sources");
				}
				mapping.source = Some(source_start + source as usize);
				mapping.original_line = Some(original_line as u32);
				mapping.original_column = Some(original_column as u32);
			}
			if length == 5 {
				name = add_delta(name, fields[4], "name index")?;
				if name as usize >= name_count {
					bail!("source-map name index is outside names");
				}
				mapping.name = Some(name_start + name as usize);
			}
			decoded.mappings.push(mapping);
		}
	}
	decoded.leaf_maps += 1;
	Ok(())
}

fn decode_map(
	map: RawMap,
	offset: Offset,
	section: &str,
	depth: usize,
	decoded: &mut Decoded,
) -> Result<()> {
	if map.version != 3 {
		bail!("source-map version must be 3");
	}
	if depth > MAX_SECTION_DEPTH {
		bail!("source-map indexed nesting exceeds eight levels");
	}
	short_text(map.file.as_deref())?;
	short_text(map.source_root.as_deref())?;
	if let Some(sections) = map.sections {
		if map.mappings.is_some()
			|| map.sources.is_some()
			|| map.names.is_some()
			|| map.source_root.is_some()
			|| map.sources_content.is_some()
			|| map.ignore_list.is_some()
			|| map.google_ignore_list.is_some()
		{
			bail!("indexed source map cannot mix regular-map fields with sections");
		}
		decoded.sections = decoded
			.sections
			.checked_add(sections.len())
			.context("section count overflow")?;
		if decoded.sections > MAX_SECTIONS {
			bail!("source map exceeds 256 sections");
		}
		let mut previous_start = None;
		let mut previous_max = None;
		for (index, child) in sections.into_iter().enumerate() {
			if child.url.is_some() {
				bail!("external source-map section URLs are not followed");
			}
			let child_map = child
				.map
				.context("indexed section requires an embedded map")?;
			let position = offset_position(child.offset.line, child.offset.column, offset)?;
			if previous_start.is_some_and(|old| position <= old)
				|| previous_max.is_some_and(|old| position <= old)
			{
				bail!("source-map sections are unordered or their recorded mappings overlap");
			}
			let start_index = decoded.mappings.len();
			decode_map(
				*child_map,
				Offset {
					line: position.0,
					column: position.1,
				},
				&format!("{section}/sections/{index}/map"),
				depth + 1,
				decoded,
			)?;
			if let Some(last) = decoded.mappings[start_index..]
				.iter()
				.map(|m| (m.line, m.column))
				.max()
			{
				previous_max = Some(last);
			}
			previous_start = Some(position);
		}
		Ok(())
	} else {
		decode_leaf(map, offset, section, decoded)
	}
}

fn source_row(index: usize, source: &Source) -> Value {
	json!({"index":index,"section_pointer":source.section,"local_index":source.local_index,
		"source":source.name,"source_root":source.root,"ignored":source.ignored,
		"embedded_content": {"present":source.content_sha256.is_some(),
			"sha256":source.content_sha256,"bytes":source.content_bytes,
			"utf16_code_units":source.content_index.as_ref().map(content::LineIndex::utf16_units),
			"line_count":source.content_index.as_ref().map(content::LineIndex::line_count)},
		"source_opened":false,"url_resolved":false})
}

fn mapping_row(mapping: &Mapping, decoded: &Decoded) -> Value {
	let source = mapping.source.and_then(|i| decoded.sources.get(i));
	let name = mapping.name.and_then(|i| decoded.names.get(i));
	json!({"generated":{"line":mapping.line+1,"column":mapping.column},
	"section_pointer":mapping.section,"mapped":mapping.source.is_some(),
	"original": source.map(|s| {
		let offset = s.content_index.as_ref().and_then(|index| {
			index.offset(mapping.original_line?, mapping.original_column?)
		});
		let content_position = if s.content_index.is_none() {
			"content-unavailable"
		} else if offset.is_some() {
			"verified-in-embedded-text"
		} else {
			"outside-embedded-text"
		};
		json!({"source_index":mapping.source,"source":s.name,
			"source_root":s.root,"line":mapping.original_line.map(|v|v+1),
			"column":mapping.original_column,"offset":offset,"content_position":content_position,
			"name_index":mapping.name,"name":name.map(|n|&n.value),
			"ignored":s.ignored,"source_content_verified":offset.is_some()})
	})})
}

fn query_position(position: &GeneratedPosition, decoded: &Decoded) -> Result<Value> {
	let line = position.line - 1;
	let end = decoded
		.mappings
		.partition_point(|m| (m.line, m.column) <= (line, position.column));
	let Some(selected) = end.checked_sub(1).and_then(|i| decoded.mappings.get(i)) else {
		return Ok(
			json!({"requested":position,"status":"no_recorded_mapping","matched_generated_position":null,"mappings":[]}),
		);
	};
	let start = decoded.mappings[..end]
		.partition_point(|m| (m.line, m.column) < (selected.line, selected.column));
	if end - start > 256 {
		bail!("source-map query has more than 256 coincident mappings");
	}
	let rows: Vec<_> = decoded.mappings[start..end]
		.iter()
		.map(|m| mapping_row(m, decoded))
		.collect();
	Ok(
		json!({"requested":position,"status": if rows.len()>1 {"coincident_mappings"}
		else if selected.source.is_some() {"mapped"} else {"explicitly_unmapped"},
		"matched_generated_position":{"line":selected.line+1,"column":selected.column},"mappings":rows,
		"column_interpolated":false}),
	)
}

pub(super) fn report(request: &WorkerRequest) -> Result<Value> {
	validate_request(request)?;
	let digest = sha256(request.text.as_bytes());
	let identity = analysis_identity(&digest);
	if request
		.expected_analysis_sha256
		.as_ref()
		.is_some_and(|v| v != &identity)
	{
		bail!("source-map input or decoder identity changed");
	}
	let raw: RawMap = serde_json::from_str(&request.text)
		.context("invalid source-map JSON or duplicate contract member")?;
	let file = raw.file.clone();
	let indexed = raw.sections.is_some();
	let mut decoded = Decoded::default();
	decode_map(raw, Offset { line: 0, column: 0 }, "", 0, &mut decoded)?;
	// Negative generated-column deltas are legal when their cumulative position
	// stays nonnegative. Sort stably without losing coincident mapping records.
	decoded.mappings.sort_by_key(|m| (m.line, m.column));
	let total = match request.collection {
		SourceMapCollection::Summary => 0,
		SourceMapCollection::Sources => decoded.sources.len(),
		SourceMapCollection::Names => decoded.names.len(),
		SourceMapCollection::Mappings => decoded.mappings.len(),
	};
	if request.offset > total {
		bail!("source-map offset exceeds selected collection");
	}
	let end = total.min(request.offset + request.limit);
	let mut rows = Vec::with_capacity(end - request.offset);
	for index in request.offset..end {
		rows.push(match request.collection {
			SourceMapCollection::Sources => source_row(index, &decoded.sources[index]),
			SourceMapCollection::Names => {
				let name = &decoded.names[index];
				json!({
				"index":index,"section_pointer":name.section,"local_index":name.local_index,"name":name.value})
			}
			SourceMapCollection::Mappings => mapping_row(&decoded.mappings[index], &decoded),
			SourceMapCollection::Summary => {
				return Err(anyhow!("unexpected source-map summary row"))
			}
		});
	}
	let query = request
		.generated_position
		.as_ref()
		.map(|p| query_position(p, &decoded))
		.transpose()?;
	let output = json!({"record_format":PROFILE,"rea_evidence_compatible":false,
	"map_sha256":digest,"analysis_sha256":identity,"map_bytes":request.text.len(),
	"version":3,"file":file,"indexed":indexed,
	"counts":{"sources":decoded.sources.len(),"names":decoded.names.len(),
		"mappings":decoded.mappings.len(),"sections":decoded.sections,"leaf_maps":decoded.leaf_maps,
		"embedded_source_lines":decoded.embedded_lines,
		"explicitly_unmapped":decoded.mappings.iter().filter(|m|m.source.is_none()).count()},
	"collection":request.collection,"offset":request.offset,"total_rows":total,
	"next_offset":(end<total).then_some(end),"rows":rows,"query":query,
	"source_files_opened":0,"network_requests":0,"javascript_executed":false,
	"coordinate_convention":{"lines":"one_based","columns":"zero_based",
		"javascript_css_columns":"utf16_code_units","wasm_columns":"byte_offsets_on_one_line",
		"embedded_original_offsets":"utf16_code_units"},
	"coverage":"complete_decoding_of_admitted_mapping_declarations",
	"limitations":[
		"Mapping declarations are not proof that generated code corresponds to original source. Embedded position checks verify only UTF-16 coordinates in retained text, not source provenance or generated/original semantic correspondence.",
		"Source names and sourceRoot are preserved separately without URL resolution or network access. Embedded content hashes commit only the retained string bytes; absence and empty content remain distinct. No original or generated source file is opened or executed.",
		"Embedded UTF-16 offsets count CRLF, lone CR, LF, U+2028 and U+2029 line breaks, accept line ends and positions inside valid surrogate pairs, and never use UTF-8 byte offsets. The whole map admits at most 1000000 embedded source lines; overflow refuses the complete report.",
		"Queries select the greatest recorded generated position at or before the request across lines, preserve all coincident records, and never interpolate original columns or infer code spans.",
		"Only embedded indexed sections are supported. External section URLs, mixed regular/index fields, invalid indexes, unordered/overlapping recorded sections and resource overflow are errors.",
		"Unknown extension properties are ignored. VLQ encodings are limited to seven digits/32 value bits; coordinates must fit the bounded unsigned range. This is a native declaration report, not upstream REA Evidence."
	]});
	if serde_json::to_vec(&output)?.len() > MAX_RESPONSE_BYTES {
		bail!("source-map response exceeds 1 MiB; reduce the selected page");
	}
	Ok(output)
}
