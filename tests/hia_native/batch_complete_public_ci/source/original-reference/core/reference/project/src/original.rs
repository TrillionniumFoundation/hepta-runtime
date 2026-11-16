fn line_endpoint_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
	let schema = serde_json::json!({
		"description": "Line id \"N:hh\" from view/edit output, or an integer line number (negative counts from the end). Edit targets require ids.",
		"anyOf": [
			{ "type": "string" },
			{ "type": "integer", "format": "int64" }
		],
		"examples": ["12:a3", -1]
	});
	serde_json::from_value(schema).expect("static schema is valid JSON")
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BatchEditOperationType {
	Insert,
	Replace,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BatchEditOperation {
	/// `insert` (after `start`) or `replace` (`start`..`end`).
	pub operation: BatchEditOperationType,
	/// Line id in the ORIGINAL file: first line to replace, or the anchor to insert after
	/// (for `insert` also the integers 0 = file start, -1 = after the last line).
	#[schemars(schema_with = "line_endpoint_schema")]
	pub start: serde_json::Value,
	/// `replace` only: last line to replace (inclusive), as a line id. Default: `start`.
	#[serde(default)]
	#[schemars(schema_with = "line_endpoint_schema")]
	pub end: Option<serde_json::Value>,
	/// Raw text to insert or replace with, no line-id prefixes.
	#[serde(deserialize_with = "string_or_lines")]
	pub content: String,
}

/// Accept content as a string or as a list of lines. A list names exactly one
/// block of text, so joining it beats rejecting the call and being re-sent the
/// same edit as a string.
fn string_or_lines<'de, D>(deserializer: D) -> Result<String, D::Error>
where
	D: serde::Deserializer<'de>,
{
	match serde_json::Value::deserialize(deserializer)? {
		serde_json::Value::String(s) => Ok(s),
		serde_json::Value::Array(items) => items
			.iter()
			.map(|item| match item {
				serde_json::Value::String(s) => Ok(s.as_str()),
				other => Err(serde::de::Error::custom(format!(
					"content list must hold strings, found {other}"
				))),
			})
			.collect::<Result<Vec<_>, _>>()
			.map(|lines| lines.join("\n")),
		other => Err(serde::de::Error::custom(format!(
			"content must be a string or a list of lines, found {other}"
		))),
	}
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct BatchEditParams {
	/// File to edit (ssh://user@host:port/path for remote).
	pub path: String,
	/// Operations on this one file (max 50).
	#[schemars(length(max = 50))]
	pub operations: Vec<BatchEditOperation>,
}

/// The tool edits one file, so callers sometimes carry `path` on each operation
/// instead of at the top level. When every operation names the same file that is
/// the file to edit, so it is hoisted rather than refused; disagreeing paths stay
/// an error because no single target is named.
impl<'de> Deserialize<'de> for BatchEditParams {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		#[derive(Deserialize)]
		struct Raw {
			#[serde(default)]
			path: Option<String>,
			operations: Vec<serde_json::Value>,
		}

		let mut raw = Raw::deserialize(deserializer)?;
		let mut per_op: Vec<String> = Vec::new();
		for op in &mut raw.operations {
			if let Some(obj) = op.as_object_mut() {
				if let Some(serde_json::Value::String(p)) = obj.remove("path") {
					per_op.push(p);
				}
			}
		}

		let path = match raw.path {
			Some(p) => p,
			None => {
				let mut unique: Vec<&String> = Vec::new();
				for p in &per_op {
					if !unique.contains(&p) {
						unique.push(p);
					}
				}
				match unique.as_slice() {
					[only] => (*only).clone(),
					[] => return Err(serde::de::Error::missing_field("path")),
					_ => return Err(serde::de::Error::custom(
						"batch_edit edits a single file, but the operations name different paths; \
							 issue one batch_edit per file",
					)),
				}
			}
		};

		let operations = raw
			.operations
			.into_iter()
			.map(serde_json::from_value::<BatchEditOperation>)
			.collect::<Result<Vec<_>, _>>()
			.map_err(serde::de::Error::custom)?;

		Ok(BatchEditParams { path, operations })
	}
}

