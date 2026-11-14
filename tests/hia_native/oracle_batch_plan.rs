// Copyright 2026 Muvon Un Limited
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

//! Actual original pure batch parsing, endpoint verification and error aggregation.
//! The caller supplies the post-read normalized line slice. Filesystem effects,
//! shared locks, conflict detection and mutation are outside this oracle.
#![allow(dead_code, unused_variables)]
use std::io::{self, Read, Write};

mod utils {
	pub mod line_hash {
		include!(concat!(
			env!("HIA_REFERENCE_RUNTIME"),
			"/src/utils/line_hash.rs"
		));
	}
}

#[rustfmt::skip]
mod original {
use serde_json::Value;
use crate::utils::line_hash::{line_id_at, verify_line_id};
// The copied blocks return the exact anyhow display string. The adapter owns
// only the error carrier, not an alternative decision or error formatter.
macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*)) }; }
struct McpToolCall { parameters: Value }
// Batch operation structures for the new single-file, multi-operation approach
#[derive(Debug, Clone)]
struct BatchOperation {
	operation_type: OperationType,
	line_range: LineRange,
	content: String,
	operation_index: usize,
}

// Unresolved batch operation with endpoints not yet verified against the file
#[derive(Debug, Clone)]
struct UnresolvedBatchOperation {
	operation_type: OperationType,
	line_range: UnresolvedLineRange,
	content: String,
	operation_index: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum OperationType {
	Insert,
	Replace,
}

#[derive(Debug, Clone)]
enum LineRange {
	Single(usize),       // Insert after this line (0 = beginning of file)
	Range(usize, usize), // Replace this range (inclusive, 1-indexed)
}

#[derive(Debug, Clone)]
enum UnresolvedLineRange {
	/// Insert anchor without content to verify: 0 = file start, -1 = after last line.
	Anchor(i64),
	/// Insert after this line id ("N:hh", verified against the file).
	IdAnchor { line: usize, hash: String },
	/// Replace this id range (inclusive; both endpoints verified).
	IdRange {
		start: (usize, String),
		end: (usize, String),
	},
}

// Resolve an unresolved range to concrete line positions, verifying every line id
// against the current file content. A stale id fails with a self-healing error
// (fresh context + relocation candidates) built by `verify_line_id`.
fn resolve_unresolved_line_range(
	unresolved: &UnresolvedLineRange,
	total_lines: usize,
	lines: &[&str],
) -> Result<LineRange, String> {
	match unresolved {
		UnresolvedLineRange::Anchor(0) => Ok(LineRange::Single(0)),
		UnresolvedLineRange::Anchor(-1) => Ok(LineRange::Single(total_lines)),
		UnresolvedLineRange::Anchor(n) => Err(format!(
			"Invalid insert anchor {n}: use 0 (file start), -1 (end), or a line id like \"12:a3\""
		)),
		UnresolvedLineRange::IdAnchor { line, hash } => {
			let resolved = verify_line_id(*line, hash, lines)?;
			Ok(LineRange::Single(resolved))
		}
		UnresolvedLineRange::IdRange { start, end } => {
			// Verify both endpoints before failing: a range with two bad ids must
			// surface both, or the caller fixes one, retries, and only then sees
			// the other.
			let (s, e) = match (
				verify_line_id(start.0, &start.1, lines),
				verify_line_id(end.0, &end.1, lines),
			) {
				(Ok(s), Ok(e)) => (s, e),
				(s, e) => {
					let errs: Vec<String> = [s.err(), e.err()].into_iter().flatten().collect();
					return Err(errs.join("\n"));
				}
			};
			if s > e {
				return Err(format!(
					"Range is reversed: start \"{}:{}\" is after end \"{}:{}\"; swap them.",
					start.0, start.1, end.0, end.1
				));
			}
			Ok(LineRange::Range(s, e))
		}
	}
}

fn parse_line_range(
	start_val: &Value,
	end_val: Option<&Value>,
	operation_type: &OperationType,
	lines: &[&str],
) -> Result<UnresolvedLineRange, String> {
	use crate::utils::line_hash::{line_id_at, parse_endpoint, Endpoint};

	// Name the id the caller almost certainly meant, with its content so the
	// target can be confirmed rather than assumed. A stale id already reports
	// itself this way; a plain number left the caller re-reading the file to
	// learn one id, then re-issuing the whole batch.
	let id_hint = |n: i64| -> String {
		if n >= 1 && (n as usize) <= lines.len() {
			let idx = n as usize;
			format!(
				" — line {n} is currently `{}` containing: {}",
				line_id_at(lines, idx),
				lines[idx - 1].trim()
			)
		} else {
			String::new()
		}
	};

	let start = parse_endpoint(start_val).map_err(|e| format!("invalid `start`: {e}"))?;

	match operation_type {
		OperationType::Insert => match start {
			Endpoint::Number(n @ (0 | -1)) => Ok(UnresolvedLineRange::Anchor(n)),
			Endpoint::Number(n) => Err(format!(
				"insert anchor {n} is not verifiable: use a line id like \"12:a3\", or 0 (file start) / -1 (end){}",
				id_hint(n)
			)),
			Endpoint::Id { line, hash } => Ok(UnresolvedLineRange::IdAnchor { line, hash }),
		},
		OperationType::Replace => {
			let end = match end_val {
				Some(v) => parse_endpoint(v).map_err(|e| format!("invalid `end`: {e}"))?,
				None => start.clone(), // single-line replace
			};
			match (start, end) {
				(Endpoint::Id { line: sl, hash: sh }, Endpoint::Id { line: el, hash: eh }) => {
					Ok(UnresolvedLineRange::IdRange {
						start: (sl, sh),
						end: (el, eh),
					})
				}
				(s, e) => {
					let mut hint = String::new();
					if let Endpoint::Number(n) = s {
						hint.push_str(&id_hint(n));
					}
					if let Endpoint::Number(n) = e {
						hint.push_str(&id_hint(n));
					}
					Err(format!(
						"replace targets must be line ids like \"12:a3\" from view output, not plain numbers{hint}"
					))
				}
			}
		}
	}
}


fn preflight(call: &McpToolCall, operations: &[Value]) -> Result<(), String> {
	// Extract path from the call parameters - NEW: single file only
	let path_str = match call.parameters.get("path").and_then(|v| v.as_str()) {
		Some(p) => p,
		None => {
			bail!("Missing required 'path' parameter for batch_edit");
		}
	};

	// Fail fast: validate operations array before touching the filesystem
	if operations.is_empty() {
		bail!("Operations array is empty — nothing to do.");
	}

	const MAX_OPERATIONS: usize = 50;
	if operations.len() > MAX_OPERATIONS {
		bail!(
			"Too many operations: {} (max {}). Split into multiple calls.",
			operations.len(),
			MAX_OPERATIONS
		);
	}

	Ok(())
}

fn plan(call: &McpToolCall, operations: &[Value], original_lines: &[&str]) -> Result<Vec<BatchOperation>, String> {
	// Extract path from the call parameters - NEW: single file only
	let path_str = match call.parameters.get("path").and_then(|v| v.as_str()) {
		Some(p) => p,
		None => {
			bail!("Missing required 'path' parameter for batch_edit");
		}
	};

	// Fail fast: validate operations array before touching the filesystem
	if operations.is_empty() {
		bail!("Operations array is empty — nothing to do.");
	}

	const MAX_OPERATIONS: usize = 50;
	if operations.len() > MAX_OPERATIONS {
		bail!(
			"Too many operations: {} (max {}). Split into multiple calls.",
			operations.len(),
			MAX_OPERATIONS
		);
	}

	let total_lines = original_lines.len();
	let mut unresolved_operations = Vec::new();
	let mut parse_failures: Vec<String> = Vec::new();

	for (index, operation) in operations.iter().enumerate() {
		let operation_obj = match operation.as_object() {
			Some(obj) => obj,
			None => {
				parse_failures.push(format!("  op {index}: Operation must be an object"));
				continue;
			}
		};

		// Extract operation type
		let op_type_str = match operation_obj.get("operation").and_then(|v| v.as_str()) {
			Some(op) => op,
			None => {
				parse_failures.push(format!("  op {index}: Missing 'operation' field"));
				continue;
			}
		};

		// Parse operation type
		let operation_type = match op_type_str {
			"insert" => OperationType::Insert,
			"replace" => OperationType::Replace,
			_ => {
				parse_failures.push(format!(
					"  op {index}: Unsupported operation type: '{op_type_str}'. Supported operations: insert, replace"
				));
				continue;
			}
		};

		// Extract start (required) and optional end endpoints. JSON null counts as
		// omitted: the server round-trips ops through the typed struct, which
		// re-serializes an absent `end` as null (and clients send explicit nulls too).
		let line_range = match operation_obj.get("start").filter(|v| !v.is_null()) {
			Some(start_value) => {
				match parse_line_range(
					start_value,
					operation_obj.get("end").filter(|v| !v.is_null()),
					&operation_type,
					&original_lines,
				) {
					Ok(range) => range,
					Err(e) => {
						parse_failures.push(format!("  op {index}: Invalid line target: {e}"));
						continue;
					}
				}
			}
			None => {
				parse_failures.push(format!("  op {index}: Missing 'start' field"));
				continue;
			}
		};

		// Extract content. An insert of "" can only mean a blank line: inserting nothing
		// is no edit, and reporting it as applied hides the miss. A replace of "" deletes.
		let content = match operation_obj.get("content").and_then(|v| v.as_str()) {
			Some("") if operation_type == OperationType::Insert => "\n".to_string(),
			Some(c) => c.to_string(),
			None => {
				parse_failures.push(format!("  op {index}: Missing 'content' field"));
				continue;
			}
		};

		unresolved_operations.push(UnresolvedBatchOperation {
			operation_type,
			line_range,
			content,
			operation_index: index,
		});
	}

	// Atomic contract: if ANY operation is malformed, apply nothing. Silently dropping
	// a bad op while applying the rest would half-execute the caller's intent.
	if !parse_failures.is_empty() {
		bail!(
			"No operations were applied: {} of {} are malformed:\n{}",
			parse_failures.len(),
			operations.len(),
			parse_failures.join("\n")
		);
	}

	let mut batch_operations = Vec::new();
	let mut resolve_failures: Vec<String> = Vec::new();

	for unresolved_op in unresolved_operations {
		match resolve_unresolved_line_range(&unresolved_op.line_range, total_lines, &original_lines)
		{
			Ok(resolved_range) => {
				batch_operations.push(BatchOperation {
					operation_type: unresolved_op.operation_type,
					line_range: resolved_range,
					content: unresolved_op.content,
					operation_index: unresolved_op.operation_index,
				});
			}
			Err(err) => {
				resolve_failures.push(format!("op {}: {}", unresolved_op.operation_index, err));
			}
		}
	}

	if !resolve_failures.is_empty() {
		bail!(
			"No operations were applied to {path_str}: {} of {} have stale or invalid targets:\n{}",
			resolve_failures.len(),
			operations.len(),
			resolve_failures.join("\n---\n")
		);
	}

	Ok(batch_operations)
}

fn word(raw: &[u8], at: usize) -> u64 { u64::from_le_bytes(raw[at..at+8].try_into().unwrap()) }
fn length(raw: &[u8], cursor: &mut usize) -> usize {
    let begin=*cursor;
    let mut value=0u64;
    for count in 0..10 {
        let part=raw[*cursor];*cursor+=1;
        assert!(count!=9 || part<=1);
        value|=u64::from(part&127)<<(7*count);
        if part<128 { assert!(*cursor==begin+1 || part!=0);return value.try_into().unwrap(); }
    }
    panic!("noncanonical line length")
}
fn endpoint(raw: &[u8]) -> Value {
    assert!(raw.len()>=32);assert_eq!(&raw[..8],b"HIAEP001");
    assert_eq!(word(raw,16) as usize,raw.len()-32);
    let kind=word(raw,8);let scalar=word(raw,24);
    match kind {
        0 => {assert_eq!(raw.len(),32);Value::from(scalar as i64)},
        1 => {assert_eq!(raw.len(),32);assert_eq!(scalar,0);serde_json::from_str("1.0").unwrap()},
        2 => {assert_eq!(scalar,0);Value::String(String::from_utf8(raw[32..].to_vec()).unwrap())},
        3 => {assert_eq!(scalar,0);let value:Value=serde_json::from_slice(&raw[32..]).unwrap();
            assert!(!value.is_string() && !value.is_number() && !value.is_null());
            assert_eq!(value.to_string().as_bytes(),&raw[32..]);value},
        _ => panic!("invalid typed endpoint"),
    }
}
fn emit_header(output:&mut impl std::io::Write,status:u64,count:u64,body:u64) {
    output.write_all(&(48+body).to_le_bytes()).unwrap();
    output.write_all(b"HBPLR001").unwrap();
    for value in [status,count,body,0,0] {output.write_all(&value.to_le_bytes()).unwrap();}
}
pub fn invoke(raw:&[u8], output:&mut impl std::io::Write) {
    assert!(raw.len()>=80);assert_eq!(&raw[..8],b"HBPLAN01");
    let mode=word(raw,8);let present=word(raw,16);let count=word(raw,32) as usize;
    assert!(mode<=1 && present<=1);assert_eq!(word(raw,64),0);assert_eq!(word(raw,72),0);
    let path_size=word(raw,40) as usize;let lines_size=word(raw,48) as usize;
    let mut at=80+path_size;
    let path=std::str::from_utf8(&raw[80..at]).unwrap();
    let mut original_lines=Vec::new();
    for _ in 0..word(raw,24) {let size=length(raw,&mut at);original_lines.push(std::str::from_utf8(&raw[at..at+size]).unwrap());at+=size;}
    assert_eq!(at,80+path_size+lines_size);assert_eq!(word(raw,56) as usize,raw.len()-at);
    if mode==0 {assert!(original_lines.is_empty());assert_eq!(lines_size,0);}
    let mut operations=Vec::new();
    for _ in 0..count {
        let words:Vec<u64>=(0..9).map(|n|word(raw,at+n*8)).collect();at+=72;
        assert!(words[..5].iter().all(|n|*n<=1));
        let mut fields=Vec::new();
        for size in &words[5..] {let n=*size as usize;fields.push(&raw[at..at+n]);at+=n;}
        if words[0]==0 {assert!(words[1..].iter().all(|n|*n==0));operations.push(Value::Null);continue;}
        let mut map=serde_json::Map::new();
        if words[1]==1 {map.insert("operation".into(),Value::String(std::str::from_utf8(fields[0]).unwrap().into()));}
        else {assert!(fields[0].is_empty());}
        for (flag,name,bytes) in [(words[2],"start",fields[1]),(words[3],"end",fields[2])] {
            if flag==1 {map.insert(name.into(),endpoint(bytes));} else {assert!(bytes.is_empty());}
        }
        if words[4]==1 {map.insert("content".into(),Value::String(std::str::from_utf8(fields[3]).unwrap().into()));}
        else {assert!(fields[3].is_empty());}
        operations.push(Value::Object(map));
    }
    assert_eq!(at,raw.len());
    let call=McpToolCall{parameters:if present==1 {serde_json::json!({"path":path})} else {assert!(path.is_empty());Value::Null}};
    let result=if mode==0 {preflight(&call,&operations).map(|_|Vec::new())} else {plan(&call,&operations,&original_lines)};
    match result {
        Err(message) => {emit_header(output,1,0,message.len() as u64);output.write_all(message.as_bytes()).unwrap();},
        Ok(operations) if mode==0 => emit_header(output,2,0,0),
        Ok(operations) => {
            let size:u64=operations.iter().map(|op|48+op.content.len() as u64).sum();
            emit_header(output,0,operations.len() as u64,size);
            for op in operations {
                let kind=match op.operation_type {OperationType::Insert=>1u64,OperationType::Replace=>2u64};
                let (range,a,b)=match op.line_range {LineRange::Single(a)=>(1u64,a,0),LineRange::Range(a,b)=>(2u64,a,b)};
                for value in [op.operation_index as u64,kind,range,a as u64,b as u64,op.content.len() as u64] {output.write_all(&value.to_le_bytes()).unwrap();}
                output.write_all(op.content.as_bytes()).unwrap();
            }
        },
    }
}
}

fn main() {
	let mut input = io::stdin().lock();
	let mut output = io::BufWriter::new(io::stdout().lock());
	let mut rows = 0u64;
	loop {
		let mut header = [0u8; 8];
		match input.read(&mut header[..1]) {
			Ok(0) => break,
			Ok(1) => input.read_exact(&mut header[1..]).unwrap(),
			_ => panic!("request read"),
		}
		let size = u64::from_le_bytes(header) as usize;
		assert!((80..=512 << 20).contains(&size));
		let mut raw = vec![0u8; size];
		input.read_exact(&mut raw).unwrap();
		original::invoke(&raw, &mut output);
		rows += 1;
	}
	output.flush().unwrap();
	eprintln!("{{\"status\":\"PASS\",\"original_batch_rows\":{rows}}}");
}
