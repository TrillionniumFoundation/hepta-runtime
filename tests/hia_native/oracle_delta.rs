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

// Exact original source owners; only framing below is test code.
fn fnv1a_8(content: &str) -> u8 {
	const FNV_OFFSET: u32 = 2166136261;
	const FNV_PRIME: u32 = 16777619;

	let mut hash = FNV_OFFSET;
	for byte in content.bytes() {
		hash ^= byte as u32;
		hash = hash.wrapping_mul(FNV_PRIME);
	}

	// Fold 32 -> 16 -> 8 via XOR
	let h16 = ((hash >> 16) ^ (hash & 0xFFFF)) as u16;
	((h16 >> 8) ^ (h16 & 0xFF)) as u8
}

pub fn line_hash(content: &str) -> String {
	format!("{:02x}", fnv1a_8(content))
}

pub fn line_id(line_1idx: usize, content: &str) -> String {
	format!("{}:{}", line_1idx, line_hash(content))
}

pub fn line_id_at(lines: &[&str], line_1idx: usize) -> String {
	line_id(line_1idx, lines[line_1idx - 1])
}
const CONTEXT: usize = 2;
const MAX_EDIT_DISTANCE: usize = 500;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffOp {
	Equal(usize, usize),
	Delete(usize),
	Insert(usize),
}

fn normalize(content: &str) -> String {
	content.replace("\r\n", "\n")
}

pub fn render_delta(old: &[&str], new: &[&str]) -> Option<String> {
	let ops = diff_lines(old, new, MAX_EDIT_DISTANCE)?;

	// Hunks are op-index ranges around each change, merged when their context touches.
	let mut hunks: Vec<(usize, usize)> = Vec::new();
	for (i, op) in ops.iter().enumerate() {
		if matches!(op, DiffOp::Equal(..)) {
			continue;
		}
		let start = i.saturating_sub(CONTEXT);
		let end = (i + CONTEXT).min(ops.len() - 1);
		match hunks.last_mut() {
			Some(last) if start <= last.1 + 1 => last.1 = last.1.max(end),
			_ => hunks.push((start, end)),
		}
	}

	let mut out = vec![format!(
		"[changed since your last view: {} hunk(s), {} lines now]",
		hunks.len(),
		new.len()
	)];
	for &(start, end) in &hunks {
		if start > 0 {
			out.push("...".to_string());
		}
		let mut i = start;
		while i <= end {
			match ops[i] {
				DiffOp::Equal(_, j) => out.push(format!("{}|{}", line_id_at(new, j + 1), new[j])),
				DiffOp::Insert(j) => out.push(format!("+{}|{}", line_id_at(new, j + 1), new[j])),
				DiffOp::Delete(first) => {
					let mut last = first;
					while i < end {
						let DiffOp::Delete(k) = ops[i + 1] else { break };
						last = k;
						i += 1;
					}
					out.push(removed_marker(old, first, last));
				}
			}
			i += 1;
		}
	}
	if hunks.last().is_some_and(|&(_, end)| end + 1 < ops.len()) {
		out.push("...".to_string());
	}
	Some(out.join("\n"))
}

pub fn removed_marker(old: &[&str], first: usize, last: usize) -> String {
	if first == last {
		format!("-{} (1 line)", line_id_at(old, first + 1))
	} else {
		format!(
			"-{}..{} ({} lines)",
			line_id_at(old, first + 1),
			line_id_at(old, last + 1),
			last - first + 1
		)
	}
}

pub fn diff_lines(old: &[&str], new: &[&str], max_d: usize) -> Option<Vec<DiffOp>> {
	let n = old.len();
	let m = new.len();
	let max_d = max_d.min(n + m);
	// Diagonal k = x - y lives at v[k + offset]; the spare slots keep k±1 in range.
	let offset = max_d as i64 + 1;
	let at = |k: i64| (k + offset) as usize;
	let mut v = vec![0usize; 2 * max_d + 3];
	let mut trace: Vec<Vec<usize>> = Vec::new();

	for d in 0..=max_d as i64 {
		trace.push(v.clone());
		let mut k = -d;
		while k <= d {
			let down = k == -d || (k != d && v[at(k - 1)] < v[at(k + 1)]);
			let mut x = if down { v[at(k + 1)] } else { v[at(k - 1)] + 1 };
			let mut y = (x as i64 - k) as usize;
			while x < n && y < m && old[x] == new[y] {
				x += 1;
				y += 1;
			}
			v[at(k)] = x;
			if x >= n && y >= m {
				return Some(backtrack(&trace, n, m, offset));
			}
			k += 2;
		}
	}
	None
}

fn backtrack(trace: &[Vec<usize>], n: usize, m: usize, offset: i64) -> Vec<DiffOp> {
	let at = |k: i64| (k + offset) as usize;
	let mut ops = Vec::new();
	let (mut x, mut y) = (n, m);
	for (d, v) in trace.iter().enumerate().rev() {
		let d = d as i64;
		let k = x as i64 - y as i64;
		let prev_k = if k == -d || (k != d && v[at(k - 1)] < v[at(k + 1)]) {
			k + 1
		} else {
			k - 1
		};
		let prev_x = v[at(prev_k)];
		let prev_y = prev_x as i64 - prev_k;
		while x > prev_x && y as i64 > prev_y {
			x -= 1;
			y -= 1;
			ops.push(DiffOp::Equal(x, y));
		}
		if d > 0 {
			if x == prev_x {
				ops.push(DiffOp::Insert(y - 1));
			} else {
				ops.push(DiffOp::Delete(x - 1));
			}
			x = prev_x;
			y = prev_y as usize;
		}
	}
	ops.reverse();
	ops
}

use std::io::{self, BufRead, Write};
fn hex(raw: &[u8]) -> String { raw.iter().map(|v| format!("{v:02x}")).collect() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn word(s: &[u8], at: usize) -> u64 { u64::from_le_bytes(s[at..at+8].try_into().unwrap()) }
fn put(out: &mut Vec<u8>, n: u64) { out.extend_from_slice(&n.to_le_bytes()); }
fn apply(raw: &[u8]) -> Vec<u8> {
 let op=word(raw,8);let a=word(raw,16) as usize;let b=word(raw,24) as usize;
 let n=word(raw,32) as usize;let m=word(raw,40) as usize;
 let mut at=64;let mut lines=Vec::new();
 for _ in 0..n+m { let len=word(raw,at) as usize;at+=8;lines.push(std::str::from_utf8(&raw[at..at+len]).unwrap());at+=len; }
 let (old,new)=lines.split_at(n);let mut out=Vec::new();
 match op {
  1 => match diff_lines(old,new,a) {
   None => put(&mut out,0),
   Some(ops) => { put(&mut out,1);put(&mut out,ops.len() as u64);
    for op in ops { match op {
     DiffOp::Equal(i,j) => {put(&mut out,0);put(&mut out,i as u64);put(&mut out,j as u64);},
     DiffOp::Delete(i) => {put(&mut out,1);put(&mut out,i as u64);put(&mut out,u64::MAX);},
     DiffOp::Insert(j) => {put(&mut out,2);put(&mut out,u64::MAX);put(&mut out,j as u64);},
    }}
   }
  },
  2 => match render_delta(old,new) {None => put(&mut out,0),Some(text) => {put(&mut out,1);out.extend_from_slice(text.as_bytes());}},
  3 => out=removed_marker(old,a,b).into_bytes(),
  4 => out=normalize(old[0]).into_bytes(),
  5 => {let parts:Vec<&str>=old[0].lines().collect();put(&mut out,parts.len() as u64);for part in parts {put(&mut out,part.len() as u64);out.extend_from_slice(part.as_bytes());}},
  _ => panic!("unknown test operation"),
 }
 out
}
fn main() {
 std::panic::set_hook(Box::new(|_|{}));
 let stdin=io::stdin();let mut out=io::BufWriter::new(io::stdout().lock());
 for line in stdin.lock().lines() {
  let raw=unhex(&line.unwrap());
  match std::panic::catch_unwind(||apply(&raw)) {
   Ok(bytes) => writeln!(&mut out,"OK {}",hex(&bytes)).unwrap(),
   Err(_) => writeln!(&mut out,"PANIC").unwrap(),
  }
 }
}
