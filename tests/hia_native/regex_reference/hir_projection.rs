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

// Test-only serialization of the locked original regex-syntax HIR. Every
// translation and smart-constructor decision remains in the original crate.
use regex_syntax::hir::Hir;

fn walk_hir(hir: &Hir, nodes: &mut Vec<[u64; 12]>, pool: &mut Vec<u8>, captures: &mut u64) -> u64 {
	let at = nodes.len();
	nodes.push([0; 12]);
	let mut record = [0u64; 12];
	let mut data = Vec::new();
	match hir.kind() {
		HirKind::Empty => record[0] = 0,
		HirKind::Literal(lit) => {
			record[0] = 1;
			data.extend_from_slice(&lit.0)
		}
		HirKind::Class(Class::Unicode(cls)) => {
			record[0] = 2;
			for r in cls.ranges() {
				data.extend((r.start() as u64).to_le_bytes());
				data.extend((r.end() as u64).to_le_bytes());
			}
		}
		HirKind::Class(Class::Bytes(cls)) => {
			record[0] = 3;
			for r in cls.ranges() {
				data.extend((r.start() as u64).to_le_bytes());
				data.extend((r.end() as u64).to_le_bytes());
			}
		}
		HirKind::Look(look) => {
			record[0] = 4;
			record[2] = look.as_repr() as u64
		}
		HirKind::Repetition(rep) => {
			record[0] = 5;
			record[2] = rep.min as u64;
			record[3] = rep.max.map(|n| n as u64).unwrap_or(u64::MAX);
			record[4] = rep.greedy as u64
		}
		HirKind::Capture(cap) => {
			record[0] = 6;
			record[2] = cap.index as u64;
			*captures = (*captures).max(cap.index as u64);
			if let Some(name) = &cap.name {
				record[3] = 1;
				data.extend(name.as_bytes());
			}
		}
		HirKind::Concat(_) => record[0] = 7,
		HirKind::Alternation(_) => record[0] = 8,
	}
	record[1] = hir.kind().subs().len() as u64;
	if !data.is_empty() {
		record[5] = pool.len() as u64;
		record[6] = data.len() as u64;
		pool.extend(data);
	}
	let p = hir.properties();
	record[7] = p.minimum_len().unwrap_or(0) as u64;
	record[8] = p.maximum_len().unwrap_or(0) as u64;
	record[9] = (p.minimum_len().is_some() as u64) | ((p.maximum_len().is_some() as u64) << 1);
	record[10] = p.look_set_prefix().bits as u64;
	record[11] = p.look_set_suffix().bits as u64;
	nodes[at] = record;
	let mut depth = 0;
	for child in hir.kind().subs() {
		depth = depth.max(walk_hir(child, nodes, pool, captures) + 1);
	}
	depth
}

fn project_hir(pattern: &str) -> (u32, Vec<u8>) {
	match regex_syntax::Parser::new().parse(pattern) {
		Err(error) => (1, error.to_string().into_bytes()),
		Ok(hir) => {
			let (mut nodes, mut pool, mut captures) = (Vec::new(), Vec::new(), 0);
			let depth = walk_hir(&hir, &mut nodes, &mut pool, &mut captures);
			let mut out = b"HRGHIR01".to_vec();
			for n in [
				nodes.len() as u64,
				captures,
				depth,
				pool.len() as u64,
				hir.properties().look_set().bits as u64,
				0,
				0,
			] {
				out.extend(n.to_le_bytes());
			}
			for node in nodes {
				for n in node {
					out.extend(n.to_le_bytes());
				}
			}
			out.extend(pool);
			(0, out)
		}
	}
}
