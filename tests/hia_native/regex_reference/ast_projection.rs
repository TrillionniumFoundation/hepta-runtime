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

// Test-only semantic AST projection. Parsing is performed solely by the locked
// original regex-syntax crate; this code only serializes its public AST values.
use regex_syntax::ast::{self, Ast};

fn flag_bits(flags: &ast::Flags) -> (u64, u64) {
	let (mut yes, mut no, mut neg) = (0, 0, false);
	for item in &flags.items {
		match item.kind {
			ast::FlagsItemKind::Negation => neg = true,
			ast::FlagsItemKind::Flag(flag) => {
				let bit = match flag {
					ast::Flag::CaseInsensitive => 1,
					ast::Flag::MultiLine => 2,
					ast::Flag::DotMatchesNewLine => 4,
					ast::Flag::CRLF => 8,
					ast::Flag::SwapGreed => 16,
					ast::Flag::Unicode => 32,
					ast::Flag::IgnoreWhitespace => 64,
				};
				if neg {
					no |= bit
				} else {
					yes |= bit
				}
			}
		}
	}
	(yes, no)
}
fn pool_add(pool: &mut Vec<u8>, text: &str) -> u64 {
	let n = pool.len();
	pool.extend(text.as_bytes());
	n as u64
}
fn unicode_args(class: &ast::ClassUnicode, pool: &mut Vec<u8>) -> [u64; 5] {
	let mut args = [class.is_negated() as u64, 0, 0, 0, 0];
	match &class.kind {
		ast::ClassUnicodeKind::OneLetter(c) => args[2] = *c as u64,
		ast::ClassUnicodeKind::Named(name) => {
			args[1] = 1;
			args[2] = pool_add(pool, name);
			args[3] = name.len() as u64;
		}
		ast::ClassUnicodeKind::NamedValue { name, value, .. } => {
			args[1] = 2;
			args[2] = pool_add(pool, name);
			pool_add(pool, value);
			args[3] = name.len() as u64;
			args[4] = value.len() as u64;
		}
	}
	args
}
fn perl_args(class: &ast::ClassPerl) -> [u64; 5] {
	[
		match class.kind {
			ast::ClassPerlKind::Digit => 0,
			ast::ClassPerlKind::Space => 1,
			ast::ClassPerlKind::Word => 2,
		},
		class.negated as u64,
		0,
		0,
		0,
	]
}
fn record(nodes: &mut Vec<[u64; 8]>, kind: u64, children: u64, args: [u64; 5]) -> usize {
	let at = nodes.len();
	nodes.push([
		kind, children, args[0], args[1], args[2], args[3], args[4], 0,
	]);
	at
}
fn finish(nodes: &mut Vec<[u64; 8]>, at: usize, depth: u64) -> u64 {
	nodes[at][7] = depth;
	depth
}
fn walk_class(set: &ast::ClassSet, nodes: &mut Vec<[u64; 8]>, pool: &mut Vec<u8>) -> u64 {
	match set {
		ast::ClassSet::Item(item) => walk_item(item, nodes, pool),
		ast::ClassSet::BinaryOp(op) => {
			let kind = match op.kind {
				ast::ClassSetBinaryOpKind::Intersection => 0,
				ast::ClassSetBinaryOpKind::Difference => 1,
				ast::ClassSetBinaryOpKind::SymmetricDifference => 2,
			};
			let at = record(nodes, 20, 2, [kind, 0, 0, 0, 0]);
			let a = walk_class(&op.lhs, nodes, pool);
			let b = walk_class(&op.rhs, nodes, pool);
			finish(nodes, at, 1 + a.max(b))
		}
	}
}
fn walk_item(item: &ast::ClassSetItem, nodes: &mut Vec<[u64; 8]>, pool: &mut Vec<u8>) -> u64 {
	let mut depth = 0;
	let at = match item {
		ast::ClassSetItem::Empty(_) => record(nodes, 12, 0, [0; 5]),
		ast::ClassSetItem::Literal(lit) => record(
			nodes,
			13,
			0,
			[lit.c as u64, lit.byte().is_some() as u64, 0, 0, 0],
		),
		ast::ClassSetItem::Range(range) => record(
			nodes,
			14,
			0,
			[
				range.start.c as u64,
				range.end.c as u64,
				range.start.byte().is_some() as u64,
				range.end.byte().is_some() as u64,
				0,
			],
		),
		ast::ClassSetItem::Ascii(class) => {
			let kind = match class.kind {
				ast::ClassAsciiKind::Alnum => 0,
				ast::ClassAsciiKind::Alpha => 1,
				ast::ClassAsciiKind::Ascii => 2,
				ast::ClassAsciiKind::Blank => 3,
				ast::ClassAsciiKind::Cntrl => 4,
				ast::ClassAsciiKind::Digit => 5,
				ast::ClassAsciiKind::Graph => 6,
				ast::ClassAsciiKind::Lower => 7,
				ast::ClassAsciiKind::Print => 8,
				ast::ClassAsciiKind::Punct => 9,
				ast::ClassAsciiKind::Space => 10,
				ast::ClassAsciiKind::Upper => 11,
				ast::ClassAsciiKind::Word => 12,
				ast::ClassAsciiKind::Xdigit => 13,
			};
			record(nodes, 15, 0, [kind, class.negated as u64, 0, 0, 0])
		}
		ast::ClassSetItem::Unicode(class) => {
			let args = unicode_args(class, pool);
			record(nodes, 16, 0, args)
		}
		ast::ClassSetItem::Perl(class) => record(nodes, 17, 0, perl_args(class)),
		ast::ClassSetItem::Bracketed(class) => {
			let at = record(nodes, 18, 1, [class.negated as u64, 0, 0, 0, 0]);
			depth = 1 + walk_class(&class.kind, nodes, pool);
			at
		}
		ast::ClassSetItem::Union(union) => {
			let at = record(nodes, 19, union.items.len() as u64, [0; 5]);
			for item in &union.items {
				depth = depth.max(walk_item(item, nodes, pool));
			}
			depth += 1;
			at
		}
	};
	finish(nodes, at, depth)
}
fn walk_ast(ast: &Ast, nodes: &mut Vec<[u64; 8]>, pool: &mut Vec<u8>, captures: &mut u64) -> u64 {
	let mut depth = 0;
	let at = match ast {
		Ast::Empty(_) => record(nodes, 0, 0, [0; 5]),
		Ast::Flags(flags) => {
			let (a, b) = flag_bits(&flags.flags);
			record(nodes, 1, 0, [a, b, 0, 0, 0])
		}
		Ast::Literal(lit) => record(
			nodes,
			2,
			0,
			[lit.c as u64, lit.byte().is_some() as u64, 0, 0, 0],
		),
		Ast::Dot(_) => record(nodes, 3, 0, [0; 5]),
		Ast::Assertion(assertion) => {
			let kind = match assertion.kind {
				ast::AssertionKind::StartLine => 0,
				ast::AssertionKind::EndLine => 1,
				ast::AssertionKind::StartText => 2,
				ast::AssertionKind::EndText => 3,
				ast::AssertionKind::WordBoundary => 4,
				ast::AssertionKind::NotWordBoundary => 5,
				ast::AssertionKind::WordBoundaryStartAngle => 6,
				ast::AssertionKind::WordBoundaryEndAngle => 7,
				ast::AssertionKind::WordBoundaryStart => 8,
				ast::AssertionKind::WordBoundaryEnd => 9,
				ast::AssertionKind::WordBoundaryStartHalf => 10,
				ast::AssertionKind::WordBoundaryEndHalf => 11,
			};
			record(nodes, 4, 0, [kind, 0, 0, 0, 0])
		}
		Ast::ClassUnicode(class) => {
			let args = unicode_args(class, pool);
			record(nodes, 5, 0, args)
		}
		Ast::ClassPerl(class) => record(nodes, 6, 0, perl_args(class)),
		Ast::ClassBracketed(class) => {
			let at = record(nodes, 7, 1, [class.negated as u64, 0, 0, 0, 0]);
			depth = 1 + walk_class(&class.kind, nodes, pool);
			at
		}
		Ast::Repetition(rep) => {
			let (min, max) = match rep.op.kind {
				ast::RepetitionKind::ZeroOrOne => (0, 1),
				ast::RepetitionKind::ZeroOrMore => (0, u64::MAX),
				ast::RepetitionKind::OneOrMore => (1, u64::MAX),
				ast::RepetitionKind::Range(ast::RepetitionRange::Exactly(n)) => {
					(n as u64, n as u64)
				}
				ast::RepetitionKind::Range(ast::RepetitionRange::AtLeast(n)) => {
					(n as u64, u64::MAX)
				}
				ast::RepetitionKind::Range(ast::RepetitionRange::Bounded(a, b)) => {
					(a as u64, b as u64)
				}
			};
			let at = record(nodes, 8, 1, [min, max, rep.greedy as u64, 0, 0]);
			depth = 1 + walk_ast(&rep.ast, nodes, pool, captures);
			at
		}
		Ast::Group(group) => {
			let mut args = [0; 5];
			match &group.kind {
				ast::GroupKind::CaptureIndex(index) => args[0] = *index as u64,
				ast::GroupKind::CaptureName { name, .. } => {
					args[0] = name.index as u64;
					args[3] = pool_add(pool, &name.name);
					args[4] = name.name.len() as u64;
				}
				ast::GroupKind::NonCapturing(flags) => {
					let (a, b) = flag_bits(flags);
					args[1] = a;
					args[2] = b;
				}
			}
			*captures = (*captures).max(args[0]);
			let at = record(nodes, 9, 1, args);
			depth = 1 + walk_ast(&group.ast, nodes, pool, captures);
			at
		}
		Ast::Alternation(alt) => {
			let at = record(nodes, 10, alt.asts.len() as u64, [0; 5]);
			for child in &alt.asts {
				depth = depth.max(walk_ast(child, nodes, pool, captures));
			}
			depth += 1;
			at
		}
		Ast::Concat(concat) => {
			let at = record(nodes, 11, concat.asts.len() as u64, [0; 5]);
			for child in &concat.asts {
				depth = depth.max(walk_ast(child, nodes, pool, captures));
			}
			depth += 1;
			at
		}
	};
	finish(nodes, at, depth)
}
fn project_ast(pattern: &str) -> (u32, Vec<u8>) {
	match regex_syntax::ast::parse::Parser::new().parse(pattern) {
		Err(error) => (1, error.to_string().into_bytes()),
		Ok(ast) => {
			let (mut nodes, mut pool, mut captures) = (Vec::new(), Vec::new(), 0);
			let depth = walk_ast(&ast, &mut nodes, &mut pool, &mut captures);
			let mut out = b"HRGTRE01".to_vec();
			for n in [
				nodes.len() as u64,
				captures,
				depth,
				pool.len() as u64,
				0,
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
