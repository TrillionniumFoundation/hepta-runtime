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

//! Exhaustive original standard-library string Debug classification.
//! This is an independent test reference, never a runtime formatter fallback.

fn main() {
	let mut ranges = Vec::new();
	let mut start = 0u32;
	let mut previous = 255u8;
	let mut scalars = 0u64;
	let mut formatting_calls = 0u64;
	for value in 0..=0x10ffffu32 {
		let flags = if let Some(c) = char::from_u32(value) {
			scalars += 1;
			let mut flags = 0u8;
			for (index, prefix) in ["", "A", "\u{301}", "A\u{301}"].iter().enumerate() {
				let input = format!("{prefix}{c}");
				let got = format!("{input:?}");
				formatting_calls += 1;
				let prefix_debug = format!("{prefix:?}");
				let prefix_without_quote = &prefix_debug[..prefix_debug.len() - 1];
				let plain = format!("{prefix_without_quote}{c}\"");
				if got != plain {
					flags |= 1 << index;
					let escaped = match c {
						'\0' => "\\0".to_string(),
						'\t' => "\\t".to_string(),
						'\r' => "\\r".to_string(),
						'\n' => "\\n".to_string(),
						'"' => "\\\"".to_string(),
						'\\' => "\\\\".to_string(),
						_ => format!("\\u{{{value:x}}}"),
					};
					assert_eq!(got, format!("{prefix_without_quote}{escaped}\""));
				}
			}
			flags
		} else {
			16
		};
		if flags != previous {
			if previous != 255 {
				ranges.push((start, value - 1, previous));
			}
			start = value;
			previous = flags;
		}
	}
	ranges.push((start, 0x10ffff, previous));
	let (major, minor, update) = char::UNICODE_VERSION;
	print!("{{\"schema\":\"hepta.runtime.rust-string-debug-properties.v1\",\"unicode\":[{major},{minor},{update}],\"scalars\":{scalars},\"formatting_calls\":{formatting_calls},\"ranges\":[");
	for (index, (start, end, flags)) in ranges.into_iter().enumerate() {
		if index != 0 {
			print!(",");
		}
		print!("[{start},{end},{flags}]");
	}
	println!("]}}");
}
