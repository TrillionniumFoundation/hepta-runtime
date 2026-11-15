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

//! Resource boundaries and code-unit distinctions for the embedded line index.

use super::*;

#[test]
fn aggregate_line_budget_includes_empty_sources_and_commits_only_complete_indexes() {
	let mut used = MAX_EMBEDDED_LINES - 3;
	let index = LineIndex::from_text("a\r\nb\n", &mut used).unwrap();
	assert_eq!(index.line_count(), 3);
	assert_eq!(used, MAX_EMBEDDED_LINES);
	assert!(LineIndex::from_text("", &mut used).is_err());
	assert_eq!(used, MAX_EMBEDDED_LINES);

	let mut used = MAX_EMBEDDED_LINES - 2;
	assert!(LineIndex::from_text("a\r\nb\n", &mut used).is_err());
	assert_eq!(used, MAX_EMBEDDED_LINES - 2);
	assert_eq!(
		LineIndex::from_text("", &mut used).unwrap().offset(0, 0),
		Some(0)
	);
	assert_eq!(used, MAX_EMBEDDED_LINES - 1);
}

#[test]
fn offsets_count_utf16_including_the_middle_of_a_valid_surrogate_pair() {
	let index = LineIndex::from_text("a🔥b", &mut 0).unwrap();
	assert_eq!(index.utf16_units(), 4);
	for column in 0..=4 {
		assert_eq!(index.offset(0, column), Some(column));
	}
	assert_eq!(index.offset(0, 5), None);
	assert_eq!(index.offset(1, 0), None);
	assert_eq!(index.offset(u32::MAX, 0), None);
	assert_eq!(index.offset(0, u32::MAX), None);
}

#[test]
fn all_web_line_endings_exclude_terminators_and_preserve_the_final_empty_line() {
	let index = LineIndex::from_text("a\r\nb\rc\nd\u{2028}e\u{2029}", &mut 0).unwrap();
	assert_eq!(index.line_count(), 6);
	assert_eq!(index.utf16_units(), 11);
	for (line, start) in [0, 3, 5, 7, 9].into_iter().enumerate() {
		assert_eq!(index.offset(line as u32, 0), Some(start));
		assert_eq!(index.offset(line as u32, 1), Some(start + 1));
		assert_eq!(index.offset(line as u32, 2), None);
	}
	assert_eq!(index.offset(5, 0), Some(11));
	assert_eq!(index.offset(5, 1), None);
	let ordinary = LineIndex::from_text("a\u{0085}b", &mut 0).unwrap();
	assert_eq!(ordinary.line_count(), 1);
	assert_eq!(ordinary.offset(0, 3), Some(3));
}

#[test]
fn seven_admitted_offsets_match_the_frozen_actual_original_function() {
	let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
		"../../tests/fixtures/rea_source_map/content-position-rea-6_8_0.json"
	))
	.unwrap();
	let (mut compared, mut outside_native_coordinate_domain) = (0, 0);
	for case in fixture["direct_offsets"].as_array().unwrap() {
		let line = case["position"]["line"]
			.as_u64()
			.and_then(|line| line.checked_sub(1))
			.and_then(|line| u32::try_from(line).ok());
		let column = case["position"]["column"]
			.as_u64()
			.and_then(|column| u32::try_from(column).ok());
		let (Some(line), Some(column)) = (line, column) else {
			assert_eq!(case["defined"], false);
			outside_native_coordinate_domain += 1;
			continue;
		};
		let text: String = serde_json::from_str(case["text_json"].as_str().unwrap()).unwrap();
		let offset = LineIndex::from_text(&text, &mut 0)
			.unwrap()
			.offset(line, column);
		assert_eq!(
			serde_json::to_value(offset).unwrap(),
			case["offset"],
			"{}",
			case["id"]
		);
		compared += 1;
	}
	assert_eq!((compared, outside_native_coordinate_domain), (7, 4));
}
