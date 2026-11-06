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

use super::*;

#[test]
fn export_input_matches_every_field_of_actual_frozen_mcp_failures() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_export_mcp_input_reference.json"
	))
	.unwrap();
	for case in fixture["cases"].as_array().unwrap() {
		let keys: Vec<String> = serde_json::from_value(case["argument_keys"].clone()).unwrap();
		let result = export_ordered(&case["arguments"], Some(&keys));
		if case["schema_error"] == true {
			let mut wire = result.unwrap_err().wire();
			// Export's public contract does not carry target-content provenance.
			wire.meta = None;
			// The oracle negotiated the legacy MCP protocol. Exercise the same
			// SDK response conversion used by its server handler, preserving
			// every resulting wire field for the complete-envelope comparison.
			let mut response = rmcp::model::ServerResult::CallToolResult(wire);
			response.strip_result_type_for_legacy_peer();
			let mut actual = serde_json::to_value(response).unwrap();
			actual["content"][0]["text"] =
				serde_json::from_str(actual["content"][0]["text"].as_str().unwrap()).unwrap();
			assert_eq!(actual, case["expected"], "{}", case["name"]);
		} else {
			assert!(result.is_ok(), "{}", case["name"]);
		}
	}
}
