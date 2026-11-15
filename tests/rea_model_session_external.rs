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

//! Shipped MCP snapshot recovery with a temporary stable HTTP principal.
//! The Python standard-library client is a test driver, not a runtime dependency.

#![cfg(all(target_os = "linux", feature = "remote-fs"))]

#[test]
fn real_http_model_session_survives_restart_and_refuses_changed_authority() {
	let output = std::process::Command::new("python3")
		.arg("-c")
		.arg(include_str!("rea_model_session_http.py"))
		.arg(env!("CARGO_BIN_EXE_hepta-runtime"))
		.output()
		.expect("Python standard-library HTTP test client");
	assert!(
		output.status.success(),
		"stdout: {}\nstderr: {}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
	let stdout = String::from_utf8(output.stdout).expect("UTF-8 qualification");
	assert!(stdout.contains("REA_MODEL_SESSION_HTTP_QUALIFICATION"));
	print!("{stdout}");
}
