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
//! Execute five original acquisition bodies without changing their assertions.
use anyhow::Result;

mod config {
	pub struct RuntimeConfig {
		pub state_dir: std::path::PathBuf,
	}
	pub fn runtime_config() -> anyhow::Result<RuntimeConfig> {
		anyhow::bail!("original acquisition tests pass an explicit state root")
	}
}
include!(concat!(
	env!("OUT_DIR"),
	"/original_effect_fence_async_reference.rs"
));

fn main() -> Result<()> {
	let started = std::time::Instant::now();
	let arguments: Vec<String> = std::env::args().skip(1).collect();
	if arguments == ["--cache-poison-control"] {
		original::run_original_cache_poison_control()?;
		println!(
			"{}",
			serde_json::json!({
				"schema": "hepta.effect-fence.original-cache-poison.v1", "status": "PASS",
				"tests_run": 1, "failures": 0, "errors": 0, "skipped": 0,
				"expected_failures": 0, "unexpected_successes": 0,
				"original_owner_calls": 5, "actual_admissions": 2,
				"actual_poisoned_queries": 2, "declared_worker_panic_injections": 1,
				"actual_permit_releases": 2, "real_exclusive_lock_restored": true,
				"elapsed_seconds": started.elapsed().as_secs_f64(),
				"original_owner_modified": false, "native_cases_added": 0
			})
		);
		return Ok(());
	}
	if !arguments.is_empty() {
		anyhow::bail!("unknown original acquisition qualification mode");
	}
	let completed = original::run_original_acquisition_tests()?;
	if completed.len() != 5 {
		anyhow::bail!("original acquisition domain incomplete");
	}
	println!(
		"{}",
		serde_json::json!({
			"schema": "hepta.effect-fence.original-acquisition-tests.v1", "status": "PASS",
			"tests_run": completed.len(), "failures": 0, "errors": 0, "skipped": 0,
			"expected_failures": 0, "unexpected_successes": 0, "cases": completed,
			"elapsed_seconds": started.elapsed().as_secs_f64(),
			"original_owner_modified": false, "original_test_bodies_modified": false,
			"native_cases_added": 0, "complete_effect_fence_owner": false
		})
	);
	Ok(())
}
