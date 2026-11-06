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
//! Fixed local-resource browser capture, owned by the existing durable process job.
//!
//! This is a native replacement for the bounded Python capture helper, not a
//! general browser controller. Input scripts are fetched as data, never executed.

#[derive(clap::Args, Clone, Debug)]
pub struct BrowserCaptureArgs {
	/// Absolute, normalized local manifest path. All components must be non-symlinks.
	#[arg(long)]
	pub manifest: String,
	/// SHA-256 of the complete manifest bytes.
	#[arg(long)]
	pub expected_sha256: String,
	/// New direct child directory of the manifest's parent; never overwritten.
	#[arg(long)]
	pub output_directory: String,
}

#[cfg(target_os = "linux")]
#[path = "rea_browser_capture.rs"]
mod capture;
#[cfg(target_os = "linux")]
#[path = "rea_browser_cdp.rs"]
mod cdp;
#[cfg(target_os = "linux")]
#[path = "rea_browser_fixture.rs"]
mod fixture;
#[cfg(target_os = "linux")]
#[path = "rea_browser_input.rs"]
mod input;
#[cfg(target_os = "linux")]
#[path = "rea_browser_process.rs"]
mod process;

/// Runs synchronously in the dedicated helper process, before Tokio is started.
pub fn run_cli(args: BrowserCaptureArgs) -> anyhow::Result<()> {
	#[cfg(target_os = "linux")]
	{
		capture::run(args)
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = args;
		anyhow::bail!("native browser capture requires Linux /proc and retained child custody")
	}
}

#[cfg(all(test, target_os = "linux"))]
#[path = "rea_browser_tests.rs"]
mod tests;
