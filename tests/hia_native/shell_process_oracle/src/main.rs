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

//! Test-only transport for unchanged original shell/background owners.
#![allow(dead_code, unused_imports)]
mod background_render;
mod fixture;
mod mcp;
mod utils;

fn main() -> std::process::ExitCode {
	let arguments = std::env::args().skip(1).collect::<Vec<_>>();
	if arguments == ["--background-render"] {
		return match background_render::run() {
			Ok(()) => std::process::ExitCode::SUCCESS,
			Err(error) => {
				eprintln!("background render transport: {error:#}");
				std::process::ExitCode::FAILURE
			}
		};
	}
	if arguments != ["--fixture"] {
		eprintln!("usage: hepta-shell-process-original-oracle --fixture | --background-render");
		return std::process::ExitCode::from(2);
	}
	let runtime = match tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()
	{
		Ok(runtime) => runtime,
		Err(error) => {
			eprintln!("fixture runtime: {error}");
			return std::process::ExitCode::FAILURE;
		}
	};
	let result = runtime.block_on(fixture::run());
	if let Err(error) = result {
		mcp::fs::shell::kill_all_shell_children();
		eprintln!("fixture transport: {error:#}");
		return std::process::ExitCode::FAILURE;
	}
	std::process::ExitCode::SUCCESS
}
