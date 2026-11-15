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

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "hepta-runtime")]
#[command(version, author = "TrillionniumFoundation")]
#[command(about = "Policy-enforced multi-host MCP runtime", long_about = None)]
pub struct Cli {
	#[command(subcommand)]
	pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
	/// Start MCP server exposing filesystem tools (view, text_editor, batch_edit, shell, workdir, extract_lines)
	Mcp {
		/// Working directory for filesystem operations (default: current directory).
		/// Supports ssh:// or sftp:// paths for remote filesystem access.
		#[arg(long, value_name = "PATH")]
		path: Option<PathBuf>,

		/// Bind authenticated HTTP MCP to loopback only (e.g., "127.0.0.1:12345").
		#[arg(long, value_name = "HOST:PORT")]
		bind: Option<String>,

		/// Path to SSH private key for remote filesystem access
		#[arg(long, value_name = "FILE")]
		ssh_key: Option<String>,

		/// SSH connection timeout in seconds for remote filesystem access
		#[arg(long, value_name = "SECS")]
		ssh_timeout: Option<u64>,

		/// Hepta Runtime host/policy JSON. Enables multi-host process, PTY, inspection and exact privileged-action tools.
		#[arg(long, value_name = "FILE")]
		runtime_config: Option<PathBuf>,

		/// Required for all HTTP MCP binds; private file with X-Hepta-Runtime-Token value.
		#[arg(long, value_name = "FILE")]
		auth_token_file: Option<PathBuf>,
	},
}
