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

// Test-only private accessors. The called lifecycle functions remain unchanged.

pub(crate) async fn fixture_execute(
	call: &McpToolCall,
	timeout: Duration,
	on_background: Option<BackgroundNotify>,
) -> Result<ShellOutcome> {
	execute_with_timeout(call, timeout, on_background).await
}

pub(crate) fn fixture_tracked_pids() -> Vec<u32> {
	match SHELL_CHILDREN.lock() {
		Ok(guard) => {
			let mut pids: Vec<u32> = guard
				.as_ref()
				.map(|set| set.iter().copied().collect())
				.unwrap_or_default();
			pids.sort_unstable();
			pids
		}
		Err(_) => Vec::new(),
	}
}
