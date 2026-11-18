// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
#[rustfmt::skip]
pub(super) fn eligible(tool: &str) -> bool {
	matches!(
		tool,
		"read_multiple_files"
			| "file_info"
			| "binary_read"
			| "process_status"
			| "process_read"
			| "process_wait"
			| "process_list"
			| "hardware_snapshot"
			| "service_status"
			| "network_inspect"
	)
}
