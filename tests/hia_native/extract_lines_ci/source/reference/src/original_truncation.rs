// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact production items; verified by the source extraction manifest.
use super::line_hash::line_id;

fn render_line(line_1idx: usize, content: &str) -> String {
	format!("{}|{}", line_id(line_1idx, content), content)
}

pub fn format_extracted_content_smart(
	lines: &[&str],
	start_line: usize,
	max_display_lines: Option<usize>,
) -> String {
	let render = |i: usize| render_line(start_line + i, lines[i]);

	let max_lines = max_display_lines.unwrap_or(50);

	if lines.len() <= max_lines {
		(0..lines.len()).map(render).collect::<Vec<_>>().join("\n")
	} else {
		let show_first = (max_lines * 2) / 3;
		let show_last = max_lines - show_first - 1;

		let mut result_lines = Vec::new();

		for i in 0..show_first {
			result_lines.push(render(i));
		}

		let hidden_lines = lines.len() - show_first - show_last;
		result_lines.push(format!("[...{} lines more]", hidden_lines));

		for i in (lines.len() - show_last)..lines.len() {
			result_lines.push(render(i));
		}

		result_lines.join("\n")
	}
}
