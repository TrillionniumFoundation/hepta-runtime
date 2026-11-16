fn render_line(line_1idx: usize, content: &str) -> String {
	format!("{}|{}", line_id(line_1idx, content), content)
}
