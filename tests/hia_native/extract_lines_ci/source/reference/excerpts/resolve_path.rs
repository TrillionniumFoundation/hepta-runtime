pub fn resolve_path(path_str: &str, workdir: &Path) -> std::path::PathBuf {
	let path = Path::new(path_str);
	if path.is_absolute() {
		path.to_path_buf()
	} else {
		workdir.join(path)
	}
}
