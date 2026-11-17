#[derive(Debug, Clone)]
pub struct RemoteMetadata {
	pub size: u64,
	pub is_dir: bool,
	pub is_file: bool,
	pub modified: Option<SystemTime>,
}
