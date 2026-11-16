pub fn note_create(source: &PathSource, content: &str) {
	let key = lock_key_for_source(source);
	with_view_cache(|cache| cache.set(key.clone(), normalize(content)));
}
