// Qualification-only serial transport. The included production functions and
// their argument decoder above are unchanged; all observer access is read-only.

fn invalid(message: &str) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn output(raw: &[u8]) -> io::Result<()> {
	let mut stream = io::stdout().lock();
	stream.write_all(&(raw.len() as u64).to_le_bytes())?;
	stream.write_all(raw)?;
	stream.flush()
}

fn observation(raw: &[u8]) -> io::Result<()> {
	let mut stream = io::stderr().lock();
	stream.write_all(raw)?;
	stream.flush()
}

fn snapshot(cache: &mcp::fs::delta::ViewCache, phase: u64, generation: u64) -> io::Result<()> {
	observation(&mcp::fs::delta::fixture_snapshot(cache, phase))?;
	observation(&mcp::fs::core::fixture_history_snapshot(phase, generation))?;
	observation(&mcp::fs::text_editing::fixture_lock_snapshot(phase, generation))
}

fn main() -> Result<()> {
	std::panic::set_hook(Box::new(|_| {}));
	if std::env::args_os().len() != 1 {
		return Err(invalid("fixture does not accept arguments").into());
	}
	let workdir = std::env::current_dir()?;
	let runtime = tokio::runtime::Builder::new_current_thread()
		.max_blocking_threads(1)
		.build()?;
	let cache = Arc::new(mcp::fs::delta::ViewCache::default());
	let mut cache_initialized = false;
	let mut history_initialized = false;
	let mut generation = 0u64;
	let mut stdin = io::stdin().lock();
	loop {
		let mut length = [0u8; 8];
		if stdin.read(&mut length[..1])? == 0 {
			break;
		}
		stdin.read_exact(&mut length[1..])?;
		let length = usize::try_from(u64::from_le_bytes(length))
			.map_err(|_| invalid("fixture length"))?;
		if !(8..=536870912).contains(&length) {
			return Err(invalid("private fixture frame domain").into());
		}
		let mut raw = vec![0u8; length];
		stdin.read_exact(&mut raw)?;
		if &raw[..8] == b"HVCACH01" {
			if raw.len() < 48 {
				return Err(invalid("short cache fixture").into());
			}
			if word(&raw, 8) == 0 {
				if cache_initialized || raw.len() != 48 || raw[8..] != [0u8; 40] {
					return Err(invalid("cache setup is permitted once").into());
				}
				cache_initialized = true;
				let mut response = b"HVCAR001".to_vec();
				response.extend_from_slice(&[0u8; 24]);
				output(&response)?;
			} else {
				if !cache_initialized {
					return Err(invalid("cache fixture before setup").into());
				}
				output(&mcp::fs::delta::fixture_apply(&cache, &raw)?)?;
			}
			continue;
		}
		if &raw[..8] == b"HHISTQ01" {
			if raw.len() < 64 {
				return Err(invalid("short history fixture").into());
			}
			if word(&raw, 8) == 0 {
				if history_initialized || raw.len() != 64 || raw[8..] != [0u8; 56] {
					return Err(invalid("history setup is permitted once").into());
				}
				history_initialized = true;
			} else if !history_initialized {
				return Err(invalid("history fixture before setup").into());
			}
			output(&mcp::fs::core::fixture_history_apply(&raw)?)?;
			continue;
		}
		if !cache_initialized || !history_initialized || raw.len() < 64
			|| &raw[..8] != b"HFBWT001"
			|| !(1..=2).contains(&word(&raw, 8))
			|| word(&raw, 16) > raw.len() as u64 - 64
			|| word(&raw, 24) > raw.len() as u64 - 64 - word(&raw, 16)
			|| word(&raw, 40) != raw.len() as u64 - 64 - word(&raw, 16) - word(&raw, 24)
			|| word(&raw, 48) > 1 || word(&raw, 56) != 0
		{
			return Err(invalid("non-admitted Batch fixture frame").into());
		}
		generation = generation.checked_add(1).expect("finite fixture generation");
		let (call, operations) = decode(&raw, &workdir);
		let context = word(&raw, 8);
		snapshot(&cache, 0, generation)?;
		let body = async {
			let result = mcp::fs::text_editing::batch_edit_spec(&call, &operations).await;
			(result, mcp::request_ctx::drain_hints())
		};
		let (result, hints) = if context == 1 {
			runtime.block_on(mcp::request_ctx::with_request_context(cache.clone(), body))
		} else {
			runtime.block_on(body)
		};
		let response = answer(result);
		let mut hint_body = Vec::new();
		for hint in &hints {
			hint_body.extend_from_slice(&(hint.len() as u64).to_le_bytes());
			hint_body.extend_from_slice(hint.as_bytes());
		}
		let mut hint_frame = b"HLBBHT01".to_vec();
		for value in [48 + hint_body.len() as u64, generation, 1, word(&response, 8), hints.len() as u64] {
			hint_frame.extend_from_slice(&value.to_le_bytes());
		}
		hint_frame.extend_from_slice(&hint_body);
		observation(&hint_frame)?;
		snapshot(&cache, 1, generation)?;
		output(&response)?;
	}
	drop(runtime);
	Ok(())
}
