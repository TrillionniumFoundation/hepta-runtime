// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
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
// Observer appended inside the unchanged original module's lexical scope.

pub fn trace_canonical_writer(line: &str) -> Result<Value> {
	struct Observed {
		owner: Commitment,
		calls: Vec<Vec<u8>>,
	}
	impl Write for Observed {
		fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
			let size = self.owner.write(bytes)?;
			self.calls.push(bytes[..size].to_vec());
			Ok(size)
		}
		fn flush(&mut self) -> std::io::Result<()> {
			self.owner.flush()
		}
	}
	let params: BellmanPlanParams = serde_json::from_str(line)?;
	let mut writer = Observed {
		owner: Commitment { hash: Sha256::new(), bytes: 0, end: Instant::now() + Duration::from_secs(30) },
		calls: Vec::new(),
	};
	serde_json::to_writer(&mut writer, &params)?;
	let complete: Vec<u8> = writer.calls.iter().flatten().copied().collect();
	let request_sha256 = hex(writer.owner.hash.finalize());
	Ok(json!({
		"write_calls": writer.calls.iter().map(hex).collect::<Vec<_>>(),
		"canonical_hex": hex(&complete),
		"canonical_bytes": writer.owner.bytes,
		"request_sha256": request_sha256,
		"original_source_sha256": hex(Sha256::digest(include_bytes!("weight_bellman.rs"))),
		"observer_changes_original_write_body": false,
		"public_handler_qualified": false
	}))
}
