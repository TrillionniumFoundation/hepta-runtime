// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Reject malformed native frame extents without panics or substituted bytes.

use super::*;

#[test]
fn native_word_and_span_decoding_refuse_truncation_and_overflow() {
	assert_eq!(frame_word(&42_u64.to_le_bytes(), 0).unwrap(), 42);
	assert!(frame_word(&[0; 7], 0).is_err());
	assert!(frame_word(&[0; 8], 1).is_err());
	assert!(frame_word(&[0; 8], usize::MAX).is_err());
	let mut observation = WireObservation {
		raw: b"original",
		descriptor: [1_u64.to_le_bytes(), 3_u64.to_le_bytes()].concat(),
	};
	assert_eq!(observation.span(0), Some(b"rig".as_slice()));
	assert!(observation.span(8).is_none());
	assert!(observation.span(usize::MAX).is_none());
	observation.descriptor = [u64::MAX.to_le_bytes(), 1_u64.to_le_bytes()].concat();
	assert!(observation.span(0).is_none());
}

#[tokio::test]
async fn http_capture_retains_original_bytes_and_refuses_overflow_or_reuse() {
	use axum::body::to_bytes;
	for size in [13, WIRE_MAX, WIRE_MAX + 1] {
		let original = vec![b'x'; size];
		let captured = HttpRequestWire(Arc::new(Mutex::new(Some(Vec::new()))));
		let body = Body::new(CapturingBody {
			body: Body::from(original.clone()),
			wire: captured.clone(),
		});
		assert_eq!(to_bytes(body, size).await.unwrap().as_ref(), original);
		let (mut parts, _) = Request::new(Body::empty()).into_parts();
		parts.extensions.insert(captured);
		if size <= WIRE_MAX {
			assert_eq!(take_http_wire(&parts).unwrap(), original);
		} else {
			assert!(take_http_wire(&parts).is_err());
		}
		assert!(take_http_wire(&parts).is_err());
	}
	let (missing, _) = Request::new(Body::empty()).into_parts();
	assert!(take_http_wire(&missing).is_err());
}
