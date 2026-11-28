// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Exact target items; verified by the source extraction manifest.
use std::cell::RefCell;
use std::sync::Arc;
use super::fs::delta::ViewCache;

struct RequestContext {
	hints: RefCell<Vec<String>>,
	view_cache: Arc<ViewCache>,
}


tokio::task_local! {
	static CTX: RequestContext;
}


pub async fn with_request_context<F>(view_cache: Arc<ViewCache>, fut: F) -> F::Output
where
	F: std::future::Future,
{
	CTX.scope(
		RequestContext {
			hints: RefCell::new(Vec::new()),
			view_cache,
		},
		fut,
	)
	.await
}


pub fn with_view_cache<R>(f: impl FnOnce(&ViewCache) -> R) -> Option<R> {
	CTX.try_with(|ctx| f(&ctx.view_cache)).ok()
}


