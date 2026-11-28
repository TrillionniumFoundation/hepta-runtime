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
//! Invoke each original body under the same current-thread runtime flavor.
pub(super) fn run_all() -> anyhow::Result<Vec<&'static str>> {
    let mut completed = Vec::new();
    exclusive_fence_waiters_exceed_old_capacity_and_preserve_authority_after_cancellation();
    completed.push("exclusive_fence_waiters_exceed_old_capacity_and_preserve_authority_after_cancellation");
    cancelled_queued_fence_workers_complete_validation_without_leaking_authority();
    completed.push("cancelled_queued_fence_workers_complete_validation_without_leaking_authority");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(unpolled_fence_acquisition_never_submits_a_worker());
    drop(runtime);
    completed.push("unpolled_fence_acquisition_never_submits_a_worker");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(fence_acquisition_success_error_and_panic_preserve_results());
    drop(runtime);
    completed.push("fence_acquisition_success_error_and_panic_preserve_results");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(acquired_shared_fence_outlives_the_acquisition_worker());
    drop(runtime);
    completed.push("acquired_shared_fence_outlives_the_acquisition_worker");
    Ok(completed)
}
