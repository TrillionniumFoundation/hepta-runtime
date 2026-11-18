// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::OnceLock;
use std::path::PathBuf;
pub(super) struct Coordinator;
static COORDINATOR: OnceLock<Coordinator> = OnceLock::new();
pub(super) fn coordinator() -> Option<&'static Coordinator> {
	COORDINATOR.get()
}
impl Coordinator {
 pub(super) fn begin(&self,_root:PathBuf,_owner:String,_tool:String,_target:Option<String>)->Result<RequestTicket> {
  panic!("group-commit activation is outside this original qualification");
 }
 pub(super) fn finish(&self,_root:PathBuf,_ticket:RequestTicket,_completion:AuditCompletion)->Result<()> {
  panic!("group-commit activation is outside this original qualification");
 }
}
