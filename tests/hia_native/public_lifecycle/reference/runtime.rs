pub mod config;
pub mod inspect;
pub mod effective_config;
pub fn query(op:u64,key:&str)->anyhow::Result<Vec<u8>> {
 use std::os::unix::ffi::OsStrExt;
 match op {
  1=>inspect::host_list().map(String::into_bytes),
  2=>effective_config::effective_config(effective_config::EffectiveConfigParams{}).map(String::into_bytes),
  3=>config::runtime_policy_digest().map(|v|v.to_vec()),
  4=>{let c=config::runtime_config()?;let _host=c.host(key)?;Ok(key.as_bytes().to_vec())},
  5=>{let c=config::runtime_config()?;Ok(c.host_by_alias(key).map(|(name,_)|name.as_bytes().to_vec()).unwrap_or_default())},
  6=>Ok(config::runtime_config()?.state_dir.as_os_str().as_bytes().to_vec()),
  _=>panic!("unknown fixed config reference operation")
 }
}

pub mod execution;

// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
pub mod request_audit;
mod namespace_version;
pub mod operation_async;
pub mod caller_scope;
pub mod operation_crypto;
pub mod search_jobs;
pub mod request_results;
pub mod request_async;
fn get(raw: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn put(raw: &mut [u8], at: usize, value: u64) {
	raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn diagnostic(error: &anyhow::Error) -> (u64, u64) {
	if let Some(value) = error.downcast_ref::<std::io::Error>() {
		use std::io::ErrorKind;
		return match value.kind() {
			ErrorKind::UnexpectedEof => (7, 0),
			ErrorKind::WriteZero => (15, 0),
			ErrorKind::NotFound => (23, value.raw_os_error().unwrap_or(2) as u64),
			ErrorKind::AlreadyExists => (23, value.raw_os_error().unwrap_or(17) as u64),
			_ => (
				23,
				value.raw_os_error().expect("actual original OS errno") as u64,
			),
		};
	}
	if error.downcast_ref::<serde_json::Error>().is_some() {
		return (24, 0);
	}
	if error.downcast_ref::<std::str::Utf8Error>().is_some() {
		return (28, 0);
	}
	let code = match error.to_string().as_str() {
		"private request archive legacy anchor refused" => 1,
		"request archive legacy anchor binding changed" => 2,
		"request archive legacy anchor changed while reading" => 3,
		"request archive legacy anchor bytes changed" => 4,
		"request archive legacy anchor disappeared" => 5,
		"request archive legacy anchor size refused" => 6,
		"request audit metadata size refused" => 8,
		"request audit retention invariant exceeded" => 32,
		"unexpected private request audit entry" => 33,
		"request audit receipt binding changed" => 20,
		"request audit record size refused" => 22,
		"invalid private metadata component" => 29,
		"request archive root binding changed" => 10,
		"request archive identity changed; history never recreated automatically" => 11,
		"unanchored request archive refused; history never recreated automatically" => 12,
		"private request audit directory refused" => 13,
		"request identity entropy unavailable" => 14,
		"private request audit inode refused" => 17,
		"audit staging inode refused" => 18,
		"audit staging hard-link binding refused" => 19,
		"request audit metadata identity refused" => 25,
		"invalid request metadata filename" => 26,
		"unexpected private audit staging entry" | "unexpected private audit staging identity" => {
			27
		}
		"request archive layout anchor refused" => 40,
		"request archive layout anchor changed" => 41,
		"request archive layout anchor binding changed" => 42,
		"request archive layout anchor link count changed" => 43,
		"request archive initialization intent refused" => 44,
		"request archive initialization intent changed" => 45,
		"request archive initialization intent binding changed" => 46,
		"request archive initialization intent link count changed" => 47,
		"request archive initialization metadata refused" => 48,
		"request archive initialization hard-link binding refused" => 49,
		"request archive anchor size refused" => 51,
		"request archive initialization intent disappeared" => 60,
		"request archive initialization intent size refused" => 62,
		"request archive layout anchor size refused" => 63,
		"invalid request archive filename" => 64,
		"request archive directory disappeared" => 65,
		"request archive directory binding changed" => 66,
		"request archive initialization intent reappeared" => 69,
		"request archive layout changed before directory set validation" => 70,
		"unexpected request archive shard namespace entry" => 72,
		"duplicate request archive shard directory" => 73,
		"request archive shard directory missing" => 74,
		"duplicate request archive identity across namespaces" => 75,
		"request archive record changed physical namespace" => 76,
		"request archive target unavailable" => 77,
		"foreign request archive target directory" => 78,
		"request archive layout binding changed" => 79,
		"unanchored request archive shards refused; history never rebound automatically" => 80,
		"request archive shard root identity changed" => 81,
		"request archive shard identity changed" => 82,
		"request archive layout initialized concurrently" => 83,
		"request archive completed initialization binding changed" => 84,
		"request archive initialization root identity changed" => 85,
		"unexpected request archive initialization entry" => 86,
		"unrecorded request archive initialization directory" => 87,
		"recorded request archive initialization directory disappeared" => 88,
		"request archive initialization directory missing" => 89,
		"request archive shard binding changed" => 93,
		"duplicate request archive initialization directory" => 94,
		"request archive initialization encountered unexpected data" => 95,
		"request archive initialization shard identity changed" => 96,
		"request archive initialization shard binding changed" => 97,
		other => panic!("unclassified original refusal: {other}"),
	};
	(code, 0)
}

