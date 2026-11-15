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
// Qualification-only reference carrier; original extracted bodies remain unchanged.
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

pub mod effect_owner_fence;
