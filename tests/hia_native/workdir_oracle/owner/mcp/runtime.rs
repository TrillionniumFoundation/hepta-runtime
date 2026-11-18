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
