// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

// Test-only typed configuration fixture. Policy function bodies below are unchanged.
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::io::{self, BufRead, Write};
type Result<T> = std::result::Result<T, String>;
macro_rules! anyhow { ($($arg:tt)*) => { format!($($arg)*) }; }
macro_rules! bail { ($($arg:tt)*) => {{ return Err(format!($($arg)*)); }}; }
#[derive(Clone,Copy,PartialEq,Eq)]
enum ExecutionMode { Isolated, Operator }
#[derive(Clone)]
struct HostConfig {
 execution_mode:ExecutionMode,ssh_target:String,allow_execute:bool,allow_pty:bool,allow_write:bool,
 allowed_cwd_prefixes:Vec<String>,allowed_read_path_prefixes:Vec<String>,allowed_write_path_prefixes:Vec<String>,
 protected_path_prefixes:Vec<String>,protected_argument_substrings:Vec<String>,denied_executables:Vec<String>,allowed_dangerous_executables:Vec<String>,
}
struct RuntimeConfig { hosts:BTreeMap<String,HostConfig> }
thread_local! { static FIXTURE:Cell<Option<&'static RuntimeConfig>> = const { Cell::new(None) }; }
fn runtime_config() -> Result<&'static RuntimeConfig> {
 FIXTURE.with(|slot|slot.get().ok_or_else(||"runtime tools are disabled; start with --runtime-config <file>".to_owned()))
}
fn maybe_runtime_config() -> Option<&'static RuntimeConfig> { FIXTURE.with(Cell::get) }
impl RuntimeConfig {
	pub fn host(&self, name: &str) -> Result<&HostConfig> {
		self.hosts
			.get(name)
			.ok_or_else(|| anyhow!("unknown host `{name}`; call host_list for configured names"))
	}

	pub fn host_by_alias(&self, alias: &str) -> Option<(&str, &HostConfig)> {
		self.hosts
			.iter()
			.find(|(name, host)| name.as_str() == alias || host.ssh_target == alias)
			.map(|(name, host)| (name.as_str(), host))
	}
}
const DEFAULT_DANGEROUS: &[&str] = &[
	"sudo",
	"su",
	"doas",
	"sh",
	"bash",
	"dash",
	"zsh",
	"fish",
	"ksh",
	"ssh",
	"scp",
	"sftp",
	"nohup",
	"setsid",
	"tmux",
	"screen",
	"systemd-run",
	"crontab",
	"at",
	"nsenter",
	"unshare",
	"kill",
	"pkill",
	"killall",
	"systemctl",
	"service",
	"loginctl",
	"reboot",
	"shutdown",
	"poweroff",
	"halt",
	"init",
	"mount",
	"umount",
	"modprobe",
	"insmod",
	"rmmod",
	"apt",
	"apt-get",
	"dpkg",
	"rpm",
	"dnf",
	"yum",
	"snap",
	"docker",
	"podman",
	"virsh",
	"nft",
	"iptables",
	"ip6tables",
];

const DANGEROUS_ENV: &[&str] = &[
	"LD_PRELOAD",
	"LD_LIBRARY_PATH",
	"DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH",
	"PYTHONPATH",
	"PYTHONHOME",
	"NODE_OPTIONS",
	"BASH_ENV",
	"ENV",
	"PERL5OPT",
	"RUBYOPT",
	"GIT_SSH",
	"GIT_SSH_COMMAND",
	"SSH_ASKPASS",
	"SUDO_ASKPASS",
];
fn executable_basename(executable: &str) -> &str {
	executable.rsplit('/').next().unwrap_or(executable)
}

fn protected_value(host: &HostConfig, value: &str) -> Option<String> {
	host.protected_path_prefixes
		.iter()
		.chain(host.protected_argument_substrings.iter())
		.find(|prefix| !prefix.is_empty() && value.contains(prefix.as_str()))
		.cloned()
}

pub fn check_environment(host_name: &str, env: &BTreeMap<String, String>) -> Result<()> {
	let host = runtime_config()?.host(host_name)?;
	for (key, value) in env {
		if value.contains('\0') {
			bail!("environment values may not contain NUL bytes");
		}
		if host.execution_mode == ExecutionMode::Isolated && DANGEROUS_ENV.contains(&key.as_str()) {
			bail!("environment variable `{key}` is denied on host `{host_name}`");
		}
		if let Some(prefix) = protected_value(host, value) {
			bail!("environment value intersects protected value `{prefix}` on host `{host_name}`");
		}
	}
	Ok(())
}

pub fn check_protected_input(host_name: &str, value: &str) -> Result<()> {
	let host = runtime_config()?.host(host_name)?;
	if let Some(prefix) = protected_value(host, value) {
		bail!("value intersects protected value `{prefix}` on host `{host_name}`");
	}
	Ok(())
}

pub fn check_execution(
	host_name: &str,
	executable: &str,
	args: &[String],
	cwd: Option<&str>,
	pty: bool,
) -> Result<&'static HostConfig> {
	let config = runtime_config()?;
	let host = config.host(host_name)?;
	validate_execution(host_name, host, executable, args, cwd, pty)?;
	Ok(host)
}

fn validate_execution(
	host_name: &str,
	host: &HostConfig,
	executable: &str,
	args: &[String],
	cwd: Option<&str>,
	pty: bool,
) -> Result<()> {
	if pty && !host.allow_pty {
		bail!("PTY execution is disabled for host `{host_name}`");
	}
	if !pty && !host.allow_execute {
		bail!("process execution is disabled for host `{host_name}`");
	}
	if executable.trim().is_empty() || executable.contains('\0') {
		bail!("executable must be a non-empty absolute path");
	}
	let executable_path = Path::new(executable);
	if !executable_path.is_absolute()
		|| executable_path
			.components()
			.any(|part| matches!(part, Component::ParentDir))
	{
		bail!("executable `{executable}` must be an absolute path without parent traversal");
	}
	if let Some(prefix) = protected_value(host, executable) {
		bail!("executable intersects protected value `{prefix}` on host `{host_name}`");
	}
	let base = executable_basename(executable);
	let explicitly_denied = host
		.denied_executables
		.iter()
		.any(|x| x == base || x == executable);
	let dangerous = DEFAULT_DANGEROUS.contains(&base);
	let explicitly_allowed = host
		.allowed_dangerous_executables
		.iter()
		.any(|x| x == base || x == executable);
	if explicitly_denied
		|| (host.execution_mode == ExecutionMode::Isolated && dangerous && !explicitly_allowed)
	{
		bail!(
            "executable `{base}` is denied on host `{host_name}`; use a named privileged_action when configured"
        );
	}
	if let Some(cwd) = cwd {
		if cwd.contains('\0')
			|| !Path::new(cwd).is_absolute()
			|| Path::new(cwd)
				.components()
				.any(|c| matches!(c, Component::ParentDir))
		{
			bail!("cwd must be an absolute path");
		}
		if !host.allowed_cwd_prefixes.is_empty()
			&& !host.allowed_cwd_prefixes.iter().any(|prefix| {
				cwd == prefix || cwd.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
			}) {
			bail!("cwd `{cwd}` is outside configured execution roots on host `{host_name}`");
		}
		if let Some(prefix) = protected_value(host, cwd) {
			bail!("cwd intersects protected value `{prefix}` on host `{host_name}`");
		}
	}
	for arg in args {
		if arg.contains('\0') {
			bail!("arguments may not contain NUL bytes");
		}
		if let Some(prefix) = protected_value(host, arg) {
			bail!("argument intersects protected value `{prefix}` on host `{host_name}`");
		}
	}
	Ok(())
}

fn normalize_absolute(path: &Path) -> Result<PathBuf> {
	if !path.is_absolute() {
		bail!("path `{}` must be absolute", path.display());
	}
	let mut normalized = PathBuf::from("/");
	for component in path.components() {
		match component {
			Component::RootDir => normalized = PathBuf::from("/"),
			Component::CurDir => {}
			Component::ParentDir => {
				if !normalized.pop() {
					bail!("path `{}` escapes the filesystem root", path.display());
				}
			}
			Component::Normal(part) => normalized.push(part),
			Component::Prefix(_) => bail!("Windows path prefixes are not accepted here"),
		}
	}
	Ok(normalized)
}

fn path_under(candidate: &Path, root: &Path) -> bool {
	candidate == root || candidate.starts_with(root)
}

fn remote_path_allowed(path: &str, prefixes: &[String]) -> bool {
	prefixes.iter().any(|prefix| {
		path == prefix || path.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
	})
}

pub fn check_remote_path(
	alias: &str,
	path: &str,
	user_explicit: bool,
	port_explicit: bool,
	write: bool,
) -> Result<()> {
	let Some(config) = maybe_runtime_config() else {
		return Ok(());
	};
	let Some((name, host)) = config.host_by_alias(alias) else {
		bail!("remote file access to unregistered SSH host `{alias}` is disabled");
	};
	if user_explicit || port_explicit {
		bail!(
			"remote file access must use the registered SSH alias without user or port overrides"
		);
	}
	if !path.starts_with('/') || path == "/~" || path.starts_with("/~/") {
		bail!("remote file access requires an absolute target path");
	}
	if path.split('/').any(|component| component == "..") {
		bail!("remote path traversal is not allowed");
	}
	if let Some(prefix) = host
		.protected_path_prefixes
		.iter()
		.find(|prefix| remote_path_allowed(path, std::slice::from_ref(prefix)))
	{
		bail!("path `{path}` is protected by prefix `{prefix}` on host `{name}`");
	}
	if write {
		if !host.allow_write {
			bail!("remote writes are disabled for host `{name}`");
		}
		if !remote_path_allowed(path, &host.allowed_write_path_prefixes) {
			bail!("path `{path}` is outside configured write roots on host `{name}`");
		}
	} else if !remote_path_allowed(path, &host.allowed_read_path_prefixes) {
		bail!("path `{path}` is outside configured read roots on host `{name}`");
	}
	Ok(())
}

fn hex(raw: &[u8]) -> String { raw.iter().map(|v| format!("{v:02x}")).collect() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn word(s: &[u8], at: usize) -> u64 { u64::from_le_bytes(s[at..at+8].try_into().unwrap()) }
fn output(tag:u64,value:u64,body:&[u8]) -> Vec<u8> {
 let mut out=b"HRTPLR01".to_vec();out.extend_from_slice(&tag.to_le_bytes());out.extend_from_slice(&value.to_le_bytes());out.extend_from_slice(&(body.len() as u64).to_le_bytes());out.extend_from_slice(body);out
}
fn unit(value:Result<()>) -> Vec<u8> {match value {Ok(())=>output(0,0,&[]),Err(err)=>output(1,0,err.as_bytes())}}
fn apply(raw:&[u8]) -> Vec<u8> {
 let op=word(raw,8);let state=word(raw,16);let mode=word(raw,24);let flags=word(raw,32);let request=word(raw,40);
 let counts:Vec<usize>=(48..=112).step_by(8).map(|i|word(raw,i) as usize).collect();
 let count=5+counts.iter().sum::<usize>()+counts[1];let mut at=128;let mut records=Vec::new();
 for _ in 0..count {let n=word(raw,at) as usize;at+=8;records.push(&raw[at..at+n]);at+=n;}
 let text=|i:usize|std::str::from_utf8(records[i]).unwrap();
 let name=text(0);let alias=text(1);let mut index=5;
 let args:Vec<String>=(index..index+counts[0]).map(|i|text(i).to_owned()).collect();index+=counts[0];
 let mut env=BTreeMap::new();for _ in 0..counts[1] {env.insert(text(index).to_owned(),text(index+1).to_owned());index+=2;}
 let mut lists=Vec::new();for count in &counts[2..] {lists.push((index..index+count).map(|i|text(i).to_owned()).collect::<Vec<_>>());index+=count;}
 let host=HostConfig {execution_mode:if mode==0 {ExecutionMode::Isolated} else {ExecutionMode::Operator},ssh_target:alias.to_owned(),
  allow_execute:flags&1!=0,allow_pty:flags&2!=0,allow_write:flags&4!=0,
  allowed_cwd_prefixes:lists[0].clone(),allowed_read_path_prefixes:lists[1].clone(),allowed_write_path_prefixes:lists[2].clone(),
  protected_path_prefixes:lists[3].clone(),protected_argument_substrings:lists[4].clone(),denied_executables:lists[5].clone(),allowed_dangerous_executables:lists[6].clone()};
 if state==0 {FIXTURE.with(|slot|slot.set(None));} else {
  let mut hosts=BTreeMap::new();if state==2 {hosts.insert(name.to_owned(),host.clone());}
  FIXTURE.with(|slot|slot.set(Some(Box::leak(Box::new(RuntimeConfig{hosts})))));
 }
 match op {
  1=>unit(check_execution(name,text(2),&args,if request&2!=0 {Some(text(3))} else {None},request&1!=0).map(|_|())),
  2=>unit(check_environment(name,&env)),
  3=>match protected_value(&host,text(2)) {Some(s)=>output(3,0,s.as_bytes()),None=>output(4,0,&[])},
  4=>unit(check_protected_input(name,text(2))),
  5=>output(2,remote_path_allowed(text(2),&host.allowed_read_path_prefixes) as u64,&[]),
  6=>unit(check_remote_path(alias,text(2),request&4!=0,request&8!=0,request&16!=0)),
  7=>match normalize_absolute(Path::new(OsStr::from_bytes(records[2]))) {Ok(p)=>output(5,0,p.as_os_str().as_bytes()),Err(err)=>output(1,0,err.as_bytes())},
  8=>output(2,path_under(Path::new(OsStr::from_bytes(records[2])),Path::new(OsStr::from_bytes(records[4]))) as u64,&[]),
  _=>panic!("unknown operation"),
 }
}
fn main() {
 std::panic::set_hook(Box::new(|_|{}));let stdin=io::stdin();let mut out=io::BufWriter::new(io::stdout().lock());
 for line in stdin.lock().lines() {let raw=unhex(&line.unwrap());match std::panic::catch_unwind(||apply(&raw)) {
  Ok(bytes)=>writeln!(&mut out,"OK {}",hex(&bytes)).unwrap(),Err(_)=>writeln!(&mut out,"PANIC").unwrap(),
 }}
}
