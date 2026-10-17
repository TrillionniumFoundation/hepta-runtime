// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Offline-tested administrator primitive: freeze or resume the SAME owner.
//! This binary does NOT promote V4 to V11, adopt jobs, or certify production ingress.
//! It intentionally is not installed as a production command.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Component, Path};
const SCHEMA: &str = "hepta-effect-owner-fence-v1";
const MAX: u64 = 4096;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    owner: String,
    epoch: u64,
    phase: String,
    state_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor_state_root: Option<String>,
}
fn open_directory(path: &Path) -> Result<File> {
    if !path.is_absolute() { bail!("private absolute directory required") }
    let mut cur = File::open("/")?;
    for item in path.components() {
        let name = match item {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => bail!("special path component refused"),
        };
        let name = CString::new(name.as_bytes())?;
        let fd = unsafe { libc::openat(cur.as_raw_fd(), name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 { return Err(std::io::Error::last_os_error()).context("directory component unavailable") }
        cur = unsafe { File::from_raw_fd(fd) };
    }
    let st = cur.metadata()?;
    if !st.is_dir() || st.uid() != unsafe { libc::geteuid() } ||
        st.mode() & 0o777 != 0o700 { bail!("authority/state root must be owner-private mode 0700") }
    Ok(cur)
}
fn checked_file(parent: &File, name: &str, writable: bool) -> Result<File> {
    let c = CString::new(name)?;
    let mode = if writable { libc::O_RDWR } else { libc::O_RDONLY };
    let fd = unsafe {libc::openat(parent.as_raw_fd(), c.as_ptr(),
        mode | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)};
    if fd < 0 { return Err(std::io::Error::last_os_error()).context("required authority file unavailable") }
    let f = unsafe { File::from_raw_fd(fd) };
    let st = f.metadata()?;
    if !st.is_file() || st.uid() != unsafe {libc::geteuid()} || st.nlink() != 1 ||
        st.mode() & 0o777 != 0o600 { bail!("authority file must be private regular inode without aliases") }
    Ok(f)
}
fn stamp(f: &File) -> Result<(u64,u64,u64,u32,u64,i64,i64,i64,i64)> {
    let s=f.metadata()?;
    Ok((s.dev(),s.ino(),s.nlink(),s.mode(),s.len(),
        s.mtime(),s.mtime_nsec(),s.ctime(),s.ctime_nsec()))
}
fn ensure_path(path: &Path, pinned: &File) -> Result<()> {
    let current=open_directory(path)?;
    let a=pinned.metadata()?;let b=current.metadata()?;
    if (a.dev(),a.ino())!=(b.dev(),b.ino()) { bail!("authority root rebound") }
    Ok(())
}
fn read_record(root: &File) -> Result<Record> {
    let mut f=checked_file(root,".owner.json",false)?;
    let before=stamp(&f)?;
    if before.4 == 0 || before.4 > MAX { bail!("invalid authority record length") }
    let mut raw=Vec::with_capacity(before.4 as usize);
    (&mut f).take(MAX+1).read_to_end(&mut raw)?;
    if raw.len() as u64 != before.4 {bail!("owner record incomplete")}
    let again=checked_file(root,".owner.json",false)?;
    if before!=stamp(&f)? || before!=stamp(&again)? {bail!("owner record replaced during read")}
    let record:Record=serde_json::from_slice(&raw).context("invalid owner record")?;
    if record.schema!=SCHEMA || record.epoch==0 ||
        !matches!(record.owner.as_str(),"v4"|"v11") ||
        !matches!(record.phase.as_str(),"admitting"|"frozen") {
        bail!("unsupported owner/phase/epoch")
    }
    let state=open_directory(Path::new(&record.state_root))?;
    match (record.owner.as_str(), record.predecessor_state_root.as_deref()) {
        ("v4", None) => {}
        ("v11", Some(original)) => {
            let prior=open_directory(Path::new(original))?;
            if (state.metadata()?.dev(),state.metadata()?.ino()) ==
               (prior.metadata()?.dev(),prior.metadata()?.ino()) {
                bail!("old and successor owner states cannot alias")
            }
        }
        _ => bail!("V11 authority requires exact trusted V4 predecessor"),
    }
    Ok(record)
}
fn lock(root:&File, exclusive:bool)->Result<File> {
    let f=checked_file(root,".owner.lock",true)?;
    let op=if exclusive {libc::LOCK_EX} else {libc::LOCK_SH};
    if unsafe {libc::flock(f.as_raw_fd(),op|libc::LOCK_NB)}!=0 {
        return Err(std::io::Error::last_os_error()).context("shared authority currently busy")
    }
    let again=checked_file(root,".owner.lock",true)?;
    if stamp(&f)?!=stamp(&again)? {bail!("authority lock inode replaced")}
    Ok(f)
}
fn atomic_publish(root: &File, record:&Record, fail_before_rename:bool)->Result<()> {
    let name=format!(".owner.json.next.{}",std::process::id());
    let c=CString::new(name.as_bytes())?;
    let fd=unsafe {libc::openat(root.as_raw_fd(),c.as_ptr(),
        libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
    if fd<0 {return Err(std::io::Error::last_os_error()).context("owner publication temp file collision")}
    let mut f=unsafe {File::from_raw_fd(fd)};
    let result=(|| -> Result<()> {
        let body=serde_json::to_vec(record)?;
        if body.len() as u64>MAX { bail!("owner record exceeds maximum") }
        f.write_all(&body)?;f.sync_all()?;
        if fail_before_rename {bail!("simulated crash before owner record commit")}
        let dest=CString::new(".owner.json")?;
        if unsafe {libc::renameat(root.as_raw_fd(),c.as_ptr(),root.as_raw_fd(),dest.as_ptr())}!=0 {
            return Err(std::io::Error::last_os_error()).context("owner record rename failed")
        }
        root.sync_all()?;
        if read_record(root)?!=*record {bail!("committed authority record inconsistent")}
        Ok(())
    })();
    if result.is_err() {
        unsafe {libc::unlinkat(root.as_raw_fd(),c.as_ptr(),0);}
    }
    result
}
fn operate(root_path: &Path, action: &str, expected_owner: &str,
           expected_epoch: u64, fail_before_rename:bool)->Result<Record> {
    let root=open_directory(root_path)?;
    let _permit=lock(&root,true)?; // LOCK_EX waits for no in-flight native SH admissions.
    ensure_path(root_path,&root)?;
    let current=read_record(&root)?;
    if current.owner!=expected_owner || current.epoch!=expected_epoch {
        bail!("stale owner/epoch; no transition submitted")
    }
    if !matches!(expected_owner,"v4"|"v11"){bail!("unknown owner")}
    let phase=match (action,current.phase.as_str()) {
        ("freeze","admitting")=>"frozen",
        ("resume","frozen")=>"admitting",
        _=>bail!("invalid phase transition"),
    };
    let next=Record{phase:phase.into(),epoch:current.epoch.checked_add(1)
        .context("epoch exhausted")?,..current};
    // Preserve root inode, stable lock inode and the same state root.
    ensure_path(root_path,&root)?;
    atomic_publish(&root,&next,fail_before_rename)?;
    Ok(next)
}
/// Offline-only implementation of the V4(frozen) -> V11(admitting)
/// authority-record transition. This is deliberately NOT wired to the CLI:
/// production promotion also needs a verified all-ingress fence and an
/// immutable historical idempotency/reconciliation proof.
#[allow(dead_code)]
fn ensure_uncreated_effect_state(target: &Path) -> Result<()> {
    use std::fs;
    use std::io::ErrorKind;
    for family in ["jobs", "terminals"] {
        let directory = target.join(family);
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("successor effect registry not inspectable"),
            Ok(_) => {},
        };
        // Resolving from / with O_NOFOLLOW rejects symlinks and writable
        // ancestors as well as unsafe final directory modes.
        let pinned = open_directory(&directory)?;
        let before = stamp(&pinned)?;
        if fs::read_dir(&directory)?.next().is_some() {
            bail!("successor has existing effect identities; refusing promotion");
        }
        ensure_path(&directory, &pinned)?;
        if stamp(&pinned)? != before {
            bail!("successor effect registry changed during promotion check");
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn promote_frozen_v4_to_v11(
    authority_root: &Path,
    expected_frozen_epoch: u64,
    new_state_root: &Path,
    simulate_crash_before_commit: bool,
) -> Result<Record> {
    // The caller MUST first prove every effect ingress is running the fence.
    // With the freeze receipt committed and this exclusive lock held, no
    // properly-fenced V4 launch can overlap the ownership record switch.
    let root = open_directory(authority_root)?;
    let _exclusive = lock(&root, true)?;
    ensure_path(authority_root, &root)?;
    let previous = read_record(&root)?;
    if previous.owner != "v4" || previous.phase != "frozen"
        || previous.epoch != expected_frozen_epoch
    {
        bail!("old authority is not frozen at the exact expected V4 epoch");
    }
    let original_state_path = Path::new(&previous.state_root);
    let old_state = open_directory(original_state_path)?;
    let candidate = open_directory(new_state_root)?;
    let old_info = old_state.metadata()?;
    let next_info = candidate.metadata()?;
    if (old_info.dev(), old_info.ino()) == (next_info.dev(), next_info.ino()) {
        bail!("original and successor state roots are not independent");
    }
    ensure_uncreated_effect_state(new_state_root)?;
    ensure_path(original_state_path, &old_state)?;
    ensure_path(new_state_root, &candidate)?;
    ensure_path(authority_root, &root)?;
    let next = Record {
        owner: "v11".into(),
        epoch: previous.epoch.checked_add(1).context("owner epoch exhausted")?,
        phase: "admitting".into(),
        state_root: new_state_root.to_str()
            .context("successor state root is not Unicode")?.into(),
        predecessor_state_root: Some(previous.state_root.clone()),
        ..previous
    };
    // Atomic rename + directory fsync forms the durable linearization point.
    // On a crash before rename the original V4 owner stays frozen;
    // after rename the next inspect reveals V11 as the authoritative owner.
    atomic_publish(&root, &next, simulate_crash_before_commit)?;
    Ok(next)
}

fn inspect(root_path:&Path)->Result<Record> {
    let root=open_directory(root_path)?;
    let _read_lock=lock(&root,false)?;
    ensure_path(root_path,&root)?;
    read_record(&root)
}
fn main()->Result<()> {
    let args:Vec<String>=std::env::args().collect();
    if args.len()==3 && args[1]=="inspect" {
        let doc=inspect(Path::new(&args[2]))?;
        println!("owner={} epoch={} phase={}",doc.owner,doc.epoch,doc.phase);
        return Ok(())
    }
    if args.len()==5 && matches!(args[1].as_str(),"freeze"|"resume") {
        let epoch=args[4].parse::<u64>().context("invalid expected epoch")?;
        // No production unit invokes this binary. It cannot promote to V11.
        let next=operate(Path::new(&args[2]),&args[1],&args[3],epoch,false)?;
        println!("owner={} epoch={} phase={}",next.owner,next.epoch,next.phase);
        return Ok(())
    }
    bail!("usage: ownerctl inspect ROOT | freeze|resume ROOT v4|v11 EXPECTED_EPOCH")
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt,symlink};
    use tempfile::TempDir;
    struct Fixture {t:TempDir,root:std::path::PathBuf,state:std::path::PathBuf}
    impl Fixture {
        fn new()->Self {
            let t=tempfile::tempdir().unwrap();
            let root=t.path().join("authority"); let state=t.path().join("v4");
            for d in [&root,&state]{fs::create_dir(d).unwrap();fs::set_permissions(d,fs::Permissions::from_mode(0o700)).unwrap();}
            let lock=root.join(".owner.lock");fs::write(&lock,b"").unwrap();fs::set_permissions(&lock,fs::Permissions::from_mode(0o600)).unwrap();
            let doc=Record{schema:SCHEMA.into(),owner:"v4".into(),epoch:9,phase:"admitting".into(),state_root:state.to_str().unwrap().into(),predecessor_state_root:None};
            let d=open_directory(&root).unwrap();atomic_publish(&d,&doc,false).unwrap();
            Self{t,root,state}
        }
    }
    fn successor_fixture(f: &Fixture) -> std::path::PathBuf {
        let path = f.t.path().join("successor");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path,fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    fn freeze_fixture(f: &Fixture) {
        assert_eq!(operate(&f.root,"freeze","v4",9,false).unwrap().phase,"frozen");
    }

    #[test] fn promotion_requires_exact_frozen_v4_epoch() {
        let f=Fixture::new();
        let successor=successor_fixture(&f);
        assert!(promote_frozen_v4_to_v11(&f.root,9,&successor,false).is_err());
        freeze_fixture(&f);
        assert!(promote_frozen_v4_to_v11(&f.root,9,&successor,false).is_err());
        assert!(promote_frozen_v4_to_v11(&f.root,11,&successor,false).is_err());
        assert_eq!(inspect(&f.root).unwrap().owner,"v4");
        assert_eq!(inspect(&f.root).unwrap().phase,"frozen");
    }

    #[test] fn frozen_v4_can_promote_to_independent_empty_v11_only_in_isolated_fixture() {
        let f=Fixture::new();
        let successor=successor_fixture(&f);
        freeze_fixture(&f);
        let next=promote_frozen_v4_to_v11(&f.root,10,&successor,false).unwrap();
        assert_eq!((next.owner.as_str(),next.phase.as_str(),next.epoch),
                   ("v11","admitting",11));
        assert_eq!(Path::new(&next.state_root),successor);
        assert_eq!(inspect(&f.root).unwrap(),next);
        assert!(operate(&f.root,"resume","v4",10,false).is_err());
        assert!(promote_frozen_v4_to_v11(&f.root,11,&successor,false).is_err());
    }

    #[test] fn promotion_refuses_candidate_with_new_job_or_pty_identity() {
        for kind in ["jobs","terminals"] {
            let f=Fixture::new();
            let successor=successor_fixture(&f);
            freeze_fixture(&f);
            let dir=successor.join(kind);fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir,fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(dir.join("already-owned.json"),b"{}").unwrap();
            assert!(promote_frozen_v4_to_v11(&f.root,10,&successor,false).is_err());
            assert_eq!(inspect(&f.root).unwrap().phase,"frozen");
        }
    }

    #[test] fn promotion_refuses_alias_symlink_and_unsafe_private_candidate() {
        let f=Fixture::new();
        freeze_fixture(&f);
        assert!(promote_frozen_v4_to_v11(&f.root,10,&f.state,false).is_err());
        let target=successor_fixture(&f);
        let alias=f.t.path().join("v11-alias");
        symlink(&target,&alias).unwrap();
        assert!(promote_frozen_v4_to_v11(&f.root,10,&alias,false).is_err());
        fs::set_permissions(&target,fs::Permissions::from_mode(0o755)).unwrap();
        assert!(promote_frozen_v4_to_v11(&f.root,10,&target,false).is_err());
        fs::set_permissions(&target,fs::Permissions::from_mode(0o700)).unwrap();
        let evil=target.join("jobs");
        symlink("/tmp",&evil).unwrap();
        assert!(promote_frozen_v4_to_v11(&f.root,10,&target,false).is_err());
        assert_eq!(inspect(&f.root).unwrap().owner,"v4");
    }

    #[test] fn promotion_crash_before_commit_stays_frozen_and_reconcilable() {
        let f=Fixture::new();
        let target=successor_fixture(&f);
        freeze_fixture(&f);
        assert!(promote_frozen_v4_to_v11(&f.root,10,&target,true).is_err());
        assert_eq!((inspect(&f.root).unwrap().owner,inspect(&f.root).unwrap().phase),
                   ("v4".into(),"frozen".into()));
        assert_eq!(inspect(&f.root).unwrap().epoch,10);
        let next=promote_frozen_v4_to_v11(&f.root,10,&target,false).unwrap();
        assert_eq!((next.owner.as_str(),next.epoch),("v11",11));
    }

    #[test] fn promotion_cannot_overlap_in_flight_admission_lock() {
        let f=Fixture::new();
        let target=successor_fixture(&f);
        freeze_fixture(&f);
        let root=open_directory(&f.root).unwrap();
        let live=lock(&root,false).unwrap();
        assert!(promote_frozen_v4_to_v11(&f.root,10,&target,false).is_err());
        assert_eq!(inspect(&f.root).unwrap().owner,"v4");
        drop(live);
        assert_eq!(promote_frozen_v4_to_v11(&f.root,10,&target,false)
                   .unwrap().owner,"v11");
    }

    #[test] fn separate_os_process_holds_shared_lock_and_prevents_promote() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        let f=Fixture::new();
        let next=successor_fixture(&f);
        freeze_fixture(&f);
        let mut child=Command::new("/usr/bin/python3")
            .arg("-c")
            .arg("import fcntl,sys,time\nf=open(sys.argv[1],'r+b')\nfcntl.flock(f,fcntl.LOCK_SH)\nprint('LOCK_HELD',flush=True)\ntime.sleep(0.75)")
            .arg(f.root.join(".owner.lock"))
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut line=String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        assert_eq!(line.trim(),"LOCK_HELD");
        assert!(promote_frozen_v4_to_v11(&f.root,10,&next,false).is_err());
        assert_eq!(inspect(&f.root).unwrap().owner,"v4");
        assert!(child.wait().unwrap().success());
        assert_eq!(promote_frozen_v4_to_v11(&f.root,10,&next,false)
                   .unwrap().owner,"v11");
    }

    #[test] fn empty_but_private_v11_effect_registries_are_eligible() {
        let f=Fixture::new();
        let next=successor_fixture(&f);
        for kind in ["jobs","terminals"] {
            let folder=next.join(kind);
            fs::create_dir(&folder).unwrap();
            fs::set_permissions(&folder,fs::Permissions::from_mode(0o700)).unwrap();
        }
        freeze_fixture(&f);
        assert_eq!(promote_frozen_v4_to_v11(&f.root,10,&next,false)
                   .unwrap().owner,"v11");
    }

    #[test] fn frozen_and_resumed_epochs_are_monotonic() {
        let f=Fixture::new();assert_eq!(inspect(&f.root).unwrap().epoch,9);
        let x=operate(&f.root,"freeze","v4",9,false).unwrap();
        assert_eq!((x.epoch,x.phase.as_str()),(10,"frozen"));
        assert!(operate(&f.root,"freeze","v4",10,false).is_err());
        assert!(operate(&f.root,"resume","v4",9,false).is_err());
        let y=operate(&f.root,"resume","v4",10,false).unwrap();
        assert_eq!((y.epoch,y.phase.as_str()),(11,"admitting"));
    }
    #[test] fn no_transition_to_second_owner_command_exists() {
        let f=Fixture::new();assert!(operate(&f.root,"promote","v4",9,false).is_err());
        assert!(operate(&f.root,"freeze","v11",9,false).is_err());
    }
    #[test] fn shared_native_admission_blocks_exclusive_freeze() {
        let f=Fixture::new();
        let root=open_directory(&f.root).unwrap();
        let held=lock(&root,false).unwrap();
        assert!(operate(&f.root,"freeze","v4",9,false).is_err());
        drop(held);
        assert_eq!(operate(&f.root,"freeze","v4",9,false).unwrap().phase,"frozen");
    }
    #[test] fn crash_before_publish_leaves_previous_owner_admitting() {
        let f=Fixture::new();
        assert!(operate(&f.root,"freeze","v4",9,true).is_err());
        assert_eq!(inspect(&f.root).unwrap().phase,"admitting");
        assert_eq!(inspect(&f.root).unwrap().epoch,9);
    }
    #[test] fn forged_owner_record_or_unknown_fields_refuse() {
        let f=Fixture::new();
        fs::write(f.root.join(".owner.json"),b"{\"schema\":\"hepta-effect-owner-fence-v1\",\"owner\":\"v4\",\"owner\":\"v11\"}").unwrap();
        assert!(operate(&f.root,"freeze","v4",9,false).is_err());
    }
    #[test] fn symlinked_lock_and_wrong_modes_refuse() {
        let f=Fixture::new();
        fs::set_permissions(&f.root,fs::Permissions::from_mode(0o755)).unwrap();
        assert!(inspect(&f.root).is_err());
        fs::set_permissions(&f.root,fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(f.root.join(".owner.lock"),f.root.join("saved-lock")).unwrap();
        symlink("saved-lock",f.root.join(".owner.lock")).unwrap();
        assert!(operate(&f.root,"freeze","v4",9,false).is_err());
    }
    #[test] fn stale_owner_root_and_epoch_refused() {
        let f=Fixture::new();
        assert!(operate(&f.root,"freeze","v4",8,false).is_err());
        assert!(operate(&f.root,"freeze","v11",9,false).is_err());
        fs::set_permissions(&f.state,fs::Permissions::from_mode(0o755)).unwrap();
        assert!(operate(&f.root,"freeze","v4",9,false).is_err());
    }
    #[test] fn root_rebinding_fails_without_touching_old_inode() {
        let f=Fixture::new();let alias=f.t.path().join("alias");
        symlink(&f.root,&alias).unwrap();
        assert!(operate(&alias,"freeze","v4",9,false).is_err());
        assert_eq!(inspect(&f.root).unwrap().phase,"admitting");
    }
    #[test] fn hardlinked_owner_record_refuses() {
        let f=Fixture::new();
        fs::hard_link(f.root.join(".owner.json"),f.root.join("alias")).unwrap();
        assert!(inspect(&f.root).is_err());
        assert!(operate(&f.root,"freeze","v4",9,false).is_err());
    }
}
