// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    v4_state: PathBuf,
    v11_state: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("authority");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let v4_state = temp.path().join("v4-state");
        let v11_state = temp.path().join("v11-state");
        for state in [&v4_state, &v11_state] {
            fs::create_dir(state).unwrap();
            fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let lock = root.join(".owner.lock");
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
        let f = Self { temp, root, v4_state, v11_state };
        f.write_state("v4", "admitting", 7);
        f
    }
    fn write_state(&self, owner: &str, phase: &str, epoch: u64) {
        let state = if owner == "v4" { &self.v4_state } else { &self.v11_state };
        let record = serde_json::json!({
            "schema": SCHEMA, "owner":owner, "phase":phase,
            "epoch":epoch, "state_root": state.to_str().unwrap(),
            "predecessor_state_root": if owner=="v11" {
                Some(self.v4_state.to_str().unwrap()) } else { None }
        });
        let path=self.root.join(".owner.json");
        let tmp=self.root.join(".owner.json.pending");
        fs::write(&tmp, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::set_permissions(&tmp,fs::Permissions::from_mode(0o600)).unwrap();
        OpenOptions::new().read(true).open(&tmp).unwrap().sync_all().unwrap();
        fs::rename(tmp,path).unwrap();
        File::open(&self.root).unwrap().sync_all().unwrap();
    }
    fn admit(&self, owner:&str) -> Result<AdmissionPermit> {
        acquire_from_root(&self.root,owner,
            if owner=="v4" {&self.v4_state} else {&self.v11_state})
    }
}
#[test]
fn all_mcp_mutating_tools_are_classified_for_owner_fencing() {
    use std::collections::BTreeSet;
    let server_source=include_str!("../server.rs");
    let matcher=regex::Regex::new(
        r"(?s)#\[tool\((.*?)\)\]\s*async fn\s+([a-zA-Z0-9_]+)\s*\("
    ).unwrap();
    let expected: BTreeSet<&str> = [
        "request_start","request_cancel","operation_start","operation_cancel",
        "text_editor","directory_create","file_move","text_file_write",
        "directory_move","batch_edit","extract_lines","shell","shell_start",
        "host_signal","sudo_start","search_start","search_stop",
        "process_start","process_cancel","document_write","document_edit",
        "binary_write","binary_upload","pdf_edit","worksheet_edit",
        "document_render","worksheet_recalculate","binary_patch_inode",
        "pdf_security","stream_handoff_prepare","stream_handoff_write",
        "stream_handoff_close","process_checkpoint","pty_start","pty_write",
        "pty_close","privileged_action","workdir",
    ].into_iter().collect();
    let retained: BTreeSet<&str> = [
        "request_cancel","operation_cancel","search_stop","process_cancel",
        "pty_write","pty_close","stream_handoff_write","stream_handoff_close","workdir",
    ].into_iter().collect();
    let direct_native: BTreeSet<&str> = ["process_start","pty_start"].into_iter().collect();
    let mut actual = BTreeSet::new();
    for capture in matcher.captures_iter(server_source) {
        if !capture[1].contains("read_only_hint = false") { continue; }
        let name = capture.get(2).unwrap().as_str();
        actual.insert(name);
        let end=capture.get(0).unwrap().end();
        let start=server_source[end..].find('{').unwrap()+end;
        let short=&server_source[start..server_source.len().min(start+400)];
        if retained.contains(name) {
            assert!(!short.contains("effect_owner_fence::admit_new_effect"),
                    "{name} is already-owned continuation or local session state");
        } else if !direct_native.contains(name) {
            assert!(short.contains("effect_owner_fence::admit_new_effect"),
                    "{name} lacks native new-effect owner admission");
        }
    }
    assert_eq!(actual, expected, "MCP mutation contract expanded without owner audit");
    assert_eq!(actual.difference(&retained).count(),29);
    let jobs=include_str!("jobs.rs");
    let pty=include_str!("pty.rs");
    assert!(jobs.contains("let _owner_admission = super::effect_owner_fence::admit_new_effect().await?;"));
    assert!(pty.contains("let _owner_admission = super::effect_owner_fence::admit_new_effect().await?;"));
}
#[test]
fn matching_owner_receives_epoch_bound_shared_admission() {
    let f=Fixture::new();
    let p=f.admit("v4").unwrap();
    assert_eq!(p.epoch,Some(7));
    assert!(p._locked.is_some());
    assert!(f.admit("v4").is_ok()); // concurrent readers, not double exclusive writers
}
#[test]
fn wrong_owner_or_wrong_state_root_fail_before_effect() {
    let f=Fixture::new();
    assert!(f.admit("v11").is_err());
    assert!(acquire_from_root(&f.root,"v4",&f.v11_state).is_err());
    assert!(acquire_from_root(&f.root,"shadow",&f.v4_state).is_err());
}
#[test]
fn frozen_admission_fails_closed_and_preserves_no_new_effect() {
    let f=Fixture::new();
    f.write_state("v4","frozen",7);
    assert!(f.admit("v4").is_err());
    assert!(f.admit("v11").is_err());
}
#[test]
fn owner_epoch_transition_denies_prior_owner_and_enables_successor() {
    let f=Fixture::new();
    let guard=f.admit("v4").unwrap();
    let lock=OpenOptions::new().read(true).write(true)
        .open(f.root.join(".owner.lock")).unwrap();
    // A transfer must be exclusive and cannot overlap the old admitted effect.
    assert_ne!(unsafe {libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)},0);
    drop(guard);
    assert_eq!(unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)},0);
    f.write_state("v4","frozen",7);
    assert_eq!(unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_UN)},0);
    assert!(f.admit("v4").is_err()); // frozen even before successor promotion
    assert_eq!(unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_EX)},0);
    f.write_state("v11","admitting",8);
    assert_eq!(unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_UN)},0);
    assert!(f.admit("v4").is_err());
    assert_eq!(f.admit("v11").unwrap().epoch,Some(8));
}
#[test]
fn in_flight_old_submission_blocks_exclusive_handoff_until_release() {
    let f=Fixture::new();
    let guard=f.admit("v4").unwrap();
    let lock=f.root.join(".owner.lock");
    let (tx,rx)=mpsc::channel();
    let child=thread::spawn(move||{
        let l=OpenOptions::new().read(true).write(true).open(lock).unwrap();
        let ok=unsafe{libc::flock(l.as_raw_fd(),libc::LOCK_EX)}==0;
        tx.send(ok).unwrap();
    });
    thread::sleep(Duration::from_millis(60));
    assert!(rx.try_recv().is_err()); // transition not admitted before old ends
    drop(guard);
    assert!(rx.recv_timeout(Duration::from_secs(3)).unwrap());
    child.join().unwrap();
}
#[test]
fn malformed_metadata_and_missing_files_refuse() {
    let f=Fixture::new();
    fs::write(f.root.join(".owner.json"),b"{bad").unwrap();
    assert!(f.admit("v4").is_err());
    f.write_state("v4","admitting",0);
    assert!(f.admit("v4").is_err());
    f.write_state("v4","admitting",7);
    fs::remove_file(f.root.join(".owner.json")).unwrap();
    assert!(f.admit("v4").is_err());
}
#[test]
fn symlinks_wrong_modes_and_replaced_lock_are_denied() {
    let f=Fixture::new();
    fs::set_permissions(f.root.join(".owner.json"),fs::Permissions::from_mode(0o644)).unwrap();
    assert!(f.admit("v4").is_err());
    fs::set_permissions(f.root.join(".owner.json"),fs::Permissions::from_mode(0o600)).unwrap();
    let lock=f.root.join(".owner.lock");
    fs::rename(&lock,f.root.join(".owner.lock.original")).unwrap();
    symlink(".owner.lock.original",&lock).unwrap();
    assert!(f.admit("v4").is_err());
    fs::remove_file(&lock).unwrap();
    fs::rename(f.root.join(".owner.lock.original"),lock).unwrap();
    fs::set_permissions(&f.root,fs::Permissions::from_mode(0o755)).unwrap();
    assert!(f.admit("v4").is_err());
}
#[test]
fn symlinked_ancestor_refuses_even_with_private_final_directory() {
    let f=Fixture::new();
    let via=f.temp.path().join("alias");
    symlink(&f.root,&via).unwrap();
    assert!(acquire_from_root(&via,"v4",&f.v4_state).is_err());
}
#[test]
fn unreadable_or_oversized_owner_record_refuses() {
    let f=Fixture::new();
    fs::write(f.root.join(".owner.json"),vec![b'x';MAX_OWNER_BYTES as usize+1]).unwrap();
    assert!(f.admit("v4").is_err());
}

#[test]
fn invalid_or_extra_authority_fields_and_unknown_phase_refuse() {
    let f=Fixture::new();
    let path=f.root.join(".owner.json");
    let mut value:serde_json::Value=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["bogus_unreviewed_flag"]=serde_json::json!(true);
    fs::write(&path,serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(f.admit("v4").is_err());
    f.write_state("v4","promoting_without_freeze",8);
    assert!(f.admit("v4").is_err());
}
#[test]
fn forged_authority_root_or_lock_hardlink_refuses() {
    let f=Fixture::new();
    let root=f.root.join(".owner.lock");
    let link=f.root.join(".owner.lock.second");
    std::fs::hard_link(&root,&link).unwrap();
    assert!(f.admit("v4").is_err());
    std::fs::remove_file(link).unwrap();
    assert!(f.admit("v4").is_ok());
}


#[test]
fn owner_metadata_replacement_under_open_fd_is_rejected() {
    let f = Fixture::new();
    let dir = open_root(&f.root).unwrap();
    let old = open_record(&dir, ".owner.json", false).unwrap();
    let expected = old.metadata().unwrap();
    // An uncooperative same-UID writer swaps the pathname while the old
    // read descriptor is still valid. The re-opened inode must not match.
    f.write_state("v4", "admitting", 8);
    assert!(verify_owner_record_stable(&dir, &old, &expected).is_err());
}

#[test]
fn authority_root_rebinding_is_detected() {
    let f = Fixture::new();
    let pinned = open_root(&f.root).unwrap();
    let moved = f.temp.path().join("previous-authority");
    fs::rename(&f.root, moved).unwrap();
    fs::create_dir(&f.root).unwrap();
    fs::set_permissions(&f.root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(verify_root_path_identity(&f.root, &pinned).is_err());
}

#[test]
fn owner_controller_state_root_must_exist_and_remain_private() {
    let f = Fixture::new();
    fs::set_permissions(&f.v4_state, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(f.admit("v4").is_err());
    fs::set_permissions(&f.v4_state, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(f.admit("v4").is_ok());
    fs::remove_dir(&f.v4_state).unwrap();
    assert!(f.admit("v4").is_err());
    symlink(&f.v11_state, &f.v4_state).unwrap();
    assert!(f.admit("v4").is_err());
}

#[test]
fn controller_state_root_rebinding_is_detected() {
    let f = Fixture::new();
    let pinned = open_root(&f.v4_state).unwrap();
    let moved = f.temp.path().join("previous-v4-state");
    fs::rename(&f.v4_state, moved).unwrap();
    fs::create_dir(&f.v4_state).unwrap();
    fs::set_permissions(&f.v4_state, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(verify_root_path_identity(&f.v4_state, &pinned).is_err());
}


#[test]
fn successor_replay_rejects_predecessor_host_and_key_but_allows_new_key() {
    let f=Fixture::new();
    let jobs=f.v4_state.join("jobs"); fs::create_dir(&jobs).unwrap();
    fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).unwrap();
    let record=serde_json::json!({
        "id":"1a14-cafe-1", "host":"main",
        "idempotency_key":"V4-OLD-PRIVATE-REQUEST",
        "request_digest":"a".repeat(64)});
    let entry=jobs.join("1a14-cafe-1.json");
    fs::write(&entry,serde_json::to_vec(&record).unwrap()).unwrap();
    fs::set_permissions(&entry,fs::Permissions::from_mode(0o600)).unwrap();
    f.write_state("v11","admitting",8);
    let guard=f.admit("v11").unwrap();
    assert!(guard.require_new_process_identity("main",Some("V4-OLD-PRIVATE-REQUEST")).is_err());
    assert!(guard.require_new_process_identity("main",Some("V11-NEW-REQUEST")).is_ok());
    assert!(guard.require_new_process_identity("mac",Some("V4-OLD-PRIVATE-REQUEST")).is_ok());
    assert!(guard.require_new_process_identity("main",None).is_err());
}

#[test]
fn successor_replay_denies_uncertain_or_corrupt_legacy_registry() {
    let f=Fixture::new();
    let jobs=f.v4_state.join("jobs"); fs::create_dir(&jobs).unwrap();
    fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).unwrap();
    f.write_state("v11","admitting",8);
    let guard=f.admit("v11").unwrap();
    assert!(guard.require_new_process_identity("main",Some("NEW")).is_ok());
    let uncertain=jobs.join("1a14-cafe-1.json.tmp.123");
    fs::write(&uncertain,b"").unwrap();
    fs::set_permissions(&uncertain,fs::Permissions::from_mode(0o600)).unwrap();
    assert!(guard.require_new_process_identity("main",Some("NEW")).is_err());
    fs::remove_file(&uncertain).unwrap();
    let bad=jobs.join("1a14-cafe-1.json");
    fs::write(&bad,b"{bad").unwrap();
    fs::set_permissions(&bad,fs::Permissions::from_mode(0o600)).unwrap();
    assert!(guard.require_new_process_identity("main",Some("NEW")).is_err());
}

#[test]
fn successor_without_predecessor_root_is_not_an_effect_owner() {
    let f=Fixture::new();
    let path=f.root.join(".owner.json");
    let record=serde_json::json!({
       "schema":SCHEMA, "owner":"v11", "epoch":8,
       "phase":"admitting", "state_root":f.v11_state});
    fs::write(&path,serde_json::to_vec(&record).unwrap()).unwrap();
    fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).unwrap();
    assert!(f.admit("v11").is_err());
    assert!(f.admit("v4").is_err());
}
