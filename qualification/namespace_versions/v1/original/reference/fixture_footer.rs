
// Copyright 2026 Muvon Un Limited
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
// Test accessors appended after the complete byte-identical original module.
// All namespace/Watcher/fingerprint/set decisions above execute unchanged.
type FixtureGlobal=std::sync::OnceLock<std::sync::Mutex<Option<Watcher>>>;
fn fixture_global(kind:&str)->&'static FixtureGlobal{
    let p=crate::fixture_elf::address(kind,std::mem::size_of::<FixtureGlobal>(),std::mem::align_of::<FixtureGlobal>());
    unsafe{&*(p as*const FixtureGlobal)}
}
fn fixture_next()->&'static std::sync::atomic::AtomicU64{
    let p=crate::fixture_elf::address("next",std::mem::size_of::<std::sync::atomic::AtomicU64>(),std::mem::align_of::<std::sync::atomic::AtomicU64>());
    unsafe{&*(p as*const std::sync::atomic::AtomicU64)}
}
fn fixture_watcher(w:&Watcher)->serde_json::Value{
    use serde_json::json;
    json!({"event_fd":w.events.as_raw_fd(),"next":w.next,"limit":w.limit,"content":w.content,
        "watches":w.watches.iter().map(|v|json!({"device":v.identity.0,"inode":v.identity.1,
            "wd":v.wd,"id":v.id,"generation":v.generation,"dead":v.dead,"pin_fd":v._pin.as_raw_fd(),
            "strong_count":std::sync::Arc::strong_count(&v._pin)})).collect::<Vec<_>>()})
}
pub(super) fn fixture_snapshot(sets:&std::collections::BTreeMap<u64,std::sync::Arc<ContentWatchSet>>)->serde_json::Value{
    use serde_json::json;
    let globals=["ordinary","content"].into_iter().map(|kind|{
        match fixture_global(kind).get(){
            None=>json!({"kind":kind,"initialized":false,"poison":false,"watcher":null}),
            Some(m)=>{
                let poisoned=m.is_poisoned();let state=m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                json!({"kind":kind,"initialized":true,"poison":poisoned,"watcher":state.as_ref().map(fixture_watcher)})
            }
        }
    }).collect::<Vec<_>>();
    let scopes=sets.iter().map(|(sid,set)|{
        let poisoned=set.state.is_poisoned();let state=set.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        json!({"sid":sid,"id":set.id,"poison":poisoned,"invalid":state.invalid,"watcher":fixture_watcher(&state.watcher)})
    }).collect::<Vec<_>>();
    json!({"globals":globals,"sets":scopes,"next":fixture_next().load(std::sync::atomic::Ordering::Relaxed)})
}
pub(super) fn fixture_watched(directory:&File)->Result<Version>{watched_version(directory)}
pub(super) fn fixture_seed_next(value:u64){
    fixture_next().store(value,std::sync::atomic::Ordering::Relaxed);
}
pub(super) fn fixture_seed_watcher(kind:&str,set:Option<&ContentWatchSet>,value:u64){
    if let Some(set)=set{
        set.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).watcher.next=value;
    }else{
        fixture_global(kind).get().expect("initialized real global").lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner).as_mut().expect("real watcher").next=value;
    }
}
pub(super) fn fixture_changed_set(set:&ContentWatchSet,wd:i32,mask:u32)->Result<()>{
    set.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).watcher.changed(wd,mask)
}
pub(super) fn fixture_poison(kind:&str,set:Option<&ContentWatchSet>)->bool{
    let outcome=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
        if let Some(set)=set{
            let _real_guard=set.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("qualification actual held set mutex unwind");
        }else{
            let _real_guard=fixture_global(kind).get().expect("initialized real global").lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("qualification actual held global mutex unwind");
        }
    }));
    assert!(outcome.is_err(),"actual original panic caught");
    if let Some(set)=set{set.state.is_poisoned()}else{fixture_global(kind).get().unwrap().is_poisoned()}
}
#[used]
#[no_mangle]
pub static NAMESPACE_VERSIONS_FIXTURE_TYPES:[usize;8]=[
    std::mem::size_of::<FixtureGlobal>(),std::mem::align_of::<FixtureGlobal>(),
    std::mem::size_of::<std::sync::atomic::AtomicU64>(),std::mem::align_of::<std::sync::atomic::AtomicU64>(),
    std::mem::size_of::<ContentWatchState>(),std::mem::align_of::<ContentWatchState>(),
    std::mem::size_of::<ContentWatchSet>(),std::mem::align_of::<ContentWatchSet>()];
pub(super) fn fixture_real_bindings()->serde_json::Value{
    serde_json::json!({"all_actual_type_words":NAMESPACE_VERSIONS_FIXTURE_TYPES,"global_bytes":std::mem::size_of::<FixtureGlobal>(),"global_alignment":std::mem::align_of::<FixtureGlobal>(),
        "atomic_bytes":std::mem::size_of::<std::sync::atomic::AtomicU64>(),"atomic_alignment":std::mem::align_of::<std::sync::atomic::AtomicU64>()})
}
