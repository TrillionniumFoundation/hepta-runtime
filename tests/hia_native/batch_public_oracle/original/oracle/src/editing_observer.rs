
// Additive lock observer. A successful try_lock is immediately released; it is
// never retained across an operation, await, event or fixture mutation.
pub fn observe_file_locks() -> serde_json::Value {
    let Some(store)=FILE_LOCKS.get() else { return serde_json::json!({"initialized":false,"poisoned":false,"entries":{}}); };
    let (poisoned,locks)=match store.lock(){Ok(x)=>(false,x),Err(e)=>(true,e.into_inner())};
    let rows:std::collections::BTreeMap<_,_>=locks.iter().map(|(key,lock)|{
        let available=lock.try_lock().is_ok();
        (key.clone(),serde_json::json!({"available":available,"strong_count":Arc::strong_count(lock)}))
    }).collect();
    serde_json::json!({"initialized":true,"poisoned":poisoned,"entries":rows})
}
