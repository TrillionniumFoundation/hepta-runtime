
// Additive observer. Clone the actual map; never synthesize a cache result.
pub fn observe_cache(cache: &ViewCache) -> (bool,std::collections::BTreeMap<String,String>) {
    match cache.entries.lock() {
        Ok(entries)=>(false,entries.iter().map(|(key,value)|(key.clone(),value.clone())).collect()),
        Err(error)=>(true,error.into_inner().iter().map(|(key,value)|(key.clone(),value.clone())).collect()),
    }
}
