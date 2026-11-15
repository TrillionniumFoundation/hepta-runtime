//! Additive observing boundary around the actual pinned Tokio implementation.
//! Every operation delegates exactly once and returns the exact received Result.
pub use ::tokio::{sync, task, time};
pub mod fs {
    use std::path::Path;
    use serde_json::json;
    use crate::observe;
    pub async fn read_to_string(path:impl AsRef<Path>)->std::io::Result<String>{
        let path=path.as_ref();observe::event("tokio_read_enter",json!({"path_blob":observe::path_blob(path)}));
        let result=::tokio::fs::read_to_string(path).await;
        observe::event("tokio_read_exit",match &result{Ok(body)=>json!({"ok":true,"body_blob":observe::blob(body.as_bytes())}),Err(e)=>observe::io_error(e)});result
    }
    pub async fn read(path:impl AsRef<Path>)->std::io::Result<Vec<u8>>{
        let path=path.as_ref();observe::event("tokio_read_bytes_enter",json!({"path_blob":observe::path_blob(path)}));
        let result=::tokio::fs::read(path).await;
        observe::event("tokio_read_bytes_exit",match &result{Ok(body)=>json!({"ok":true,"body_blob":observe::blob(body)}),Err(e)=>observe::io_error(e)});result
    }
    pub async fn metadata(path:impl AsRef<Path>)->std::io::Result<std::fs::Metadata>{
        let path=path.as_ref();observe::event("tokio_metadata_enter",json!({"path_blob":observe::path_blob(path)}));
        let result=::tokio::fs::metadata(path).await;
        observe::event("tokio_metadata_exit",match &result{Ok(meta)=>json!({"ok":true,"metadata":observe::metadata(meta)}),Err(e)=>observe::io_error(e)});
        observe::after("atomic_metadata");result
    }
    pub async fn write(path:impl AsRef<Path>,bytes:impl AsRef<[u8]>)->std::io::Result<()>{
        let path=path.as_ref();let bytes=bytes.as_ref();
        observe::event("tokio_write_enter",json!({"path_blob":observe::path_blob(path),"body_blob":observe::blob(bytes)}));
        let result=::tokio::fs::write(path,bytes).await;
        observe::event("tokio_write_exit",observe::io_unit(&result));observe::after("atomic_write");result
    }
    pub async fn set_permissions(path:impl AsRef<Path>,perms:std::fs::Permissions)->std::io::Result<()>{
        use std::os::unix::fs::PermissionsExt;
        let path=path.as_ref();observe::event("tokio_set_permissions_enter",json!({"path_blob":observe::path_blob(path),"mode":perms.mode()}));
        let result=::tokio::fs::set_permissions(path,perms).await;
        observe::event("tokio_set_permissions_exit",observe::io_unit(&result));observe::after("atomic_permissions");result
    }
    pub async fn rename(from:impl AsRef<Path>,to:impl AsRef<Path>)->std::io::Result<()>{
        let from=from.as_ref();let to=to.as_ref();observe::event("tokio_rename_enter",json!({"from_blob":observe::path_blob(from),"to_blob":observe::path_blob(to)}));
        let result=::tokio::fs::rename(from,to).await;
        observe::event("tokio_rename_exit",observe::io_unit(&result));observe::after("atomic_rename");result
    }
    pub async fn remove_file(path:impl AsRef<Path>)->std::io::Result<()>{
        let path=path.as_ref();observe::event("tokio_remove_enter",json!({"path_blob":observe::path_blob(path)}));
        let result=::tokio::fs::remove_file(path).await;
        observe::event("tokio_remove_exit",observe::io_unit(&result));result
    }
    pub async fn create_dir_all(path:impl AsRef<Path>)->std::io::Result<()>{
        let path=path.as_ref();observe::event("tokio_mkdir_enter",json!({"path_blob":observe::path_blob(path)}));
        let result=::tokio::fs::create_dir_all(path).await;
        observe::event("tokio_mkdir_exit",observe::io_unit(&result));result
    }
    pub async fn canonicalize(path:impl AsRef<Path>)->std::io::Result<std::path::PathBuf>{
        let path=path.as_ref();observe::event("tokio_canonicalize_enter",json!({"path_blob":observe::path_blob(path)}));
        let result=::tokio::fs::canonicalize(path).await;
        observe::event("tokio_canonicalize_exit",match &result{Ok(path)=>json!({"ok":true,"path_blob":observe::path_blob(path)}),Err(e)=>observe::io_error(e)});result
    }
}
