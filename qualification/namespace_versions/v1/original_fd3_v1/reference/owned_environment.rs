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
//! Test-owned real descriptor and RLIMIT placement outside the original Watcher.
use anyhow::{ensure,Result};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::FromRawFd;
pub const ROOT_FIRST:i32=512;
pub fn absent(fd:i32)->bool{
    (unsafe{libc::fcntl(fd,libc::F_GETFD)})==-1 &&
        std::io::Error::last_os_error().raw_os_error()==Some(libc::EBADF)
}
pub fn reserve()->Result<serde_json::Value>{
    for fd in (32..320).chain(512..772){ensure!(absent(fd),"owned pool/root FD already occupied");}
    let base=unsafe{libc::open(c"/dev/null".as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC)};
    ensure!((3..32).contains(&base),"owned reservation stays outside kernel pool");
    let mut held=Vec::new();
    for fd in 3..32 {
        if absent(fd){
            ensure!(unsafe{libc::dup2(base,fd)}==fd,"actual reserve dup2");
            ensure!(unsafe{libc::fcntl(fd,libc::F_SETFD,libc::FD_CLOEXEC)}==0,"actual reserve cloexec");
            held.push(fd);
        }
    }
    Ok(serde_json::json!({"pool_first":32,"pool_end":320,"root_first":512,"root_end":772}))
}
pub fn open_root(path:&[u8],index:usize)->Result<File>{
    ensure!(index<260,"bounded owned root index");
    let destination=ROOT_FIRST+i32::try_from(index)?;
    ensure!(absent(destination),"owned root must not replace existing descriptor");
    let name=CString::new(path)?;
    let fd=unsafe{libc::open(name.as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC)};
    ensure!((32..320).contains(&fd),"actual transient root uses admitted empty pool");
    if unsafe{libc::dup2(fd,destination)}!=destination{
        unsafe{libc::close(fd)};anyhow::bail!("actual owned root duplication");
    }
    ensure!(unsafe{libc::fcntl(destination,libc::F_SETFD,libc::FD_CLOEXEC)}==0,"root cloexec");
    ensure!(unsafe{libc::close(fd)}==0,"actual transient root closed");
    Ok(unsafe{File::from_raw_fd(destination)})
}
pub fn limit()->Result<libc::rlimit>{
    let mut value=libc::rlimit{rlim_cur:0,rlim_max:0};
    ensure!(unsafe{libc::getrlimit(libc::RLIMIT_NOFILE,&mut value)}==0,"actual getrlimit");Ok(value)
}
pub fn set_limit(soft:u64,maximum:u64)->Result<()>{
    let value=libc::rlimit{rlim_cur:soft,rlim_max:maximum};
    ensure!(unsafe{libc::setrlimit(libc::RLIMIT_NOFILE,&value)}==0,"actual setrlimit");Ok(())
}
pub fn clear()->Result<()>{
    for fd in (32..320).chain(512..772){ensure!(absent(fd),"all case-owned descriptors actually closed");}
    Ok(())
}
