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
//! Real descriptor placement and Linux seccomp errors, outside the unchanged original.
use anyhow::{bail,ensure,Result};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::FromRawFd;
pub const ROOT_FD:i32=96;
pub const STREAM_FD:i32=80;
pub fn reserve()->Result<serde_json::Value>{
    for fd in [STREAM_FD,ROOT_FD]{
        ensure!(unsafe{libc::fcntl(fd,libc::F_GETFD)}==-1 &&
            std::io::Error::last_os_error().raw_os_error()==Some(libc::EBADF),"reserved FD already occupied");
    }
    let base=unsafe{libc::open(c"/dev/null".as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC)};
    ensure!(base>=0,"owned reserve open");
    let mut held=Vec::new();
    for fd in 3..128{
        if fd==ROOT_FD || fd==STREAM_FD{continue;}
        if unsafe{libc::fcntl(fd,libc::F_GETFD)}<0{
            ensure!(std::io::Error::last_os_error().raw_os_error()==Some(libc::EBADF),"descriptor hole");
            ensure!(unsafe{libc::dup2(base,fd)}==fd,"owned reserve dup2");
            ensure!(unsafe{libc::fcntl(fd,libc::F_SETFD,libc::FD_CLOEXEC)}==0,"owned reserve cloexec");
            held.push(fd);
        }
    }
    Ok(serde_json::json!({"base":base,"held":held,"root_fd":ROOT_FD,"stream_fd":STREAM_FD}))
}
pub fn open_root(path:&[u8])->Result<File>{
    let path=CString::new(path)?;
    let fd=unsafe{libc::open(path.as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC)};
    ensure!(fd==STREAM_FD,"actual next owned root open");
    ensure!(unsafe{libc::dup2(fd,ROOT_FD)}==ROOT_FD,"borrowed root placement");
    ensure!(unsafe{libc::fcntl(ROOT_FD,libc::F_SETFD,libc::FD_CLOEXEC)}==0,"root cloexec");
    ensure!(unsafe{libc::close(fd)}==0,"release temporary root FD");
    Ok(unsafe{File::from_raw_fd(ROOT_FD)})
}
pub fn install(group:&str)->Result<serde_json::Value>{
    let pairs:&[(u32,Option<(u32,u32)>,u32)]=match group{
        "ordinary"|"names"|"wide"=>&[],
        "open-eacces"=>&[(257,Some((0,ROOT_FD as u32)),13)],
        "fdopendir-eperm"=>&[(72,Some((1,3)),1)],
        "readdir-eio"=>&[(217,None,5)],
        "readdir-eintr"=>&[(217,None,4)],
        "closedir-eio"=>&[(3,Some((0,STREAM_FD as u32)),5)],
        "fdopendir-eperm-close-eio"=>&[(72,Some((1,3)),1),(3,Some((0,STREAM_FD as u32)),5)],
        "readdir-eio-close-eacces"=>&[(217,None,5),(3,Some((0,STREAM_FD as u32)),13)],
        _=>bail!("unknown actual kernel environment"),
    };
    let mut descriptions:Vec<(u16,u8,u8,u32)>=vec![
        (0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),(0x20,0,0,0)];
    for &(number,argument,error) in pairs{
        match argument{
            None=>descriptions.extend([(0x15,0,1,number),(0x06,0,0,0x50000|error)]),
            Some((index,value))=>descriptions.extend([
                (0x15,0,4,number),(0x20,0,0,16+index*8),
                (0x15,0,1,value),(0x06,0,0,0x50000|error),(0x20,0,0,0)]),
        }
    }
    descriptions.push((0x06,0,0,0x7fff0000));
    if !pairs.is_empty(){
        let mut rows=descriptions.iter().map(|&(code,jt,jf,k)|libc::sock_filter{code,jt,jf,k}).collect::<Vec<_>>();
        let program=libc::sock_fprog{len:rows.len().try_into()?,filter:rows.as_mut_ptr()};
        ensure!(unsafe{libc::prctl(38,1,0,0,0)}==0,"actual NO_NEW_PRIVS");
        ensure!(unsafe{libc::prctl(22,2,&program,0,0)}==0,"actual SECCOMP");
    }
    Ok(serde_json::json!({"group":group,"installed":!pairs.is_empty(),"filters":descriptions}))
}
