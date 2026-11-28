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
//! Real kernel error environments outside all unchanged target functions.
use anyhow::{bail,Result};
pub fn install(group:&str)->Result<()>{
    let pairs:&[(u32,u32)]=match group{
        "normal"=>&[],
        "enosys"=>&[(318,38)],
        "eperm"=>&[(318,1)],
        "entropy-eio"=>&[(318,5)],
        "fsync-eio"=>&[(74,5)],
        "link-eacces"=>&[(265,13)],
        "unlink-eacces"=>&[(263,13)],
        "enosys-unlink-eacces"=>&[(318,38),(263,13)],
        "eperm-fsync-eio"=>&[(318,1),(74,5)],
        _=>bail!("unknown owned environment"),
    };
    if pairs.is_empty(){return Ok(());}
    let make=|code,jt,jf,k|libc::sock_filter{code,jt,jf,k};
    let mut rows=vec![make(0x20,0,0,4),make(0x15,1,0,0xc000003e),
                      make(0x06,0,0,0x80000000),make(0x20,0,0,0)];
    for &(number,errno) in pairs{rows.push(make(0x15,0,1,number));rows.push(make(0x06,0,0,0x50000|errno));}
    rows.push(make(0x06,0,0,0x7fff0000));
    let program=libc::sock_fprog{len:rows.len().try_into()?,filter:rows.as_mut_ptr()};
    if unsafe{libc::prctl(38,1,0,0,0)}!=0 || unsafe{libc::prctl(22,2,&program,0,0)}!=0{
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
