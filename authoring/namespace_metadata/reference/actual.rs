// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Actual Rust 1.95 std metadata reference and separately loaded native candidate.
// This is qualification-only; neither Rust nor this harness is in the native ABI.
use std::{ffi::OsString,fs::File,io::Write,mem::ManuallyDrop,os::{fd::FromRawFd,unix::{ffi::OsStringExt,fs::MetadataExt}},path::PathBuf};
unsafe extern "C" {
    fn syscall(number:isize, ...)->isize;
    fn read(fd:i32,buf:*mut u8,count:usize)->isize;
    fn write(fd:i32,buf:*const u8,count:usize)->isize;
    fn mmap(address:*mut u8,size:usize,prot:i32,flags:i32,fd:i32,offset:isize)->*mut u8;
    fn munmap(address:*mut u8,size:usize)->i32;
    fn prctl(option:i32,...)->i32;
}
#[repr(C)] struct Filter {code:u16,jt:u8,jf:u8,k:u32}
#[repr(C)] struct Program {len:u16,filter:*const Filter}
fn ins(code:u16,jt:u8,jf:u8,k:u32)->Filter {Filter{code,jt,jf,k}}
fn install(mode:u64) {
    if mode==0{return}
    let mut program=vec![ins(0x20,0,0,4),ins(0x15,1,0,0xc000003e),ins(0x06,0,0,0x80000000),ins(0x20,0,0,0)];
    let errno=|e:u32|0x50000u32|e;
    let mut statx=Vec::new();
    match mode {
        1=>statx.push(ins(0x06,0,0,errno(38))),
        2=>statx.push(ins(0x06,0,0,errno(1))),
        3=>statx.push(ins(0x06,0,0,errno(22))),
        4=>statx.push(ins(0x06,0,0,errno(14))),
        10=>statx.push(ins(0x06,0,0,errno(9))),
        5|6|9=>{
            let probe=if mode==5{0x7fff0000}else if mode==6{errno(38)}else{errno(14)};
            let real=if mode==5{errno(1)}else if mode==6{errno(14)}else{errno(38)};
            statx.extend([ins(0x20,0,0,24),ins(0x15,0,3,0),ins(0x20,0,0,28),
                ins(0x15,0,1,0),ins(0x06,0,0,probe),ins(0x06,0,0,real)]);
        }
        7|8=>statx.push(ins(0x06,0,0,errno(38))),
        _=>panic!("unknown seccomp profile")
    }
    program.push(ins(0x15,0,statx.len() as u8,332));program.extend(statx);
    if mode==7 || mode==8 {
        let error=if mode==7{1}else{5};
        for number in [5,262] {program.push(ins(0x15,0,1,number));program.push(ins(0x06,0,0,errno(error)));}
    }
    program.push(ins(0x06,0,0,0x7fff0000));
    let filter=Program{len:program.len() as u16,filter:program.as_ptr()};
    unsafe{assert_eq!(prctl(38,1u64,0u64,0u64,0u64),0);assert_eq!(prctl(22,2u64,&filter as *const Program,0u64,0u64),0);}
}
fn word(data:&[u8],at:usize)->u64 {u64::from_le_bytes(data[at..at+8].try_into().unwrap())}
fn put(data:&mut [u8],at:usize,value:u64){data[at..at+8].copy_from_slice(&value.to_le_bytes())}
fn reference(req:&[u8],out:&mut [u8])->u64 {
    let cmd=word(req,8);let descriptor=word(req,16) as i32;
    let result=if cmd==1 {let borrowed=ManuallyDrop::new(unsafe{File::from_raw_fd(descriptor)});borrowed.metadata()}
        else{std::fs::metadata(PathBuf::from(OsString::from_vec(req[96..].to_vec())))};
    out[..32].fill(0);out[..8].copy_from_slice(b"HNSMR001");
    match result {
        Ok(m)=>{
            put(out,24,144);out[32..176].fill(0);
            put(out,32,m.dev());put(out,40,m.ino());put(out,48,m.nlink());
            out[56..60].copy_from_slice(&m.mode().to_le_bytes());
            out[60..64].copy_from_slice(&m.uid().to_le_bytes());
            out[64..68].copy_from_slice(&m.gid().to_le_bytes());
            for (at,value) in [(72,m.rdev()),(80,m.size()),(88,m.blksize()),(96,m.blocks()),
                (104,m.atime() as u64),(112,m.atime_nsec() as u64),(120,m.mtime() as u64),
                (128,m.mtime_nsec() as u64),(136,m.ctime() as u64),(144,m.ctime_nsec() as u64)]{put(out,at,value)}
        }
        Err(error)=>if let Some(code)=error.raw_os_error(){put(out,8,1);put(out,16,code as u64)}
            else{assert_eq!(cmd,2);assert!(req[96..].contains(&0));assert_eq!(error.kind(),std::io::ErrorKind::InvalidInput);put(out,8,2)}
    }
    32
}
type Entry=unsafe extern "C" fn(*const u8,u64,*mut u8,u64,*mut u8,u64)->u64;
fn invoke(entry:Option<Entry>,request:&[u8],cache:&mut [u8;33])->Vec<u8> {
    let mut input=vec![0xa5;request.len()+32];input[16..16+request.len()].copy_from_slice(request);
    let mut output=vec![0xb6;288];
    let code=if let Some(call)=entry{unsafe{call(input.as_ptr().add(16),request.len() as u64,
        output.as_mut_ptr().add(16),256,cache.as_mut_ptr().add(16),1)}}
        else{reference(&input[16..16+request.len()],&mut output[16..272])};
    let input_ok=input[..16]==[0xa5;16] && input[16..16+request.len()]==*request && input[16+request.len()..]==[0xa5;16];
    let output_ok=output[..16]==[0xb6;16] && output[272..]==[0xb6;16];
    let cache_ok=cache[..16]==[0xcc;16] && cache[17..]==[0xcc;16];
    let mut record=Vec::with_capacity(288);
    record.extend_from_slice(&code.to_le_bytes());
    record.extend_from_slice(&(if entry.is_some(){cache[16] as u64}else{255}).to_le_bytes());
    record.extend_from_slice(&((input_ok as u64)|((output_ok as u64)<<1)|((cache_ok as u64)<<2)).to_le_bytes());
    record.extend_from_slice(&(32+word(&output[16..272],24)).to_le_bytes());
    record.extend_from_slice(&output[16..272]);record
}
fn main(){
    let args=std::env::args().collect::<Vec<_>>();assert_eq!(args.len(),3);
    let mut data=Vec::new();let mut chunk=[0u8;8192];
    loop{let n=unsafe{read(0,chunk.as_mut_ptr(),chunk.len())};assert!(n>=0);if n==0{break}data.extend_from_slice(&chunk[..n as usize]);}
    assert_eq!(&data[..8],b"HMTST001");
    let filter=word(&data,8);let warm=word(&data,16);let count=word(&data,24);let mut at=32;let mut requests=Vec::new();
    for _ in 0..count{let n=word(&data,at) as usize;at+=8;requests.push(data[at..at+n].to_vec());at+=n;}
    assert_eq!(at,data.len());assert!(!requests.is_empty());
    let mut mapping=std::ptr::null_mut();let mut image_size=0;
    let entry=if args[1]=="native" {
        let image=std::fs::read(&args[2]).unwrap();image_size=image.len();
        let fd=unsafe{syscall(319,b"hia-metadata-reference\0".as_ptr(),3u32)} as i32;assert!(fd>=0);
        let mut offset=0;while offset<image.len(){let n=unsafe{write(fd,image[offset..].as_ptr(),image.len()-offset)};assert!(n>0);offset+=n as usize;}
        assert_eq!(unsafe{syscall(72,fd,1033,15)},0);
        mapping=unsafe{mmap(std::ptr::null_mut(),image.len(),5,2,fd,0)};assert_ne!(mapping as isize,-1);
        assert_eq!(unsafe{syscall(3,fd)},0);
        Some(unsafe{std::mem::transmute::<*mut u8,Entry>(mapping)})
    } else{assert_eq!(args[1],"reference");None};
    let mut cache=[0xccu8;33];cache[16]=0;
    // Invalid-FD write markers cannot mutate a file; the tracer brackets only this exact call sequence.
    unsafe{syscall(1,-1i32,cache.as_ptr().add(16),8usize);}
    if warm!=0{let first=invoke(entry,&requests[0],&mut cache);assert_eq!(word(&first,0),32);assert_eq!(word(&first,40),0);}
    install(filter);
    let mut result=b"HMTRS001".to_vec();result.extend_from_slice(&count.to_le_bytes());
    for request in &requests{result.extend_from_slice(&invoke(entry,request,&mut cache));}
    unsafe{syscall(1,-2i32,cache.as_ptr().add(16),8usize);}
    std::io::stdout().write_all(&result).unwrap();
    if !mapping.is_null(){assert_eq!(unsafe{munmap(mapping,image_size)},0);}
}
