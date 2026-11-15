use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
@@MAX_TEXT_INPUT@@
@@PUBLISHED@@
@@LINUX@@

fn integer(raw:&[u8],at:usize)->u64 {u64::from_le_bytes(raw[at..at+8].try_into().unwrap())}
fn marker(case_id:u64,end:bool) {
    let value=900_000_000_i64+(case_id as i64)*2+i64::from(end);
    unsafe { libc::syscall(libc::SYS_getpgid,value); }
}
fn main()->anyhow::Result<()> {
    let mut input=std::io::stdin().lock();
    let mut output=std::io::stdout().lock();
    loop {
        let mut length=[0u8;8];
        match input.read(&mut length[..1])? {0=>break,1=>{},_=>unreachable!()}
        input.read_exact(&mut length[1..])?;
        let length=u64::from_le_bytes(length);
        let mut frame=vec![0u8;usize::try_from(length)?];input.read_exact(&mut frame)?;
        anyhow::ensure!(frame.len()>=32 && &frame[..8]==b"HTXPI001","carrier header");
        let id=integer(&frame,8);let size=usize::try_from(integer(&frame,16))?;
        anyhow::ensure!(integer(&frame,24)==0 && size==frame.len()-32,"carrier extent");
        let wire=&frame[32..];
        anyhow::ensure!(wire.len()>=64 && &wire[..8]==b"HTXTQ001","publication header");
        let op=integer(wire,8);let mode=integer(wire,16);
        let pn=usize::try_from(integer(wire,24))?;let tn=usize::try_from(integer(wire,32))?;
        let en=usize::try_from(integer(wire,40))?;
        anyhow::ensure!(op==1 && (1..=3).contains(&mode) && integer(wire,48)==0 && integer(wire,56)==0,"already admitted command");
        anyhow::ensure!(64usize.checked_add(pn).and_then(|v|v.checked_add(en)).and_then(|v|v.checked_add(tn))==Some(wire.len()),"complete admitted spans");
        let path=Path::new(std::ffi::OsStr::from_bytes(&wire[64..64+pn]));
        let expected=std::str::from_utf8(&wire[64+pn..64+pn+en])?;
        let text=std::str::from_utf8(&wire[64+pn+en..])?;
        anyhow::ensure!(text.len()<=MAX_TEXT_INPUT,"admitted input size");
        anyhow::ensure!(if mode==1 {expected=="absent"} else {expected.len()==64 && expected.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))},"admitted expected digest");
        let mode=match mode {1=>"create",2=>"replace",3=>"append",_=>unreachable!()};
        marker(id,false);
        let actual=linux::publish(path,mode,expected,text);
        marker(id,true);
        let value=match actual {
            Ok(published)=>serde_json::json!({"case_id":id,"ok":true,"bytes":published.bytes,
                "sha256":published.sha256,"version":published.version,"was_new_file":published.was_new_file}),
            Err(error)=>serde_json::json!({"case_id":id,"ok":false,"short":error.to_string(),
                "chain":format!("{error:#}"),"errno":error.downcast_ref::<std::io::Error>().and_then(|e|e.raw_os_error())}),
        };
        let payload=serde_json::to_vec(&value)?;
        let mut record=b"HTXPO001".to_vec();record.extend(id.to_le_bytes());
        record.extend((payload.len() as u64).to_le_bytes());record.extend(payload);
        output.write_all(&(record.len() as u64).to_le_bytes())?;output.write_all(&record)?;output.flush()?;
    }
    Ok(())
}
