// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Test-only transport: all semantic operations above are original Rust bodies.
pub fn evaluate_diff(raw: &str, rows: Vec<(usize, u64, usize, usize, String)>, plan: &[u8]) -> Vec<u8> {
    let original = EditableContent::from_raw(raw);
    let original_normalized = original.normalized();
    let operations: Vec<BatchOperation> = rows.into_iter().map(|(index,kind,start,end,content)| BatchOperation {
        operation_type: if kind==1 { OperationType::Insert } else { OperationType::Replace },
        line_range: if kind==1 { LineRange::Single(start) } else { LineRange::Range(start,end) },
        content, operation_index:index,
    }).collect();
    let result=crate::ready(checked_apply(&original,operations.clone()));
    let (status, normalized, rendered, diff, error) = match result {
        Ok(edited) => {
            let normalized=edited.normalized();
            let diff=render_diff(&original_normalized,&normalized,operations).unwrap();
            (0u64,normalized,edited.rendered(),diff,String::new())
        },
        Err(error) => (1u64,String::new(),String::new(),String::new(),error),
    };
    let mut response=b"HBDICO01".to_vec();
    for value in [status,original_normalized.len() as u64,normalized.len() as u64,rendered.len() as u64,plan.len() as u64,diff.len() as u64,error.len() as u64,0] {
        response.extend_from_slice(&value.to_le_bytes());
    }
    for value in [original_normalized.as_bytes(),normalized.as_bytes(),rendered.as_bytes(),plan,diff.as_bytes(),error.as_bytes()] {
        response.extend_from_slice(value);
    }
    response
}
}

struct NoWake;
impl std::task::Wake for NoWake { fn wake(self: std::sync::Arc<Self>) {} }
fn ready<T>(future: impl std::future::Future<Output=T>) -> T {
    let waker=std::task::Waker::from(std::sync::Arc::new(NoWake));
    let mut context=std::task::Context::from_waker(&waker);
    match std::pin::pin!(future).as_mut().poll(&mut context) {
        std::task::Poll::Ready(result)=>result,
        std::task::Poll::Pending=>panic!("pure original unexpectedly suspended"),
    }
}
fn word(raw:&[u8],at:usize)->u64 { u64::from_le_bytes(raw[at..at+8].try_into().unwrap()) }
fn evaluate(raw:&[u8])->Vec<u8> {
    assert!(raw.len()>=112);
    assert_eq!(&raw[..8],b"HBACT001");
    assert_eq!(word(raw,8),2);
    for at in [32,40,48,56] { assert_eq!(word(raw,at),0); }
    let size=word(raw,16) as usize;
    let text=std::str::from_utf8(&raw[64..64+size]).unwrap();
    let plan=&raw[64+size..];
    assert_eq!(word(raw,24) as usize,plan.len());
    assert_eq!(&plan[..8],b"HBPLR001");
    assert_eq!(word(plan,8),0);
    let count=word(plan,16) as usize;
    assert!((1..=50).contains(&count));
    assert_eq!(word(plan,24) as usize,plan.len()-48);
    assert_eq!(word(plan,32),0);assert_eq!(word(plan,40),0);
    let mut rows=Vec::new();let mut at=48;
    for ordinal in 0..count {
        assert_eq!(word(plan,at) as usize,ordinal);
        let kind=word(plan,at+8);assert!(kind==1 || kind==2);assert_eq!(word(plan,at+16),kind);
        let start=word(plan,at+24) as usize;let end=word(plan,at+32) as usize;
        let size=word(plan,at+40) as usize;at+=48;
        let content=std::str::from_utf8(&plan[at..at+size]).unwrap().to_owned();at+=size;
        rows.push((ordinal,kind,start,end,content));
    }
    assert_eq!(at,plan.len());
    original::evaluate_diff(text,rows,plan)
}
fn main()->io::Result<()> {
    let mut input=io::BufReader::new(io::stdin().lock());
    let mut output=io::BufWriter::new(io::stdout().lock());
    let mut tag=[0;8];input.read_exact(&mut tag)?;assert_eq!(&tag,b"HBDIQ001");
    output.write_all(b"HBDIO001")?;
    let mut cases=0u64;let mut succeeded=0u64;let mut bytes=0u64;
    loop {
        let mut size=[0;8];if input.read(&mut size[..1])?==0 { break; }
        input.read_exact(&mut size[1..])?;
        let size=u64::from_le_bytes(size) as usize;assert!(size>=112);
        let mut raw=vec![0;size];input.read_exact(&mut raw)?;
        let result=evaluate(&raw);
        if word(&result,8)==0 { succeeded+=1; }
        output.write_all(&(result.len() as u64).to_le_bytes())?;output.write_all(&result)?;
        bytes+=result.len() as u64;cases+=1;
    }
    output.flush()?;
    eprintln!("{{\"status\":\"PASS\",\"original_cases\":{cases},\"successful_diff_cases\":{succeeded},\"output_body_bytes\":{bytes}}}");
    Ok(())
}

