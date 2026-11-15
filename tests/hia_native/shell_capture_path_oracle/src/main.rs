// Typed test transport only. Original statement projections live in projection.
use std::io::{self, Read, Write};
mod projection;

fn word(raw: &[u8], offset: usize) -> Result<u64, String> {
    let part = raw.get(offset..offset + 8).ok_or("missing request word")?;
    Ok(u64::from_le_bytes(part.try_into().map_err(|_| "request word size")?))
}

fn render(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() < 64 || &raw[..8] != b"HSHCPQ01" {
        return Err("request header differs".into());
    }
    let op = word(raw, 8)?;
    let present = word(raw, 16)?;
    let pid = word(raw, 24)?;
    let seq = word(raw, 32)?;
    let first_len = usize::try_from(word(raw, 40)?).map_err(|_| "first extent overflow")?;
    let second_len = usize::try_from(word(raw, 48)?).map_err(|_| "second extent overflow")?;
    let split = 64usize.checked_add(first_len).ok_or("first extent overflow")?;
    if split.checked_add(second_len) != Some(raw.len()) || word(raw, 56)? != 0 {
        return Err("request extent or reserved word differs".into());
    }
    match op {
        1 if present == 0 && pid == 0 && seq == 0 => (),
        2 if present == 0 && pid == 0 && seq == 0 && second_len == 0 => (),
        3 if present <= 1 && pid <= u32::MAX as u64 && second_len == 0
            && (present == 1 || first_len == 0) => (),
        _ => return Err("request operation or typed carrier differs".into()),
    }
    let (flag, next_seq, fields) = projection::project(
        op, &raw[64..split], &raw[split..], present == 1, pid as u32, seq);
    let extent = fields.iter().try_fold(80usize, |size, field| size.checked_add(field.len()))
        .ok_or("response extent overflow")?;
    let mut out = Vec::with_capacity(extent);
    out.extend_from_slice(b"HSHCPR01");
    for value in [op, extent as u64, flag, next_seq, fields[0].len() as u64,
                  fields[1].len() as u64, fields[2].len() as u64, fields[3].len() as u64, 0] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for field in fields {
        out.extend_from_slice(&field);
    }
    Ok(out)
}

fn run() -> Result<(), String> {
    if std::env::args_os().len() != 1 {
        return Err("no command-line arguments accepted".into());
    }
    let mut input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    loop {
        let mut size = [0u8; 8];
        match input.read(&mut size[..1]).map_err(|e| e.to_string())? {
            0 => break,
            1 => (),
            _ => unreachable!(),
        }
        input.read_exact(&mut size[1..]).map_err(|e| e.to_string())?;
        let size = usize::try_from(u64::from_le_bytes(size)).map_err(|_| "packet extent overflow")?;
        let mut raw = vec![0u8; size];
        input.read_exact(&mut raw).map_err(|e| e.to_string())?;
        let body = render(&raw)?;
        output.write_all(&80u64.to_le_bytes()).map_err(|e| e.to_string())?;
        output.write_all(&(body.len() as u64).to_le_bytes()).map_err(|e| e.to_string())?;
        output.write_all(&body).map_err(|e| e.to_string())?;
    }
    output.flush().map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("capture-path original projection: {error}");
        std::process::exit(2);
    }
}
