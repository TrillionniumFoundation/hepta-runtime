// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Actual persistent descriptor observer around unchanged target PinnedAnchor.
use anyhow::{anyhow, bail, Result};
use std::io::{Read, Write};
use std::path::PathBuf;
mod target;
fn main() -> Result<()> {
    let root=PathBuf::from(std::env::args_os().nth(1).ok_or_else(||anyhow!("fixture root"))?);
    let mut input=std::io::stdin().lock();
    let mut output=std::io::stdout().lock();
    let mut current:Option<(u64,target::State)>=None;
    loop {
        let mut header=[0_u8;16];
        if input.read(&mut header[..1])?==0 {break;}
        input.read_exact(&mut header[1..])?;
        let case=u64::from_le_bytes(header[..8].try_into()?);
        let size=u64::from_le_bytes(header[8..].try_into()?);
        if case>=10000 || size!=128 {bail!("fixture case/extent");}
        let mut request=[0_u8;128];input.read_exact(&mut request)?;
        if current.as_ref().map(|x|x.0)!=Some(case) {
            current=None;
            current=Some((case,target::State::new(&root.join(format!("case-{case:04}")))?));
        }
        let generation=u64::from_le_bytes(request[16..24].try_into()?);
        eprintln!("ANCHOR_ORIGINAL_BEGIN {case} {generation}");
        let result=current.as_mut().ok_or_else(||anyhow!("fixture state"))?.1.run(&request)?;
        eprintln!("ANCHOR_ORIGINAL_END {case} {generation}");
        output.write_all(&(result.len() as u64).to_le_bytes())?;
        output.write_all(&result)?;output.flush()?;
    }
    drop(current);
    Ok(())
}
