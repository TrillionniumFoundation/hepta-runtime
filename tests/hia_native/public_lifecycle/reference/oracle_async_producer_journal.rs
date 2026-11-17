// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification framing around unchanged Original controller, journal and Slot.
pub mod mcp;
pub mod utils;
use std::io::{Read,Write};
fn run() -> anyhow::Result<()> {
    let args:Vec<_>=std::env::args_os().collect();
    anyhow::ensure!(args.len()==3 && args[1]=="--runtime-config","fixed qualification argv");
    mcp::runtime::config::RuntimeConfig::load(&std::path::PathBuf::from(&args[2]))
        .and_then(mcp::runtime::config::init_runtime)?;
    let rt=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let mut owner=mcp::runtime::request_async::ProducerQualification::new();
    let mut input=std::io::stdin().lock();let mut output=std::io::stdout().lock();
    let (mut setups,mut journals,mut controls,mut states)=(0u64,0u64,0u64,0u64);
    loop {
        let mut header=[0u8;8];
        if input.read(&mut header[..1])?==0 {break;}
        input.read_exact(&mut header[1..])?;
        let size=usize::try_from(u64::from_le_bytes(header))?;
        anyhow::ensure!(size>=8 && size<=8*1024*1024,"qualification capacity");
        let mut frame=vec![0u8;size];input.read_exact(&mut frame)?;
        let response=if &frame[..8]==b"HRASYQ01" {
            controls+=1;
            rt.block_on(mcp::runtime::request_async::qualification_producer_extended(&frame))?
        } else if &frame[..8]==b"HRASSQ01" {
            states+=1;owner.state(&frame)?
        } else {
            let response=mcp::runtime::request_async::qualification_producer_journal(&frame)?;
            if u64::from_le_bytes(frame[8..16].try_into()?)==1 {setups+=1;} else {journals+=1;}
            response
        };
        output.write_all(&(u32::try_from(response.len())?).to_le_bytes())?;
        output.write_all(&response)?;output.flush()?;
    }
    drop(owner);drop(rt);
    eprintln!("{}",serde_json::json!({"config_queries":setups,"original_journal_calls":journals,
        "original_controller_calls":controls,"original_state_calls":states}));
    Ok(())
}
fn main() {
    if let Err(error)=run() {
        eprintln!("qualification carrier error: {error}");
        std::process::exit(1);
    }
}
