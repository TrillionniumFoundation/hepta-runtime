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
//! One actual private service lifetime per original process.
use anyhow::{anyhow,bail,Result};
use std::io::{Read,Write};
use std::path::PathBuf;
mod target;
mod owned_environment;
fn main()->Result<()>{
    let args=std::env::args_os().collect::<Vec<_>>();
    if args.len()!=4{bail!("fixture arguments");}
    let root=PathBuf::from(&args[1]);let group=args[2].to_str().ok_or_else(||anyhow!("group"))?;
    let case=args[3].to_str().ok_or_else(||anyhow!("case"))?.parse::<u64>()?;
    let mut state=target::State::new(&root)?;
    owned_environment::install(group)?;
    let mut input=std::io::stdin().lock();let mut output=std::io::stdout().lock();
    loop{
        let mut header=[0_u8;8];
        if input.read(&mut header[..1])?==0{break;}
        input.read_exact(&mut header[1..])?;
        if u64::from_le_bytes(header)!=128{bail!("fixture extent");}
        let mut request=[0_u8;128];input.read_exact(&mut request)?;
        let generation=u64::from_le_bytes(request[16..24].try_into()?);
        eprintln!("PUBLISH_ORIGINAL_BEGIN {case} {generation}");
        let result=state.run(&request)?;
        eprintln!("PUBLISH_ORIGINAL_END {case} {generation}");
        output.write_all(&(result.len() as u64).to_le_bytes())?;
        output.write_all(&result)?;output.flush()?;
    }
    drop(state);Ok(())
}
