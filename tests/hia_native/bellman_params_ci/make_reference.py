"""Extract original typed definitions without changing a byte of the derives."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import tomllib

TARGET='d3d75c30719db966b004756f610007a7c723729e'
HEADER='''// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
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
'''
ADAPTER=r'''
fn word(output: &mut Vec<u8>, value: u64) { output.extend_from_slice(&value.to_le_bytes()); }
fn compact(params: &BellmanPlanParams) -> Vec<u8> {
    let mut result = b"HIABELL1".to_vec();
    word(&mut result, params.states.len() as u64);
    if params.states.is_empty() || params.states.len() > 4096 { return result; }
    for state in &params.states {
        for action in &state.actions {
            let mut row = Vec::new();
            match action {
                None => {},
                Some(BellmanAction::Terminal { value }) => {
                    word(&mut row, 1); word(&mut row, value.to_bits());
                },
                Some(BellmanAction::Continue { branches }) => {
                    word(&mut row, 2); word(&mut row, 0); word(&mut row, branches.len() as u64);
                    for branch in branches.iter().take(3) {
                        word(&mut row, branch.probability.to_bits());
                        word(&mut row, u64::from(branch.successor));
                        word(&mut row, branch.reward.to_bits());
                        word(&mut row, branch.fee.to_bits());
                    }
                },
            }
            row.resize(120, 0); result.extend_from_slice(&row);
        }
    }
    result
}
fn get(input: &[u8], at: usize) -> usize {
    usize::try_from(u64::from_le_bytes(input[at..at+8].try_into().unwrap())).unwrap()
}
fn main() {
    let mut input=Vec::new(); std::io::stdin().read_to_end(&mut input).unwrap();
    let mut output=std::io::BufWriter::new(std::io::stdout().lock());
    let mut at=0;
    while at<input.len() {
        let size=get(&input,at); at+=8;
        let value: serde_json::Value=serde_json::from_slice(&input[at..at+size]).unwrap(); at+=size;
        let canonical=serde_json::to_vec(&value).unwrap();
        let (status, count, body)=match serde_json::from_value::<BellmanPlanParams>(value) {
            Ok(params) => (0,params.states.len() as u64,compact(&params)),
            Err(error) => (1,0,error.to_string().into_bytes()),
        };
        let mut result=b"HBPOR001".to_vec();
        for value in [status,canonical.len() as u64,body.len() as u64,count,0,0,0] {word(&mut result,value);}
        result.extend_from_slice(&canonical);result.extend_from_slice(&body);
        output.write_all(&(result.len() as u64).to_le_bytes()).unwrap();
        output.write_all(&result).unwrap();
    }
    assert_eq!(at,input.len()); output.flush().unwrap();
}
'''

def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def create(target:Path,output:Path):
    raw=(target/'src/mcp/weight_bellman.rs').read_bytes()
    assert pin(raw)['sha256']=='254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
    lock_raw=(target/'Cargo.lock').read_bytes();manifest_raw=(target/'Cargo.toml').read_bytes()
    assert pin(lock_raw)['sha256']=='1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631'
    assert pin(manifest_raw)['sha256']=='bf00111f6ec88df9df4d0d1d14c125a64ce4f6bdc6724ba20e70498f56dcae7f'
    source=raw.decode();begin=source.index('#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]')
    end=source.index('#[derive(Clone, Debug, Serialize)]\nstruct StatePlan',begin)
    types=source[begin:end]
    program=HEADER+'use serde::{Deserialize, Serialize};\nuse std::io::{Read,Write};\n'+types+ADAPTER
    package='hia-bellman-params-reference'
    manifest=f'''[package]
name = "{package}"
version = "0.1.0"
edition = "2021"
publish = false

[[bin]]
name = "{package}"
path = "oracle.rs"

[dependencies]
serde = {{ version = "=1.0.229", features = ["derive"] }}
serde_json = {{ version = "=1.0.151", features = ["float_roundtrip", "raw_value"] }}
schemars = "=1.2.2"
'''
    text=manifest_raw.decode();profile=text[text.index('[profile.release]'):text.index('[dependencies]')]
    manifest+='\n'+profile
    blocks={}
    for block in re.split(r'(?m)^\[\[package\]\]\n',lock_raw.decode())[1:]:
        record=tomllib.loads('[[package]]\n'+block)['package'][0]
        blocks[(record['name'],record['version'])]=(record,'[[package]]\n'+block)
    needed=set()
    def visit(name,version=None):
        keys=[key for key in blocks if key[0]==name and (version is None or key[1]==version)]
        assert len(keys)==1,keys
        key=keys[0]
        if key in needed:return
        needed.add(key)
        for dependency in blocks[key][0].get('dependencies',[]):
            fields=dependency.split();visit(fields[0],fields[1] if len(fields)>1 else None)
    for name in ('serde','serde_json','schemars'):visit(name)
    root=f'[[package]]\nname = "{package}"\nversion = "0.1.0"\ndependencies = [\n "schemars",\n "serde",\n "serde_json",\n]\n\n'
    lock='# Exact resolved registry package records from the target.\nversion = 4\n\n'
    lock+=''.join(block for _,block in sorted([(key,blocks[key][1]) for key in needed]+[((package,'0.1.0'),root)]))
    output.mkdir(parents=True,exist_ok=True)
    for name,data in {'oracle.rs':program.encode(),'Cargo.toml':manifest.encode(),'Cargo.lock':lock.encode(),
                      'weight_bellman.rs':raw,'target-Cargo.lock':lock_raw,'target-Cargo.toml':manifest_raw}.items():
        (output/name).write_bytes(data)
    proof={'schema':'hepta.runtime.bellman-params-original-extraction.v1','target_commit':TARGET,
           'target_source':pin(raw),'target_lock':pin(lock_raw),'target_manifest':pin(manifest_raw),
           'unchanged_types':pin(types.encode()),'unchanged_release_profile':pin(profile.encode()),
           'oracle':pin(program.encode()),'resolved_lock':pin(lock.encode()),
           'registry_packages':[blocks[key][0] for key in sorted(needed)],
           'scope':'original Value + unchanged Bellman type Deserialize, no solver/admission/clock',
           'whole_runtime_replaced':False}
    (output/'extraction.json').write_text(json.dumps(proof,indent=2)+'\n')
    return proof

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--target',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(create(args.target,args.output)))
