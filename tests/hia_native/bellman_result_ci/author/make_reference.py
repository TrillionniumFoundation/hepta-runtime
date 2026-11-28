"""Extract the unchanged target result expression into a serializer-only reference."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import tomllib

TARGET_SHA = '254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
LOCK_SHA = '1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631'
MANIFEST_SHA = 'bf00111f6ec88df9df4d0d1d14c125a64ce4f6bdc6724ba20e70498f56dcae7f'
HEADER = '''// Copyright 2026 Muvon Un Limited
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
ADAPTER = r'''
// An explicit observation fixture, never an implementation of a clock.
// This reference qualifies serialization of the supplied elapsed bits only.
#[derive(Clone, Copy)]
struct ObservedElapsed(u64);
impl ObservedElapsed {
    fn elapsed(self) -> Self { self }
    fn as_secs_f64(self) -> f64 { f64::from_bits(self.0) }
}
fn get(s: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(s[at..at+8].try_into().unwrap())
}
fn hex(s: &[u8]) -> String {
    s.iter().map(|value| format!("{value:02x}")).collect()
}
fn render_observation(s: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    assert!(s.len() >= 64 && &s[..8] == b"HBLMRQ01");
    assert_eq!(get(s, 8), 1);
    assert_eq!(&s[40..64], &[0u8;24]);
    let core_len = usize::try_from(get(s, 16)).unwrap();
    let commitment_len = usize::try_from(get(s, 24)).unwrap();
    assert_eq!(s.len(), 64 + core_len + commitment_len);
    let c = &s[64..64+core_len];
    let h = &s[64+core_len..];
    assert_eq!(&c[..8], b"HIABPLN1");
    assert_eq!(&h[..8], b"HBCMTRES");
    let dims = Dimensions {
        states: usize::try_from(get(c, 8)).unwrap(),
        legal_actions: usize::try_from(get(c, 16)).unwrap(),
        continuing_actions: usize::try_from(get(c, 24)).unwrap(),
        branches: usize::try_from(get(c, 32)).unwrap(),
        zero_probability_branches: usize::try_from(get(c, 40)).unwrap(),
        probability_sum_error: f64::from_bits(get(c, 48)),
        work: get(c, 56),
    };
    assert_eq!(c.len(), 128 + 72 * dims.states);
    let plans: Vec<StatePlan> = (0..dims.states).map(|i| {
        let at = 128 + i * 72;
        let mask = get(c, at);
        StatePlan {
            q: std::array::from_fn(|j| {
                if mask & (1 << j) == 0 { None }
                else { Some(f64::from_bits(get(c, at + 24 + j * 8))) }
            }),
            value: f64::from_bits(get(c, at + 16)),
            action: usize::try_from(get(c, at + 8)).unwrap(),
        }
    }).collect();
    let exact_tie_states = get(c, 64);
    let near_tie_states = get(c, 72);
    let minimum_relative_action_gap = if get(c, 80) == 0 { None }
        else { Some(f64::from_bits(get(c, 88))) };
    let maximum_consistency_residual = f64::from_bits(get(c, 96));
    let request_bytes = usize::try_from(get(h, 8)).unwrap();
    assert_eq!(h.len(), 128 + request_bytes);
    let request_sha256 = hex(&h[16..48]);
    let implementation_source_sha256 = hex(&h[48..80]);
    let plan_id = format!("wb1_{}", hex(&h[80..112]));
    let started = ObservedElapsed(get(s, 32));
'''
MAIN = r'''
fn main() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let mut at = 0;
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    while at < input.len() {
        let size = usize::try_from(get(&input, at)).unwrap();
        at += 8;
        let value = render_observation(&input[at..at+size]).unwrap();
        at += size;
        let body = serde_json::to_vec(&value).unwrap();
        output.write_all(&(body.len() as u64).to_le_bytes()).unwrap();
        output.write_all(&body).unwrap();
    }
    assert_eq!(at, input.len());
    output.flush().unwrap();
}
'''

def pin(raw):
    return {'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest()}

def create(target: Path, output: Path):
    raw=(target/'src/mcp/weight_bellman.rs').read_bytes()
    lock_raw=(target/'Cargo.lock').read_bytes()
    manifest_raw=(target/'Cargo.toml').read_bytes()
    assert pin(raw)['sha256']==TARGET_SHA
    assert pin(lock_raw)['sha256']==LOCK_SHA
    assert pin(manifest_raw)['sha256']==MANIFEST_SHA
    source=raw.decode()
    begin=source.index('#[derive(Clone, Debug, Serialize)]\nstruct StatePlan')
    end=source.index('\nfn finite(', begin)
    expression_begin=source.index('\tOk(json!({',source.index('fn solve('))
    expression_end=source.index('\n}', expression_begin)
    names=('ACTION_NAMES','SEMANTICS_VERSION','MAX_REQUEST_BYTES','MAX_WORK',
           'PROBABILITY_SUM_TOLERANCE','NEAR_TIE_TOLERANCE')
    pieces={'types':source[begin:end], 'result_expression':source[expression_begin:expression_end]}
    for name in names:
        pieces['constant_'+name]=next(line for line in source.splitlines(True) if line.startswith('const '+name+':'))
    program=(HEADER+'use serde::Serialize;\nuse serde_json::{Value,json};\nuse std::io::{Read,Write};\n'+
             ''.join(pieces['constant_'+name] for name in names)+pieces['types']+ADAPTER+
             pieces['result_expression']+'\n}\n'+MAIN)
    assert all(program.count(text)==1 for text in pieces.values())
    package='hia-bellman-result-reference'
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
'''
    original_manifest=manifest_raw.decode()
    profile=original_manifest[original_manifest.index('[profile.release]'):original_manifest.index('[dependencies]')]
    manifest+='\n'+profile
    # Registry package records are copied byte for byte from the target lock.
    blocks={}
    for block in re.split(r'(?m)^\[\[package\]\]\n',lock_raw.decode())[1:]:
        record=tomllib.loads('[[package]]\n'+block)['package'][0]
        blocks[(record['name'],record['version'])]=(record,'[[package]]\n'+block)
    needed=set()
    def visit(name, version=None):
        choices=[key for key in blocks if key[0]==name and (version is None or key[1]==version)]
        assert len(choices)==1,choices
        key=choices[0]
        if key in needed:return
        needed.add(key)
        for dependency in blocks[key][0].get('dependencies',[]):
            fields=dependency.split()
            visit(fields[0],fields[1] if len(fields)>1 else None)
    visit('serde');visit('serde_json')
    root=f'[[package]]\nname = "{package}"\nversion = "0.1.0"\ndependencies = [\n "serde",\n "serde_json",\n]\n\n'
    package_blocks=[(key,blocks[key][1]) for key in needed]+[((package,'0.1.0'),root)]
    lock='# Resolved target registry package records, retained without edits.\nversion = 4\n\n'
    lock+=''.join(block for _,block in sorted(package_blocks))
    output.mkdir(parents=True,exist_ok=True)
    for name,data in {'oracle.rs':program.encode(),'Cargo.toml':manifest.encode(),'Cargo.lock':lock.encode(),
                      'weight_bellman.rs':raw,'target-Cargo.lock':lock_raw,'target-Cargo.toml':manifest_raw}.items():
        (output/name).write_bytes(data)
    evidence={'schema':'hepta.runtime.bellman-result-original-extraction.v1',
        'target_commit':'d3d75c30719db966b004756f610007a7c723729e',
        'target_source':pin(raw),'target_lock':pin(lock_raw),'target_manifest':pin(manifest_raw),
        'oracle':pin(program.encode()),'resolved_lock':pin(lock.encode()),
        'unchanged_extractions':{name:pin(text.encode()) for name,text in pieces.items()},
        'unchanged_release_profile':pin(profile.encode()),
        'registry_packages':[blocks[key][0] for key in sorted(needed)],
        'adapter_only':['decode actual native core and commitment observations',
                        'explicit elapsed-bit observation fixture; no clock emulation',
                        'length-delimited complete serde_json::Value bytes'],
        'excluded':['numerical solver correctness','elapsed clock/deadline semantics',
                    'installed-source identity authority','async admission and cancellation','public tool routing']}
    (output/'extraction.json').write_text(json.dumps(evidence,indent=2)+'\n')
    return evidence

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(create(a.target,a.output)))
