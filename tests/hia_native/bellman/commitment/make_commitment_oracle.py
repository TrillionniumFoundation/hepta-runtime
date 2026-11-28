"""Copy the original typed serializer and commitment calculation without edits."""
import argparse
import hashlib
import json
from pathlib import Path

ORIGINAL_SHA = '254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
ORIGINAL_COMMIT = '737acf6f901e46c57b0b4374e323e0d1132e0d49'
ORIGINAL_LOCK_SHA = '1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631'
ORIGINAL_MANIFEST_SHA = 'bf00111f6ec88df9df4d0d1d14c125a64ce4f6bdc6724ba20e70498f56dcae7f'

ADAPTER = r'''
fn get(s:&[u8],at:usize)->u64 { u64::from_le_bytes(s[at..at+8].try_into().unwrap()) }
fn decode(s:&[u8])->BellmanPlanParams {
    assert!(s.len()>=56 && &s[..8]==b"HBCMT001" && &s[40..48]==b"HIABELL1");
    let count=get(s,48) as usize;
    assert!(count<=4096 && s.len()==56+count*720);
    assert_eq!(&s[8..40],Sha256::digest(include_bytes!("weight_bellman.rs")).as_slice());
    BellmanPlanParams { states:(0..count).map(|state|BellmanState {
        actions:std::array::from_fn(|action| {
            let at=56+state*720+action*120;
            match get(s,at) {
                0=>None,
                1=>Some(BellmanAction::Terminal{value:f64::from_bits(get(s,at+8))}),
                2=>{
                    let count=get(s,at+16) as usize;
                    assert!(count<=3);
                    Some(BellmanAction::Continue{branches:(0..count).map(|index| {
                        let at=at+24+index*32;
                        BellmanBranch{probability:f64::from_bits(get(s,at)),
                            successor:u32::try_from(get(s,at+8)).unwrap(),
                            reward:f64::from_bits(get(s,at+16)),fee:f64::from_bits(get(s,at+24))}
                    }).collect()})
                },
                _=>panic!("fixture kind differs"),
            }
        })
    }).collect() }
}
fn from_hex(value:&str)->Vec<u8> {
    assert_eq!(value.len(),64);
    (0..32).map(|index|u8::from_str_radix(&value[index*2..index*2+2],16).unwrap()).collect()
}
fn main() {
    let mut input=Vec::new();std::io::stdin().read_to_end(&mut input).unwrap();
    let mut at=0;let mut out=std::io::BufWriter::new(std::io::stdout().lock());
    while at<input.len() {
        let size=get(&input,at) as usize;at+=8;
        let wire=&input[at..at+size];at+=size;
        let (kind,bytes)=match canonical(&decode(wire)) {
            Ok(bytes)=>(0u64,bytes),Err(error)=>(1,error.to_string().into_bytes()),
        };
        out.write_all(&kind.to_le_bytes()).unwrap();
        out.write_all(&(bytes.len() as u64).to_le_bytes()).unwrap();
        out.write_all(&bytes).unwrap();
    }
    out.flush().unwrap();
}
'''

def extract(original, original_lock, original_manifest, output, resolved_lock=None):
    output.mkdir(parents=True, exist_ok=True)
    raw = original.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ORIGINAL_SHA
    assert hashlib.sha256(original_lock.read_bytes()).hexdigest() == ORIGINAL_LOCK_SHA
    assert hashlib.sha256(original_manifest.read_bytes()).hexdigest() == ORIGINAL_MANIFEST_SHA
    source = raw.decode()
    types_begin = source.index('#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]')
    types_end = source.index('#[derive(Clone, Debug, Serialize)]\nstruct StatePlan')
    writer_begin = source.index('struct Commitment {')
    writer_end = source.index('\nfn hex(', writer_begin)
    hex_begin = writer_end + 1
    hex_end = source.index('\n}\n', hex_begin) + 3
    block_begin = source.index('\tlet mut commitment = Commitment {', source.index('fn solve('))
    block_end = source.index('\n\tlet mut plans = ', block_begin)
    pieces = {
        'serde_annotated_types': source[types_begin:types_end],
        'commitment_writer': source[writer_begin:writer_end],
        'hex': source[hex_begin:hex_end],
        'canonical_and_identity_block': source[block_begin:block_end],
        'semantics_version': next(line for line in source.splitlines(True) if line.startswith('const SEMANTICS_VERSION:')),
        'byte_budget': next(line for line in source.splitlines(True) if line.startswith('const MAX_REQUEST_BYTES:')),
    }
    program = ('use serde::{Deserialize, Serialize};\nuse sha2::{Digest, Sha256};\n'
               'use std::io::{Read,Write};\nuse std::time::{Duration,Instant};\n')
    program += ''.join(pieces[key] for key in ('semantics_version','byte_budget','serde_annotated_types','commitment_writer','hex'))
    program += '\nfn canonical(params:&BellmanPlanParams)->Result<Vec<u8>,Box<dyn std::error::Error>> {\n'
    program += '    let end=Instant::now()+Duration::from_secs(30);\n'
    program += pieces['canonical_and_identity_block']
    program += r'''
    let canonical=serde_json::to_vec(params)?;
    assert_eq!(canonical.len(),request_bytes);
    let mut result=Vec::from(*b"HBCMTRES");
    result.extend((request_bytes as u64).to_le_bytes());
    result.extend(from_hex(&request_sha256));
    result.extend(from_hex(&implementation_source_sha256));
    result.extend(from_hex(plan_id.strip_prefix("wb1_").unwrap()));
    result.extend([0u8;16]);result.extend(canonical);
    Ok(result)
}
'''
    program += ADAPTER
    for name, text in pieces.items():
        assert program.count(text) == 1, ('unchanged extraction not unique', name)
    (output/'oracle.rs').write_text(program)
    (output/'weight_bellman.rs').write_bytes(raw)
    manifest = '''[package]
name = "hia-bellman-commitment-reference"
version = "0.1.0"
edition = "2021"
publish = false

[[bin]]
name = "hia-bellman-commitment-reference"
path = "oracle.rs"

[dependencies]
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = { version = "=1.0.151", features = ["float_roundtrip", "raw_value"] }
schemars = "=1.2.2"
sha2 = "=0.11.0"
'''
    original_cargo = original_manifest.read_text()
    profile = original_cargo[original_cargo.index('[profile.release]'):original_cargo.index('[dependencies]')]
    manifest += '\n' + profile
    (output/'Cargo.toml').write_text(manifest)
    # Seed only; the portable runner resolves offline, proves every registry
    # package version/checksum belongs to this exact lock, then builds --frozen.
    lock = original_lock.read_bytes() if resolved_lock is None else resolved_lock.read_bytes()
    if resolved_lock is not None:
        assert hashlib.sha256(lock).hexdigest() == 'c7012ff277fa183c0aed8252522fa7741b71e49a5d49ebb83a5d1f8de0480215'
    (output/'Cargo.lock').write_bytes(lock)
    (output/'target-Cargo.lock').write_bytes(original_lock.read_bytes())
    evidence = {
        'original_commit': ORIGINAL_COMMIT, 'original_path': 'src/mcp/weight_bellman.rs',
        'original_sha256': ORIGINAL_SHA,
        'original_lock_sha256': hashlib.sha256(original_lock.read_bytes()).hexdigest(),
        'original_manifest_sha256': hashlib.sha256(original_manifest.read_bytes()).hexdigest(),
        'unchanged_release_profile_sha256': hashlib.sha256(profile.encode()).hexdigest(),
        'oracle_sha256': hashlib.sha256(program.encode()).hexdigest(),
        'resolved_lock_sha256': hashlib.sha256(lock).hexdigest() if resolved_lock is not None else None,
        'unchanged_extractions': {name: {'bytes':len(text.encode()), 'sha256':hashlib.sha256(text.encode()).hexdigest()}
                                 for name,text in pieces.items()},
        'adapter_only': ['fixed typed-frame fixture decoding', 'binary commitment result encoding',
                         'standalone schemars import at the exact locked version',
                         'independent canonical byte vector for byte-for-byte comparison'],
        'excluded': ['public JSON parsing and admission', 'numerical validation and solver',
                     'public response rendering', 'runtime semaphore, cancellation, deadline and routing',
                     'native installed-source digest authority'],
    }
    (output/'extraction.json').write_text(json.dumps(evidence,indent=2)+'\n')
    assert original.read_bytes() == raw
    return evidence

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original',type=Path,required=True)
    parser.add_argument('--original-lock',type=Path,required=True)
    parser.add_argument('--original-manifest',type=Path,required=True)
    parser.add_argument('--resolved-lock',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args()
    print(json.dumps(extract(a.original,a.original_lock,a.original_manifest,a.output,a.resolved_lock)))
