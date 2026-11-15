"""Extract unchanged Rust numerical owners into a dependency-free replay driver.

Only typed wire decoding and result encoding are new. The original functions
and the two solve passes are copied byte-for-byte, with identities recorded.
Canonical serde commitment, async admission and public rendering are excluded.
"""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--original', type=Path, default=Path(__file__).resolve().parent/'weight_bellman.original.rs')
parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parent)
args = parser.parse_args()
ROOT = args.output.resolve()
ROOT.mkdir(parents=True,exist_ok=True)
raw = args.original.read_bytes()
assert hashlib.sha256(raw).hexdigest() == '254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
source = raw.decode()

def original_function(name):
    start = source.index('fn ' + name + '(')
    end = source.index('\n}\n', start) + 3
    return source[start:end]

pieces = {name: original_function(name) for name in ('finite','deadline','validate','action_value','choose')}
begin = source.index('\tlet mut plans = Vec::with_capacity(dims.states);')
end = source.index('\n\tdeadline(end)?;\n\tOk(json!', begin) + len('\n\tdeadline(end)?;')
pieces['solve_numerical_body'] = source[begin:end]
constants = source[source.index('const MAX_STATES:'):source.index('static PLANNERS:')]

prefix = r'''
use std::io::{Read, Write};
use std::time::{Duration, Instant};
type Result<T> = std::result::Result<T,String>;
macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*)) }; }
macro_rules! anyhow { ($($arg:tt)*) => { format!($($arg)*) }; }
#[derive(Clone,Debug)]
struct BellmanPlanParams { states: Vec<BellmanState> }
#[derive(Clone,Debug)]
struct BellmanState { actions: [Option<BellmanAction>;6] }
#[derive(Clone,Debug)]
enum BellmanAction { Terminal { value:f64 }, Continue { branches:Vec<BellmanBranch> } }
#[derive(Clone,Debug)]
struct BellmanBranch { probability:f64, successor:u32, reward:f64, fee:f64 }
#[derive(Clone,Debug)]
struct StatePlan { q:[Option<f64>;6], value:f64, action:usize }
#[derive(Clone,Copy,Debug)]
struct Dimensions { states:usize, legal_actions:usize, continuing_actions:usize,
    branches:usize, zero_probability_branches:usize, probability_sum_error:f64, work:u64 }
'''

encode = r'''
    let mut output=Vec::new();
    for value in [u64::from_le_bytes(*b"HIABPLN1"), dims.states as u64,
        dims.legal_actions as u64, dims.continuing_actions as u64,
        dims.branches as u64, dims.zero_probability_branches as u64,
        dims.probability_sum_error.to_bits(),dims.work,
        exact_tie_states as u64,near_tie_states as u64,
        u64::from(minimum_relative_action_gap.is_some()),
        minimum_relative_action_gap.unwrap_or(0.0).to_bits(),
        maximum_consistency_residual.to_bits(),0,0,0] {
        output.extend(value.to_le_bytes());
    }
    for plan in plans {
        let mut mask=0;
        for (index,q) in plan.q.iter().enumerate() { if q.is_some() { mask|=1<<index; } }
        for value in [mask,plan.action as u64,plan.value.to_bits()] { output.extend(value.to_le_bytes()); }
        for q in plan.q { output.extend(q.unwrap_or(0.0).to_bits().to_le_bytes()); }
    }
    Ok(output)
}
fn get(wire:&[u8],at:usize)->u64 { u64::from_le_bytes(wire[at..at+8].try_into().unwrap()) }
fn decode(wire:&[u8])->BellmanPlanParams {
    let count=get(wire,8) as usize;
    let states=(0..count).map(|index| BellmanState { actions:std::array::from_fn(|action| {
        let at=16+index*720+action*120;
        match get(wire,at) {
            0 => None,
            1 => Some(BellmanAction::Terminal { value:f64::from_bits(get(wire,at+8)) }),
            2 => {
                let n=get(wire,at+16) as usize;
                Some(BellmanAction::Continue { branches:(0..n).map(|i| {
                    // A fourth slot is used only to exercise original count
                    // refusal before any branch value can be examined.
                    if i>=3 { return BellmanBranch{probability:0.0,successor:0,reward:0.0,fee:0.0}; }
                    let p=at+24+i*32;
                    BellmanBranch{probability:f64::from_bits(get(wire,p)),successor:get(wire,p+8) as u32,
                        reward:f64::from_bits(get(wire,p+16)),fee:f64::from_bits(get(wire,p+24))}
                }).collect() })
            },
            _ => panic!("oracle accepts only declared typed kinds"),
        }
    }) }).collect();
    BellmanPlanParams{states}
}
fn main() {
    let mut input=Vec::new();std::io::stdin().read_to_end(&mut input).unwrap();
    let mut at=0;let mut out=std::io::BufWriter::new(std::io::stdout().lock());
    while at<input.len() {
        let n=get(&input,at) as usize;at+=8;let wire=&input[at..at+n];at+=n;
        let response=solve_numeric(&decode(wire));
        let (kind,bytes)=match response {Ok(bytes)=>(0u64,bytes),Err(error)=>(1,error.into_bytes())};
        out.write_all(&kind.to_le_bytes()).unwrap();out.write_all(&(bytes.len() as u64).to_le_bytes()).unwrap();
        out.write_all(&bytes).unwrap();
    }
    out.flush().unwrap();
}
'''
program = prefix + constants + '\n'.join(pieces[name] for name in ('finite','deadline','validate','action_value','choose'))
program += '\nfn solve_numeric(params:&BellmanPlanParams)->Result<Vec<u8>> {\n'
program += '    let end=Instant::now()+Duration::from_secs(30);\n    let dims=validate(params,end)?;\n'
program += pieces['solve_numerical_body'] + '\n' + encode
(ROOT/'bellman_original_oracle.rs').write_text(program)
assert args.original.read_bytes() == raw, 'original source changed during extraction'
for name,text in pieces.items():
    assert program.count(text) == 1, 'original extraction changed or duplicated: '+name
(ROOT/'bellman_original_oracle.json').write_text(json.dumps({
    'original_commit':'737acf6f901e46c57b0b4374e323e0d1132e0d49',
    'original_path':'src/mcp/weight_bellman.rs',
    'original_sha256':hashlib.sha256(raw).hexdigest(),
    'oracle_sha256':hashlib.sha256(program.encode()).hexdigest(),
    'unchanged_extractions':{name:{'bytes':len(text.encode()),'sha256':hashlib.sha256(text.encode()).hexdigest()}
                             for name,text in pieces.items()},
    'excluded':['canonical serde serialization and SHA256 identity','public JSON schema/result rendering',
                'async capacity and cancellation ownership','real 30-second timeout qualification'],
},indent=2)+'\n')
print(ROOT/'bellman_original_oracle.rs')
