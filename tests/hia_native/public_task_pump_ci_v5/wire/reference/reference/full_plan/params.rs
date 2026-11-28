// Copyright 2026 Muvon Un Limited
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
//! Complete original typed values, encoded by the previously qualified compact observer.

use std::io::{Read, Write};
#[path = "../weight_bellman.rs"]
mod original;
use original::{BellmanAction, BellmanPlanParams};

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
