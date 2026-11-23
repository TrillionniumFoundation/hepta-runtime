//! Locate a single altered parameter of the source-bound four-output linear readout.
//! Input is forward evidence only. This process cannot mutate a model.
mod interval;
use std::io::{self, Read, Write};

const INPUTS: usize = 49; // 48 hidden features followed by an explicit 1 for bias.
const OUTPUTS: usize = 4;
const MIN_ROWS: usize = 2;
const MAX_ROWS: usize = 256;

fn take_u32(input: &mut impl Read) -> io::Result<usize> {
    let mut bytes = [0u8; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes) as usize)
}

fn take_row<const N: usize>(input: &mut impl Read) -> io::Result<[f64; N]> {
    let mut row = [0.; N];
    for value in &mut row {
        let mut bytes = [0u8; 8];
        input.read_exact(&mut bytes)?;
        *value = f64::from_le_bytes(bytes);
        if !value.is_finite() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "nonfinite forward evidence"));
        }
    }
    Ok(row)
}

struct Evidence {
    hidden: [f64; INPUTS],
    drift: [f64; OUTPUTS], // reference minus observed pre-activation
}

fn locate(rows: &[Evidence]) -> String {
    let energy: f64 = rows.iter().flat_map(|r| r.drift).map(|v| v * v).sum();
    if rows.iter().all(|r| r.drift.iter().all(|&x| x == 0.)) {
        return "KEEP".into();
    }
    if !energy.is_normal() { return "ABSTAIN".into(); }
    let mut best = (f64::INFINITY, 0, 0, 0.0);
    let mut second = f64::INFINITY;
    for column in 0..INPUTS {
        let norm: f64 = rows.iter().map(|r| r.hidden[column].powi(2)).sum();
        if norm == 0.0 { continue; }
        for output in 0..OUTPUTS {
            let dot: f64 = rows.iter().map(|r| r.hidden[column] * r.drift[output]).sum();
            let delta = dot / norm;
            // Direct residual evaluation avoids cancellation for near-exact fits.
            let loss: f64 = rows.iter().map(|r| {
                r.drift.iter().enumerate().map(|(i, &drift)| {
                    let error = if i == output { drift - delta * r.hidden[column] } else { drift };
                    error * error
                }).sum::<f64>()
            }).sum();
            if loss < best.0 {
                second = best.0;
                best = (loss, output, column, delta);
            } else if loss < second {
                second = loss;
            }
        }
    }
    if best.0 / energy <= 1e-16 && second / energy >= 1e-6 && best.3.is_finite() {
        return format!("EDIT {} {} {:.17e}", best.1, best.2, best.3);
    }
    "ABSTAIN".into()
}

fn read_hidden(input: &mut impl Read) -> io::Result<[f64; INPUTS]> {
    let hidden = take_row(input)?;
    if hidden[INPUTS - 1] != 1. || hidden[..INPUTS-1].iter().any(|x| x.abs() > 1.) {
        return Err(io::Error::other("expected tanh activations and unit bias"));
    }
    Ok(hidden)
}

fn main() -> io::Result<()> {
    let mut input = io::BufReader::new(io::stdin().lock());
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic)?;
    if &magic != b"WSL1" && &magic != b"WSL2" { return Err(io::Error::other("unexpected version")); }
    let count = take_u32(&mut input)?;
    for _ in 0..count {
        let n = take_u32(&mut input)?;
        if !(MIN_ROWS..=MAX_ROWS).contains(&n) { return Err(io::Error::other("invalid probe count")); }
        if &magic == b"WSL2" {
            writeln!(output, "{}", interval::query(&mut input, n)?)?;
            continue;
        }
        let mut rows = Vec::with_capacity(n);
        for _ in 0..n {
            let hidden = read_hidden(&mut input)?;
            let drift = take_row(&mut input)?;
            rows.push(Evidence { hidden, drift });
        }
        writeln!(output, "{}", locate(&rows))?;
    }
    let mut extra = [0u8; 1];
    if input.read(&mut extra)? != 0 { return Err(io::Error::other("unexpected trailing data")); }
    output.flush()
}
