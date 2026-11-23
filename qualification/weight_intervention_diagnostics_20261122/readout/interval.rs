//! One-coordinate interval inference for independently rounded reference and observed logits.
use super::{INPUTS, OUTPUTS};
use std::io::{self, Read};

struct IntervalRow {
    hidden: [f64; INPUTS],
    lo: [f64; OUTPUTS],
    hi: [f64; OUTPUTS],
}

pub(super) fn query(input: &mut impl Read, n: usize) -> io::Result<String> {
    let mut rows = Vec::with_capacity(n);
    for _ in 0..n {
        let hidden = super::read_hidden(input)?;
        let lo = super::take_row::<OUTPUTS>(input)?;
        let hi = super::take_row::<OUTPUTS>(input)?;
        if lo.iter().zip(hi).any(|(&a,b)| a > b) {
            return Err(io::Error::other("reversed observation interval"));
        }
        rows.push(IntervalRow { hidden, lo, hi });
    }
    if rows.iter().all(|r| (0..OUTPUTS).all(|k| r.lo[k] <= 0. && r.hi[k] >= 0.)) {
        return Ok("KEEP".into());
    }
    let mut unique = None;
    for k in 0..OUTPUTS {
        // A single changed output cannot produce a certain drift in another output.
        if rows.iter().any(|r| (0..OUTPUTS).any(|i| i != k && (r.lo[i] > 0. || r.hi[i] < 0.))) {
            continue;
        }
        for c in 0..INPUTS {
            let mut lower = f64::NEG_INFINITY;
            let mut upper = f64::INFINITY;
            for r in &rows {
                let h = r.hidden[c];
                if h == 0. {
                    if r.lo[k] > 0. || r.hi[k] < 0. { lower = f64::INFINITY; break; }
                    continue;
                }
                let a = r.lo[k] / h;
                let b = r.hi[k] / h;
                lower = lower.max(a.min(b).next_down());
                upper = upper.min(a.max(b).next_up());
                if lower > upper { break; }
            }
            if lower.is_finite() && upper.is_finite() && lower <= upper {
                if unique.is_some() { return Ok("ABSTAIN".into()); }
                unique = Some((k,c,lower,upper));
            }
        }
    }
    Ok(match unique {
        Some((k,c,lo,hi)) => format!("EDIT {k} {c} {:.17e} {lo:.17e} {hi:.17e}", lo.midpoint(hi)),
        None => "ABSTAIN".into(),
    })
}
