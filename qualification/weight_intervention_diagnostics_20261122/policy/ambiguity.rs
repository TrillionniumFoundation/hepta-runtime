//! Finite-horizon rectangular transition uncertainty and nonnegative uncertain fees.
//! A branch's tilt varies independently per state and action, with its listed order fixed.
use super::{Edge, Graph, Outcome, State, ACTIONS, TOLERANCE};

#[derive(Clone, Copy)]
struct Law {
    fee_low: f64,
    fee_high: f64,
    tilt: f64,
}

impl Law {
    fn validate(&self, graph: &Graph) -> Outcome<()> {
        if !self.fee_low.is_finite() || !self.fee_high.is_finite() || self.fee_low < 0.
            || self.fee_low > self.fee_high || !(0. ..1.).contains(&self.tilt) {
            return Err("require a finite ordered fee interval and branch tilt in [0,1)".into());
        }
        if self.fee_high * graph.max_fee > f64::MAX / (16. * (graph.deadline as f64 + 1.)) {
            return Err("uncertain fees exceed numerical range".into());
        }
        Ok(())
    }

    fn range(&self, edges: &[Edge], mut at: impl FnMut(&Edge) -> f64) -> (f64, f64) {
        let mut mass = [0.; 2];
        let mut weighted = [0.; 2];
        for (k, e) in edges.iter().enumerate() {
            let slope = if edges.len() == 1 { 0. } else { 2. * k as f64 / (edges.len()-1) as f64 - 1. };
            let x = at(e);
            for (i, sign) in [-1.,1.].iter().enumerate() {
                let p = e.probability * (1. + sign * self.tilt * slope);
                mass[i] += p;
                weighted[i] += p*x;
            }
        }
        // Normalized linear reweighting yields a linear-fractional expectation.
        // Positive denominators make the two tilt endpoints sufficient for an extremum.
        let left = weighted[0]/mass[0];
        let right = weighted[1]/mass[1];
        (left.min(right), left.max(right))
    }

    fn bound(&self, state: &State, a: usize, children: &[f64], lower: bool) -> f64 {
        if !(1..=3).contains(&a) { return state.terminal[a]; }
        let fee = if lower { self.fee_high } else { self.fee_low };
        let (lo,hi) = self.range(&state.branches[a-1], |e| children[e.next] - fee*e.fee);
        if lower { lo } else { hi }
    }

    fn common_action_delta(&self, state: &State, a: usize, child_deltas: &[f64]) -> f64 {
        if !(1..=3).contains(&a) { return 0.; }
        self.range(&state.branches[a-1], |e| child_deltas[e.next]).0
    }
}

struct Assessment {
    worst: Vec<f64>,
    best: Vec<f64>,
}

fn assess(g: &Graph, law: Law, policy: &[usize]) -> Assessment {
    let mut worst = vec![0.; g.states.len()];
    let mut best = worst.clone();
    for &i in g.order.iter().rev() {
        let st = &g.states[i];
        worst[i] = law.bound(st, policy[i], &worst, true);
        best[i] = law.bound(st, policy[i], &best, false);
    }
    Assessment { worst, best }
}

fn paired_lower(g: &Graph, law: Law, policy: &[usize], candidate: &Assessment, base: &Assessment) -> Vec<f64> {
    let mut delta = vec![0.; g.states.len()];
    for &i in g.order.iter().rev() {
        let st = &g.states[i];
        delta[i] = if policy[i] == st.original {
            // Under one shared law, fees on the common first action cancel exactly.
            law.common_action_delta(st,policy[i],&delta)
        } else {
            candidate.worst[i] - base.best[i]
        };
    }
    delta
}

fn minimize_risk(g: &Graph, law: Law, base: &Assessment, dominate: bool) -> Vec<usize> {
    let mut policy = vec![0; g.states.len()];
    let mut lower = vec![0.; g.states.len()];
    let mut delta = lower.clone();
    for &i in g.order.iter().rev() {
        let st = &g.states[i];
        let mut choice = st.original;
        let mut best_q = law.bound(st, choice, &lower, true);
        let mut score = if dominate { law.common_action_delta(st,choice,&delta) } else { best_q };
        for a in 0..ACTIONS {
            if !st.legal(a) || a == st.original { continue; }
            let q = law.bound(st, a, &lower, true);
            let s = if dominate { q - base.best[i] } else { q };
            // A strict maximum is needed for the Bellman maximin reference.
            if (dominate && s > score + TOLERANCE) || (!dominate && s > score) {
                choice=a; score=s; best_q=q;
            }
        }
        policy[i]=choice; lower[i]=best_q; delta[i]=score;
    }
    policy
}

pub(super) fn run(g: &Graph, args: &[String]) -> Outcome<()> {
    if args.len()!=3 { return Err("expected --uncertainty MIN_FEE MAX_FEE MAX_TILT".into()); }
    let number=|i:usize| args[i].parse::<f64>().map_err(|_| "invalid ambiguity parameter".to_owned());
    let law=Law { fee_low:number(0)?,fee_high:number(1)?,tilt:number(2)? };
    law.validate(g)?;
    let original:Vec<_>=g.states.iter().map(|s| s.original).collect();
    let candidate:Vec<_>=g.states.iter().map(|s| s.direct).collect();
    let base=assess(g,law,&original);
    let opt=minimize_risk(g,law,&base,false);
    let safe=minimize_risk(g,law,&base,true);
    let mut rows=Vec::new();
    for (name,policy) in [("BASE",original.clone()),("PROPOSAL",candidate),("MAXIMIN",opt),("DOMINANT",safe)] {
        let value=assess(g,law,&policy);
        let delta=paired_lower(g,law,&policy,&value,&base);
        if value.worst.iter().chain(&value.best).chain(&delta).any(|x| !x.is_finite()) {
            return Err("nonfinite uncertainty assessment".into());
        }
        if name=="DOMINANT" && delta.iter().any(|x| *x < -TOLERANCE) {
            return Err("state-level dominance invariant failed".into());
        }
        let i=g.initial;
        rows.push((name,policy,value.worst[i],value.best[i],delta[i]));
    }
    for (name,actions,lo,hi,delta) in rows {
        let codes:String=actions.into_iter().map(|a| char::from(b'0'+a as u8)).collect();
        println!("{name} {lo:.17e} {hi:.17e} {delta:.17e} {codes}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_asymmetric_probability_endpoints() {
        let l=Law{fee_low:1.,fee_high:3.,tilt:0.4};
        let edges=[Edge{probability:0.25,next:0,fee:0.},Edge{probability:0.75,next:1,fee:0.}];
        let (lo,hi)=l.range(&edges,|e| if e.next==1 {1.} else {-1.});
        assert!((lo-0.125).abs()<1e-12 && (hi-0.75).abs()<1e-12);
    }
    #[test]
    fn a_preferable_worst_case_is_not_uniform_dominance() {
        let g=Graph::parse("HEPTA_DAG_V1 3 0 0 3 0.3 0 0 1 0 0 2 .5 1 0 .5 2 0 0 0 1 16 0 1 0 4 4 4 0 0 0 1 16 0 -1 0 4 4 4 0 0 0").unwrap();
        let law=Law{fee_low:1.,fee_high:3.,tilt:0.8};
        let base=assess(&g,law,&[1,4,4]);
        assert_eq!(minimize_risk(&g,law,&base,false)[0],0);
        assert_eq!(minimize_risk(&g,law,&base,true)[0],1);
        let bounds=assess(&g,law,&[0,4,4]);
        let delta=paired_lower(&g,law,&[0,4,4],&bounds,&base);
        assert!((delta[0]+0.5).abs()<1e-12);
    }
}
