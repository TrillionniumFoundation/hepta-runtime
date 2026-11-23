//! Hard-action planning for a supplied finite, acyclic task law.
mod fee_band;
mod ambiguity;
use std::io::{self, Read};
use std::str::{FromStr, SplitWhitespace};

const ACTIONS: usize = 6;
const TOLERANCE: f64 = 1e-10;
const MAX_STATES: usize = 100_000;
const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;

type Outcome<T> = Result<T, String>;

#[derive(Clone)]
struct Edge {
    probability: f64,
    next: usize,
    fee: f64,
}

struct State {
    tick: usize,
    mask: u8,
    terminal: [f64; ACTIONS],
    branches: [Vec<Edge>; 3],
    original: usize,
    direct: usize,
    reverse: usize,
}

impl State {
    fn legal(&self, action: usize) -> bool {
        action < ACTIONS && self.mask & (1 << action) != 0
    }

    fn action_value(&self, action: usize, successor_values: &[f64]) -> f64 {
        if (1..=3).contains(&action) {
            self.branches[action - 1].iter().map(|edge| {
                edge.probability * (successor_values[edge.next] - edge.fee)
            }).sum()
        } else {
            self.terminal[action]
        }
    }

    fn veto(&self, candidate: usize, lower: &[f64], upper: &[f64]) -> usize {
        if candidate != self.original
            && self.action_value(candidate, lower) > self.action_value(self.original, upper) + TOLERANCE
        {
            candidate
        } else {
            self.original
        }
    }
}

struct Graph {
    states: Vec<State>,
    initial: usize,
    order: Vec<usize>,
    deadline: usize,
    max_fee: f64,
}

fn token<T: FromStr>(tokens: &mut SplitWhitespace<'_>, field: &str) -> Outcome<T> {
    tokens.next().ok_or_else(|| format!("missing {field}"))?
        .parse().map_err(|_| format!("invalid {field}"))
}

impl Graph {
    fn parse(input: &str) -> Outcome<Self> {
        let mut t = input.split_whitespace();
        if t.next() != Some("HEPTA_DAG_V1") {
            return Err("invalid graph version".into());
        }
        let count: usize = token(&mut t, "state count")?;
        let initial: usize = token(&mut t, "initial state")?;
        if count == 0 || count > MAX_STATES || initial >= count {
            return Err("graph size or initial state outside supported range".into());
        }
        let mut states = Vec::with_capacity(count);
        let mut max_fee: f64 = 0.;
        let mut deadline = 0;
        for _ in 0..count {
            let tick: usize = token(&mut t, "tick")?;
            let mask: u8 = token(&mut t, "mask")?;
            if mask == 0 || mask >= 1 << ACTIONS || tick >= MAX_STATES {
                return Err("invalid tick or mask".into());
            }
            deadline = deadline.max(tick);
            let mut terminal = [0.; ACTIONS];
            for index in [0, 4, 5] {
                let payoff: f64 = token(&mut t, "terminal payoff")?;
                if !payoff.is_finite() || !(-1.0 ..= 1.0).contains(&payoff) {
                    return Err("terminal payoff outside [-1,1]".into());
                }
                terminal[index] = payoff;
            }
            let original = token(&mut t, "incumbent action")?;
            let direct = token(&mut t, "candidate action")?;
            let reverse = token(&mut t, "reverse-control action")?;
            let mut state = State {
                tick, mask, terminal, branches: Default::default(), original, direct, reverse,
            };
            if [original, direct, reverse].iter().any(|&a| !state.legal(a)) {
                return Err("illegal received policy action".into());
            }
            for action in 1..=3 {
                let n: usize = token(&mut t, "branch count")?;
                if n > 3 || (n != 0) != state.legal(action) {
                    return Err("branch count disagrees with admissible action".into());
                }
                let mut mass = 0.;
                for _ in 0..n {
                    let probability: f64 = token(&mut t, "branch probability")?;
                    let next: usize = token(&mut t, "successor")?;
                    let fee: f64 = token(&mut t, "fee")?;
                    if !(0.0 ..= 1.0).contains(&probability) || next >= count || !fee.is_finite() || fee < 0. {
                        return Err("invalid transition".into());
                    }
                    max_fee = max_fee.max(fee);
                    mass += probability;
                    state.branches[action-1].push(Edge { probability, next, fee });
                }
                if n > 0 && (mass - 1.).abs() > 2e-11 {
                    return Err("outgoing probability mass".into());
                }
            }
            states.push(state);
        }
        if t.next().is_some() {
            return Err("trailing fields".into());
        }
        for state in &states {
            for edge in state.branches.iter().flatten() {
                if states[edge.next].tick != state.tick + 1 {
                    return Err("transitions must advance exactly one tick".into());
                }
            }
        }
        // All permitted cumulative fee/expectation arithmetic must stay finite with headroom.
        if max_fee > f64::MAX / (4. * (deadline as f64 + 1.)) {
            return Err("cumulative cost exceeds the numerical range".into());
        }
        let mut order = (0..count).collect::<Vec<_>>();
        order.sort_by_key(|&i| states[i].tick);
        Ok(Self { states, initial, order, deadline, max_fee })
    }

    fn policy_values(&self, policy: &[usize]) -> Vec<f64> {
        let mut values = vec![0.; self.states.len()];
        for &i in self.order.iter().rev() {
            values[i] = self.states[i].action_value(policy[i], &values);
        }
        values
    }

    fn bounded_vetoes(&self) -> [Vec<usize>; 2] {
        let mut lower = self.states.iter().map(|s| -1. - (self.deadline - s.tick) as f64 * self.max_fee)
            .collect::<Vec<_>>();
        let mut upper = vec![1.; self.states.len()];
        std::array::from_fn(|_| {
            let policy = self.states.iter().map(|s| s.veto(s.direct, &lower, &upper)).collect();
            lower = self.states.iter().map(|s| s.action_value(s.original, &lower)).collect();
            upper = self.states.iter().map(|s| s.action_value(s.original, &upper)).collect();
            policy
        })
    }

    fn solve(&self) -> Outcome<Vec<(&'static str, Vec<usize>, f64)>> {
        let original: Vec<_> = self.states.iter().map(|s| s.original).collect();
        let direct = self.states.iter().map(|s| s.direct).collect();
        let reverse = self.states.iter().map(|s| s.reverse).collect();
        let baseline = self.policy_values(&original);
        let [h1, h2] = self.bounded_vetoes();
        let full = self.states.iter().map(|s| s.veto(s.direct, &baseline, &baseline)).collect();
        let reverse_full = self.states.iter().map(|s| s.veto(s.reverse, &baseline, &baseline)).collect();
        let any = self.states.iter().map(|s| {
            let mut best_action = s.original;
            let mut best_value = f64::NEG_INFINITY;
            for action in 0..ACTIONS {
                if s.legal(action) {
                    let value = s.action_value(action, &baseline);
                    // Strictly greater preserves canonical ascending-action tie order.
                    if value > best_value {
                        best_value = value;
                        best_action = action;
                    }
                }
            }
            s.veto(best_action, &baseline, &baseline)
        }).collect();
        let mut results = Vec::new();
        for (name, policy, guarded) in [("KEEP",original,false), ("EXACT_RAW",direct,false),
                ("EXACT_H1",h1,true), ("EXACT_H2",h2,true), ("EXACT_VPI",full,true),
                ("REVERSE_RAW",reverse,false), ("REVERSE_VPI",reverse_full,true), ("ALL_VPI",any,true)] {
            if guarded && self.states.iter().enumerate().any(|(i,s)| {
                s.action_value(policy[i], &baseline) < baseline[i]-TOLERANCE
            }) {
                return Err("accepted action violates supplied-law improvement".into());
            }
            let value = self.policy_values(&policy)[self.initial];
            if !value.is_finite() {
                return Err("nonfinite policy value".into());
            }
            results.push((name,policy,value));
        }
        Ok(results)
    }
}

fn run() -> Outcome<()> {
    let mut input = String::new();
    let n = io::stdin().take(MAX_INPUT_BYTES+1).read_to_string(&mut input).map_err(|e| e.to_string())?;
    if n > MAX_INPUT_BYTES as usize {
        return Err("input size cap".into());
    }
    let graph = Graph::parse(&input)?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--uncertainty") {
        return ambiguity::run(&graph, &args[1..]);
    }
    if !args.is_empty() {
        if args.len() != 3 || args[0] != "--fee-band" {
            return Err("expected --fee-band MIN MAX or no arguments".into());
        }
        let lo = args[1].parse::<f64>().map_err(|_| "invalid minimum fee multiplier")?;
        let hi = args[2].parse::<f64>().map_err(|_| "invalid maximum fee multiplier")?;
        return fee_band::emit(&graph, lo, hi);
    }
    for (name,policy,value) in graph.solve()? {
        let actions: String = policy.iter().map(|&a| char::from(b'0' + a as u8)).collect();
        println!("{name} {value:.17e} {actions}");
    }
    Ok(())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRAPH: &str = "HEPTA_DAG_V1 2 0\n0 3 0 0 0 0 1 0 1 1 1 .1 0 0\n1 16 0 .8 0 4 4 4 0 0 0";

    #[test]
    fn known_fee_and_one_more_action_unlock_profitable_continuation() {
        let results = Graph::parse(GRAPH).unwrap().solve().unwrap();
        assert_eq!(results[2].1[0],0);
        assert_eq!(results[3].1[0],1);
        assert!((results[3].2-0.7).abs()<1e-12);
        assert_eq!(results[4].1,results[3].1);
    }

    #[test]
    fn malformed_laws_and_proposals_are_refused() {
        for mutation in [GRAPH.replace("1 .1","0 .1"),GRAPH.replace(" 1 1 1 .1"," 1 .5 1 .1"),
                GRAPH.replace(" 0 1 0 1"," 4 1 0 1"),GRAPH.replace(" .8 0"," NaN 0"),
                GRAPH.replace(" .1 "," -1 "),format!("{GRAPH} 9")] {
            assert!(Graph::parse(&mutation).is_err());
        }
    }
}
