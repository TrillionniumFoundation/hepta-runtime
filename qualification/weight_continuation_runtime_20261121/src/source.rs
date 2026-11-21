// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Authenticate the actual gzip checkpoint, then evaluate its stored finite law.
//! Stored transition tables are reused; raw-parameter CTMC exponentials are not rebuilt.

use crate::task::{Completion, CompletionKind, Public, State};
use anyhow::{anyhow, bail, Result};
use hepta_semantic_source_adapter_study::semantics::{
    authenticate_neuron_gzip, TaskClass, VerifiedProfile,
};
use hepta_semantic_source_adapter_study::{unique_json, SourcePin, MAX_JSON_BYTES};
use serde::Serialize;
use serde_json::Value;
use std::io::Read;

pub const LAW_TOLERANCE: f64 = 2e-11;
pub const TASK_SHA256: &str = "51139ba57004f2a5d69381af2f781b3717404318f122d8b6bec8416004efffa5";
pub const PLANNING_SHA256: &str =
    "2fbd9b00861d3ff932c81b975b60e39dc9d4e9138e160a99222e6fdc6eb0a687";
pub const FORWARD_SHA256: &str = "c91ef40c484000e2a2b923425467c03fbbfb4e15a1f54856f6c850f9242c8e26";
pub const ARITHMETIC_SHA256: &str =
    "d0922ab0c458d9d382e1f9c851c52731c4a71256870000862dbebf5d38366b24";

#[derive(Clone, Debug, Serialize)]
pub struct SourceReceipt {
    pub compressed_sha256: String,
    pub decoded_sha256: String,
    pub semantic_binding_sha256: String,
    pub profile_binding_sha256: String,
    pub protected_fields_sha256: String,
}

pub struct VerifiedSource {
    pub(crate) receipt: SourceReceipt,
    pub(crate) law: StoredLaw,
    checkpoint_bytes: Vec<u8>,
}

impl VerifiedSource {
    pub fn receipt(&self) -> &SourceReceipt {
        &self.receipt
    }
    pub fn checkpoint_bytes(&self) -> &[u8] {
        &self.checkpoint_bytes
    }
    pub fn verify_unchanged(&self, current: &[u8]) -> Result<()> {
        if current != self.checkpoint_bytes {
            bail!("original checkpoint bytes changed");
        }
        Ok(())
    }
    /// Read-only numerical access for the separately bounded full-policy evaluator.
    pub fn validate_schedule(&self, public: &Public) -> Result<()> {
        public.validate()?;
        self.law.validate_schedule(public)
    }
    pub fn endpoint_posterior(&self, public: &Public, state: &State) -> Result<f64> {
        crate::task::validate_state(public, state)?;
        self.law.posterior(public, state)
    }
    pub fn completion_probability(
        &self,
        public: &Public,
        state: &State,
        completion: Completion,
    ) -> Result<f64> {
        crate::task::validate_state(public, state)?;
        self.law.probability(public, state, completion)
    }
    /// Renewal mass plus the three reviewed threshold forecasts, all in F64.
    /// This exposes no mutable law or hidden-parameter handle.
    pub fn representation(&self, public: &Public, state: &State) -> Result<Vec<f64>> {
        crate::task::validate_state(public, state)?;
        let mass = self.law.mass(public, state)?;
        let horizons = [(state.tick + 1).min(6), (state.tick + 2).min(6), 6];
        let mut forecasts = std::collections::BTreeMap::new();
        let mut future = mass.clone();
        for tick in state.tick..=6 {
            if horizons.contains(&tick) {
                let mut row = [0.0; 3];
                for (value, coordinate) in future.iter().zip(&self.law.coordinates) {
                    for (i, threshold) in [-0.5, 0.0, 0.5].iter().enumerate() {
                        if coordinate > threshold {
                            row[i] += value;
                        }
                    }
                }
                forecasts.insert(tick, row);
            }
            if tick < 6 {
                future = self.law.propagate(&future, public, tick)?;
            }
        }
        let mut out = mass;
        for horizon in horizons {
            out.extend_from_slice(
                forecasts
                    .get(&horizon)
                    .ok_or_else(|| anyhow!("missing forecast"))?,
            );
        }
        Ok(out)
    }
}

pub fn authenticate_source(
    compressed: &[u8],
    compressed_pin: &SourcePin,
    decoded_pin: &SourcePin,
    profile: &VerifiedProfile,
) -> Result<VerifiedSource> {
    for (role, expected) in [
        ("task_code", TASK_SHA256),
        ("planning_code", PLANNING_SHA256),
        ("forward_code", FORWARD_SHA256),
        ("arithmetic_code", ARITHMETIC_SHA256),
    ] {
        if profile
            .sources()
            .get(role)
            .is_none_or(|pin| pin.sha256 != expected)
        {
            bail!("source semantics differ from this compiled task/law reader");
        }
    }
    let authenticated = authenticate_neuron_gzip(
        compressed,
        compressed_pin,
        decoded_pin,
        profile,
        TaskClass::EndpointBinarySubmission,
    )?;
    let mut decoder = flate2::bufread::GzDecoder::new(compressed);
    let mut decoded = Vec::new();
    (&mut decoder)
        .take((MAX_JSON_BYTES + 1) as u64)
        .read_to_end(&mut decoded)?;
    decoded_pin.verify(&decoded, MAX_JSON_BYTES)?;
    let law = StoredLaw::from_json(&unique_json(&decoded)?)?;
    Ok(VerifiedSource {
        receipt: SourceReceipt {
            compressed_sha256: compressed_pin.sha256.clone(),
            decoded_sha256: decoded_pin.sha256.clone(),
            semantic_binding_sha256: authenticated.receipt().binding_sha256().into(),
            profile_binding_sha256: profile.binding_sha256().into(),
            protected_fields_sha256: authenticated.protected_fields_sha256().into(),
        },
        law,
        checkpoint_bytes: compressed.to_vec(),
    })
}

#[derive(Clone)]
pub(crate) struct Table {
    pub(crate) duration: f64,
    pub(crate) drive: i8,
    pub(crate) matrix: Vec<Vec<f64>>,
}

#[derive(Clone)]
pub(crate) struct StoredLaw {
    pub(crate) coordinates: Vec<f64>,
    pub(crate) confusion: [[f64; 2]; 2],
    pub(crate) tables: Vec<Table>,
}

impl StoredLaw {
    fn from_json(value: &Value) -> Result<Self> {
        let coordinates: Vec<f64> = serde_json::from_value(value["coordinates"].clone())?;
        let confusion: [[f64; 2]; 2] = serde_json::from_value(value["confusion"].clone())?;
        if coordinates.len() != 33 {
            bail!("stored law dimension differs");
        }
        for row in &confusion {
            if row.iter().any(|x| !x.is_finite() || *x <= 0.0 || *x > 1.0)
                || (row[0] + row[1] - 1.0).abs() > LAW_TOLERANCE
            {
                bail!("invalid original decoder law");
            }
        }
        let mut tables = Vec::new();
        for item in value["core"]["tables"]
            .as_array()
            .ok_or_else(|| anyhow!("missing law tables"))?
        {
            let duration = item["dt"]
                .as_f64()
                .ok_or_else(|| anyhow!("invalid table duration"))?;
            let drive = item["drive"]
                .as_i64()
                .ok_or_else(|| anyhow!("invalid table drive"))? as i8;
            let matrix: Vec<Vec<f64>> = serde_json::from_value(item["matrix"].clone())?;
            if matrix.len() != 33 {
                bail!("stored law rows differ");
            }
            for row in &matrix {
                let mut total = 0.0;
                for x in row {
                    total += x;
                }
                if row.len() != 33
                    || row.iter().any(|x| !x.is_finite() || *x < 0.0)
                    || (total - 1.0).abs() > 5e-11
                {
                    bail!("checkpoint transition is not stochastic");
                }
            }
            tables.push(Table {
                duration,
                drive,
                matrix,
            });
        }
        Ok(Self {
            coordinates,
            confusion,
            tables,
        })
    }

    fn transition(&self, public: &Public, tick: usize) -> Result<&[Vec<f64>]> {
        let row = self.tables.iter().find(|table| {
            table.duration.to_bits() == public.duration[tick].to_bits()
                && table.drive == public.drive[tick]
        });
        Ok(&row
            .ok_or_else(|| anyhow!("schedule has no original checkpoint transition table"))?
            .matrix)
    }

    pub(crate) fn validate_schedule(&self, public: &Public) -> Result<()> {
        for tick in 0..6 {
            self.transition(public, tick)?;
        }
        Ok(())
    }

    fn propagate(&self, mass: &[f64], public: &Public, tick: usize) -> Result<Vec<f64>> {
        let table = self.transition(public, tick)?;
        let mut out = vec![0.0; 33];
        // Explicit sequence is deliberate. NumPy's reductions are checked by tolerance,
        // never promoted to a false bitwise arithmetic equivalence claim.
        for (i, value) in mass.iter().enumerate() {
            for (j, target) in out.iter_mut().enumerate() {
                *target += value * table[i][j];
            }
        }
        Ok(out)
    }

    fn emission(&self, reliability: f64) -> Vec<[f64; 2]> {
        self.coordinates
            .iter()
            .map(|coordinate| {
                let noise = if *coordinate > 0.0 {
                    [1.0 - reliability, reliability]
                } else {
                    [reliability, 1.0 - reliability]
                };
                let mut row = [0.0; 2];
                for (i, n) in noise.iter().enumerate() {
                    for (j, value) in row.iter_mut().enumerate() {
                        *value += n * self.confusion[i][j];
                    }
                }
                row
            })
            .collect()
    }

    fn mass(&self, public: &Public, state: &State) -> Result<Vec<f64>> {
        let mut mass = vec![0.0; 33];
        for distance in [public.prior_distance, -public.prior_distance] {
            let mut best = 0;
            for i in 1..31 {
                if (self.coordinates[i] - distance).abs()
                    < (self.coordinates[best] - distance).abs()
                {
                    best = i;
                }
            }
            mass[best] += 0.5;
        }
        for tick in 0..state.tick {
            mass = self.propagate(&mass, public, tick)?;
            if let Some(record) = state
                .history
                .iter()
                .find(|item| item.observation_tick == tick + 1)
            {
                let emission = self.emission(public.reliability[tick]);
                let mut total = 0.0;
                for (i, value) in mass.iter_mut().enumerate() {
                    *value *= emission[i][usize::from(record.observation)];
                    total += *value;
                }
                if !total.is_finite() || total <= 0.0 {
                    bail!("impossible observation under original checkpoint law");
                }
                for value in &mut mass {
                    *value /= total;
                }
            }
        }
        Ok(mass)
    }

    pub(crate) fn posterior(&self, public: &Public, state: &State) -> Result<f64> {
        let mut mass = self.mass(public, state)?;
        for tick in state.tick..6 {
            mass = self.propagate(&mass, public, tick)?;
        }
        let mut posterior = 0.0;
        for (value, coordinate) in mass.iter().zip(&self.coordinates) {
            if *coordinate > 0.0 {
                posterior += value;
            }
        }
        Ok(posterior)
    }

    pub(crate) fn probability(
        &self,
        public: &Public,
        state: &State,
        completion: Completion,
    ) -> Result<f64> {
        match completion.kind {
            CompletionKind::None => Ok(1.0),
            CompletionKind::Failure => Ok(public.failure_probability),
            CompletionKind::Observation => {
                let tick = completion
                    .observation_tick
                    .ok_or_else(|| anyhow!("missing observation tick"))?;
                if tick != state.tick + 1 || tick > 6 {
                    bail!("noncausal predictive observation");
                }
                let y = usize::from(
                    completion
                        .observation
                        .ok_or_else(|| anyhow!("missing observation"))?,
                );
                if y > 1 {
                    bail!("observation is not binary");
                }
                let mass = self.propagate(&self.mass(public, state)?, public, state.tick)?;
                let emission = self.emission(public.reliability[tick - 1]);
                let mut value = 0.0;
                for (m, row) in mass.iter().zip(&emission) {
                    value += m * row[y];
                }
                Ok((1.0 - public.failure_probability) * value)
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn synthetic_source(law: StoredLaw) -> VerifiedSource {
    use hepta_semantic_source_adapter_study::digest;
    let bytes = b"explicit synthetic test checkpoint".to_vec();
    VerifiedSource {
        receipt: SourceReceipt {
            compressed_sha256: digest(&bytes),
            decoded_sha256: digest(&bytes),
            semantic_binding_sha256: digest(b"synthetic semantic"),
            profile_binding_sha256: digest(b"synthetic profile"),
            protected_fields_sha256: digest(b"synthetic protected"),
        },
        law,
        checkpoint_bytes: bytes,
    }
}
