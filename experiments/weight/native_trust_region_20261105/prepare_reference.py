#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Freeze independent eigen/Brent and Fraction references before native RPC execution."""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import random
import struct
import time

import numpy as np
import scipy
from scipy.optimize import brentq

ORIGINAL_SHA = "6230881d25b9511d176fefd31778a6552444e22d2c0d8a8afaa7ad40eb3975c1"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_new(path: Path, data: dict) -> str:
    raw = (json.dumps(data, indent=2, allow_nan=False)+"\n").encode()
    with path.open("xb") as stream:
        stream.write(raw)
    return sha(raw)


def reference(params: dict) -> dict:
    started, cpu = time.perf_counter(), time.process_time()
    x = np.asarray(params["features"], dtype=np.float64)
    y = np.asarray(params["targets"], dtype=np.float64)
    sw = np.asarray(params["sample_weights"], dtype=np.float64)
    base = np.asarray(params["base_weights"], dtype=np.float64)
    lam, radius = params["lambda"], params["max_update_l2_norm"]
    systems = []
    for j in range(len(base)):
        h = x.T @ (sw[:, j, None] * x) + lam*np.eye(x.shape[1])
        c = x.T @ (sw[:, j] * (y[:, j]-x @ base[j]))
        eigenvalues, q = np.linalg.eigh(h)
        assert np.min(eigenvalues) > 0
        systems.append((h, c, eigenvalues, q, q.T @ c))

    def delta(mu: float) -> np.ndarray:
        return np.asarray([q @ (coordinates/(eigenvalues+mu)) for _, _, eigenvalues, q, coordinates in systems])

    if radius == 0:
        update, mu = np.zeros_like(base), None
    else:
        update, mu = delta(0.0), 0.0
        if np.linalg.norm(update) > radius:
            upper = max(lam, np.linalg.norm(np.asarray([s[1] for s in systems]))/radius)
            for _ in range(8):
                if np.linalg.norm(delta(upper)) <= radius:
                    break
                upper *= 2
            assert np.linalg.norm(delta(upper)) <= radius
            mu = brentq(lambda value: np.linalg.norm(delta(value))-radius, 0.0, upper,
                        xtol=np.finfo(float).tiny, rtol=1e-14, maxiter=256)
            update = delta(mu)
    weights = base+update
    objectives = [float(np.sum(sw[:, j]*(x @ weights[j]-y[:, j])**2)+lam*np.sum(update[j]**2)) for j in range(len(base))]
    residual = None if mu is None else max(float(np.max(np.abs((h+mu*np.eye(len(c))) @ update[j]-c))) for j, (h,c,_,_,_) in enumerate(systems))
    return {"weights_f64": weights.tolist(), "shared_multiplier": mu,
            "objective_per_output": objectives, "update_l2_norm_f64":float(np.linalg.norm(update)),
            "absolute_shifted_stationarity_residual":residual,
            "wall_seconds":time.perf_counter()-started, "cpu_seconds":time.process_time()-cpu,
            "method":"NumPy symmetric eigensystem per output and SciPy Brent shared-multiplier root"}


def norm_families() -> list[dict]:
    tiny = struct.unpack("<f", struct.pack("<I", 1))[0]
    maximum = float(np.finfo(np.float32).max)
    definitions = [
        ("pythagorean", [0.0,0.0], [3.0,4.0], "adjacent"),
        ("subnormal", [0.0], [tiny], "adjacent"),
        ("maximum_1024", [maximum]*1024, [-maximum]*1024, "adjacent"),
        ("small_positive_term", [0.0,0.0], [1.0,tiny], [1.0]),
        ("decimal_f32", [0.0], [float(np.float32(0.1))], [0.1]),
        ("signed_zero", [-0.0,1.0], [0.0,1.0], [0.0]),
    ]
    rng = random.Random(1782417)
    lengths = [1,2,7,31,127,512,1024]
    def finite_random() -> float:
        bits = rng.getrandbits(32)
        if (bits >> 23) & 255 == 255:
            bits ^= 1 << 23
        return struct.unpack("<f", struct.pack("<I", bits))[0]
    for i in range(16):
        n = lengths[i % len(lengths)]
        definitions.append((f"random_{i:02d}", [finite_random() for _ in range(n)],
                            [finite_random() for _ in range(n)], "adjacent"))
    result = []
    for name, before, after, radii in definitions:
        square = sum((Fraction(b)-Fraction(a))**2 for a,b in zip(before,after))
        units = square * (1 << 298)
        assert units.denominator == 1 and units.numerator.bit_length() <= 566
        if radii == "adjacent":
            r = math.sqrt(float(square))
            radii = [math.nextafter(r,0.0),r,math.nextafter(r,math.inf)]
        result.append({"name":name,"elements":len(before),
            "before_f32_hex":b"".join(struct.pack("<f",x) for x in before).hex(),
            "after_f32_hex":b"".join(struct.pack("<f",x) for x in after).hex(),
            "squared_update_units_hex":format(units.numerator,"x"),
            "squared_update_unit_exponent":-298,
            "radii":[{"radius":r,"radius_f64_bits":format(struct.unpack("<Q",struct.pack("<d",r))[0],"016x"),
                      "within_budget":square <= Fraction(r)**2} for r in radii]})
    return result


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    raw=args.fixture.read_bytes()
    assert sha(raw)==ORIGINAL_SHA
    original=json.loads(raw)
    anchor=np.asarray(original["base_weights"],dtype=np.float32).astype(np.float64)
    assert np.isfinite(anchor).all()
    derived={"schema":"hepta.public-head-exact-f32-anchor.v1",
        "original_fixture_sha256":ORIGINAL_SHA,"source_commit":original["source_commit"],
        "source_model_sha256":original["source_model_sha256"],
        "numeric_change":"Original F64 anchor explicitly rounded to F32 and lifted exactly to F64; features, targets, sample weights and lambda remain the original public TRAIN fixture.",
        "features":original["features"],"targets":original["targets"],
        "sample_weights":original["sample_weights"],"base_weights":anchor.tolist(),
        "frozen_belief_weights":np.asarray(original["frozen_belief_weights"],dtype=np.float32).astype(np.float64).tolist(),
        "lambda":original["lambda_"]}
    derived_sha=write_new(args.output/"derived_public_fixture.json",derived)
    basic={"features":[[1.0]],"targets":[[3.0]],"sample_weights":[[1.0]],
           "base_weights":[[1.0]],"lambda":1.0}
    cases=[]
    for name,radius in [("scalar_active",0.25),("scalar_inactive",10.0),("singleton",0.0)]:
        cases.append({"name":name,"params":dict(basic,max_update_l2_norm=radius)})
    cases.append({"name":"decimal_lowering","params":{"features":[[1.0]],"targets":[[1.0]],"sample_weights":[[1.0]],"base_weights":[[0.0]],"lambda":1.0,"max_update_l2_norm":0.1}})
    cases.append({"name":"shared_multiplier","params":{"features":[[1.0]],"targets":[[14.0,7.0]],"sample_weights":[[1.0,3.0]],"base_weights":[[2.0],[-1.0]],"lambda":1.0,"max_update_l2_norm":5.0}})
    for fraction in [0.05,0.5]:
        cases.append({"name":f"public_head_radius_fraction_{fraction}","public_fixture":True,
                      "radius_fraction_of_anchor_norm":fraction,
                      "params":dict({k:derived[k] for k in ["features","targets","sample_weights","base_weights","lambda"]},
                                    max_update_l2_norm=fraction*float(np.linalg.norm(anchor)))})
    for case in cases:
        case["reference"]=reference(case["params"])
    cases_sha=write_new(args.output/"reference_cases.json",{"schema":"hepta.native-wsp-trust-region-reference-cases.v1",
        "numpy_version":np.__version__,"scipy_version":scipy.__version__,"derived_fixture_sha256":derived_sha,
        "parameter_error_tolerance":"1e-8*(1+max abs reference parameter)","cases":cases})
    norms=norm_families()
    norm_sha=write_new(args.output/"norm_cases.json",{"schema":"hepta.native-wsp-exact-f32-norm-cases.v1",
        "random_seed":1782417,"random_families":16,"families":norms})
    print(json.dumps({"derived_fixture_sha256":derived_sha,"reference_cases_sha256":cases_sha,
                      "norm_cases_sha256":norm_sha,"planning_cases":len(cases),"norm_families":len(norms),
                      "norm_checks":sum(len(f["radii"]) for f in norms)}))


if __name__=="__main__":
    main()
