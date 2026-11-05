#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Prepare and bind one R23 16/64 KiB component screen. Never builds or runs it."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

PROFILE = "src/mcp/runtime/ssh_observation_profile.rs"
VALIDATION = "src/mcp/runtime/ssh_observation_validation.rs"
TESTS = "src/mcp/runtime/ssh_observation_reference_tests.rs"
EXPECTED_PROFILE = "a62169343c2a08c38d69925f33fdc7551cf4be7b4b7f50cf89683f652a8f853a"
RLIBS = ("anyhow", "libc", "ring", "serde_json", "tokio", "tokio_util")
CONST16 = "const VERIFY_BUFFER_BYTES: usize = 16 * 1024;"
CONST64 = "const VERIFY_BUFFER_BYTES: usize = 64 * 1024;"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def source_map(source):
    files = [source / n for n in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")]
    for folder in ("src", "examples"):
        files.extend(p for p in (source / folder).rglob("*") if p.is_file())
    return {str(p.relative_to(source)): digest(p) for p in sorted(files)}


def between(text, start, end):
    assert text.count(start) == 1, start
    begin = text.index(start)
    assert text.find(end, begin) >= 0, end
    return text[begin:text.index(end, begin)]


IMPORTS = """use anyhow::{bail, Context, Result};
use std::collections::VecDeque;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
"""

GUARD_PREFIX = """mod guard {
use anyhow::{bail, Result};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
struct Completion { stop: CancellationToken }
pub(super) struct OwnerTicket { completion: Completion, deadline: Instant }
impl OwnerTicket {
"""
GUARD_SUFFIX = """
}
pub(super) fn new() -> OwnerTicket {
    OwnerTicket { completion: Completion { stop: CancellationToken::new() },
        deadline: Instant::now() + std::time::Duration::from_secs(120) }
}
pub(super) fn cancel(ticket: &OwnerTicket) { ticket.completion.stop.cancel(); }
pub(super) fn expire(ticket: &mut OwnerTicket) {
    ticket.deadline = Instant::now() - std::time::Duration::from_secs(1);
}
pub(super) fn keep_alive(ticket: &OwnerTicket) -> CancellationToken {
    ticket.completion.stop.clone()
}
}
"""

WRAPPER = """
pub(super) struct ComponentPins {
    ssh: PinnedFile, false_program: PinnedFile, shell: PinnedShell,
}
pub(super) fn load(spec: &crate::PublicPins) -> Result<ComponentPins> {
__LOAD_BLOCK__
    if ssh.reference.is_none() || false_program.reference.is_none()
        || shell.target.reference.is_none() {
        bail!("screen requires all three public files to fit the R23 reference budget");
    }
    Ok(ComponentPins { ssh, false_program, shell })
}
impl ComponentPins {
    fn pin(&self, index: usize) -> &PinnedFile {
        match index { 0 => &self.ssh, 1 => &self.false_program, 2 => &self.shell.target,
            _ => unreachable!("fixed three-file screen") }
    }
}
impl crate::ScreenArm for ComponentPins {
    fn verify(&self, scenario: usize, ticket: &crate::guard::OwnerTicket) -> Result<()> {
        let range = if scenario == 3 { 0..3 } else { scenario..scenario + 1 };
        for index in range {
            ticket.check_current()?;
            if index == 2 {
                self.shell.verify_resolution()?;
                ticket.check_current()?;
            }
            self.pin(index).verify_checked(&|| ticket.check_current())?;
            ticket.check_current()?;
        }
        Ok(())
    }
    fn preflight(&self) -> Result<serde_json::Value> {
        use std::cell::Cell;
        self.shell.verify_resolution()?;
        let mut rows = Vec::new();
        for index in 0..3 {
            let pin = self.pin(index);
            let good = crate::guard::new();
            let complete = Cell::new(0usize);
            pin.verify_checked(&|| {
                complete.set(complete.get() + 1);
                good.check_current()
            })?;
            let mut bad = pin.clone();
            let mut bytes = pin.reference.as_ref().context("reference missing")?.to_vec();
            if bytes.is_empty() { bail!("fixed executable unexpectedly empty"); }
            bytes[0] ^= 1;
            bad.reference = Some(bytes.into());
            let count = Cell::new(0usize);
            let failure = bad.verify_checked(&|| {
                count.set(count.get() + 1);
                good.check_current()
            }).err().context("reference mismatch was accepted")?;
            if failure.to_string() != "observation profile changed"
                || count.get() + 1 != complete.get() {
                bail!("complete-read mismatch preflight failed");
            }
            let late = crate::guard::new();
            let count_late = Cell::new(0usize);
            let failure = bad.verify_checked(&|| {
                count_late.set(count_late.get() + 1);
                if count_late.get() == complete.get() - 2 { crate::guard::cancel(&late); }
                late.check_current()
            }).err().context("late cancellation was accepted")?;
            if failure.to_string() != crate::CANCEL_ERROR {
                bail!("late cancellation did not retain precedence over content mismatch");
            }
            let stopped = crate::guard::new();
            crate::guard::cancel(&stopped);
            let failure = pin.verify_checked(&|| stopped.check_current())
                .err().context("cancelled validation was accepted")?;
            if failure.to_string() != crate::CANCEL_ERROR { bail!("cancel result differs"); }
            let mut expired = crate::guard::new();
            crate::guard::expire(&mut expired);
            let failure = pin.verify_checked(&|| expired.check_current())
                .err().context("expired validation was accepted")?;
            if failure.to_string() != crate::CANCEL_ERROR { bail!("expiry result differs"); }
            rows.push(serde_json::json!({"index": index, "bytes": pin.stamp.len,
                "complete_checkpoints": complete.get(), "mismatch_checkpoints": count.get(),
                "late_cancel_preempts_mismatch": true, "cancel_and_expiry_rejected": true}));
        }
        self.shell.verify_resolution()?;
        Ok(serde_json::json!({"buffer_bytes": VERIFY_BUFFER_BYTES, "files": rows}))
    }
}
pub(super) fn discover_public_pins() -> Result<(crate::PublicPins, serde_json::Value)> {
    let (shell_path, _) = fixed_shell_resolution()?;
    let paths = [PathBuf::from("/usr/bin/ssh"), PathBuf::from("/usr/bin/false"), shell_path];
    let maxima = [16 * 1024 * 1024, 1024 * 1024, 16 * 1024 * 1024];
    let mut hexes = Vec::new();
    let mut rows = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let (pin, _) = PinnedFile::load(path, None, maxima[index], false, true)?;
        let hex = pin.digest.iter().map(|v| format!("{v:02x}")).collect::<String>();
        rows.push(serde_json::json!({"role": crate::SCENARIOS[index],
            "path": path.to_str().context("public path is not UTF-8")?,
            "bytes": pin.stamp.len, "sha256": hex}));
        hexes.push(hex);
    }
    Ok((crate::PublicPins { ssh_sha256: hexes[0].clone(),
        false_sha256: hexes[1].clone(), shell_sha256: hexes[2].clone() },
        serde_json::json!(rows)))
}
"""

DRIVER = """
use anyhow::{bail, Context, Result};
const SCENARIOS: [&str; 4] = ["ssh", "false", "shell", "public_triplet"];
const CANCEL_ERROR: &str = "observation validation cancelled or expired before authority acceptance";
struct PublicPins { ssh_sha256: String, false_sha256: String, shell_sha256: String }
trait ScreenArm {
    fn verify(&self, scenario: usize, ticket: &guard::OwnerTicket) -> Result<()>;
    fn preflight(&self) -> Result<serde_json::Value>;
}
__CLOCK__
fn main() -> Result<()> {
    if std::env::args().len() != 1 { bail!("the frozen screen takes no runtime parameters"); }
    let (pins, public) = arm16::discover_public_pins()?;
    let a = arm16::load(&pins)?;
    let b = arm64::load(&pins)?;
    let arms: [&dyn ScreenArm; 2] = [&a, &b];
    let preflight = [a.preflight()?, b.preflight()?];
    println!("{}", serde_json::json!({"kind": "setup",
        "profile_sha256": "__PROFILE_SHA__", "validation_sha256": "__VALIDATION_SHA__",
        "blocks": 3, "iterations": 256, "warmup_per_scenario_arm": 8,
        "buffers": [16384, 65536], "scenarios": SCENARIOS,
        "public_inputs": public, "preflight": preflight,
        "scope": "public-file component only; no worker/owner lifecycle or RPC workload",
        "private_profile_read": false, "rss_comparable": false,
        "pins_source": "fixed public-file fingerprints; no private profile pin extraction"}));
    for scenario in 0..4 {
        for arm in &arms {
            let ticket = guard::new();
            for _ in 0..8 { arm.verify(scenario, &ticket)?; }
        }
        for block in 0..3 {
            for (position, index) in [0usize, 1, 1, 0].into_iter().enumerate() {
                let ticket = guard::new();
                let escape = guard::keep_alive(&ticket);
                std::hint::black_box(&escape);
                let wall_start = clock_ns(libc::CLOCK_MONOTONIC);
                let thread_start = clock_ns(libc::CLOCK_THREAD_CPUTIME_ID);
                let process_start = clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID);
                for _ in 0..256 { arms[index].verify(scenario, &ticket)?; }
                let process_end = clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID);
                let thread_end = clock_ns(libc::CLOCK_THREAD_CPUTIME_ID);
                let wall_end = clock_ns(libc::CLOCK_MONOTONIC);
                std::hint::black_box(&escape);
                println!("{}", serde_json::json!({"kind": "sample",
                    "scenario": SCENARIOS[scenario], "block": block, "position": position,
                    "buffer_bytes": ([16384, 65536][index]), "iterations": 256,
                    "wall_start_ns": wall_start, "wall_end_ns": wall_end,
                    "thread_cpu_start_ns": thread_start, "thread_cpu_end_ns": thread_end,
                    "process_cpu_start_ns": process_start, "process_cpu_end_ns": process_end}));
            }
        }
    }
    a.preflight()?;
    b.preflight()?;
    println!("{}", serde_json::json!({"kind": "complete", "sample_cells": 48,
        "automatic_retries": 0, "final_public_checks_passed": true}));
    Ok(())
}
"""


def prepare(args):
    source, out = args.source.resolve(), args.output.resolve()
    assert digest(source / PROFILE) == EXPECTED_PROFILE, "actual frozen R23 profile differs"
    profile = (source / PROFILE).read_text()
    validation = (source / VALIDATION).read_text()
    tests = (source / TESTS).read_text()
    section = between(profile, "#[derive(Clone, Debug, PartialEq, Eq)]\npub(super) struct Stamp {",
                      "\nfn validate_config(")
    load = between(profile, "\t\tlet mut reference_budget = MAX_EXECUTABLE_REFERENCE_BYTES;",
                   "\n\t\tlet runtime = crate::mcp::runtime::config::runtime_config()?;")
    guard = between(validation, "\tpub(super) fn check_current(&self) -> Result<()> {",
                    "\n\tpub(super) fn finish")
    clock = between(tests, "fn clock_ns(clock: libc::clockid_t) -> u64 {", "\n#[test]")
    reference = "const MAX_EXECUTABLE_REFERENCE_BYTES: usize = 2 * 1024 * 1024;"
    assert reference in profile and profile.count(CONST16) == 1
    arm16 = IMPORTS + reference + "\n" + CONST16 + "\n" + section + WRAPPER.replace("__LOAD_BLOCK__", load)
    assert arm16.count(CONST16) == 1
    arm64 = arm16.replace(CONST16, CONST64, 1)
    assert arm64.replace(CONST64, CONST16, 1) == arm16
    driver = DRIVER.replace("__CLOCK__", clock).replace("__PROFILE_SHA__", EXPECTED_PROFILE)
    driver = driver.replace("__VALIDATION_SHA__", digest(source / VALIDATION))
    body = ("// Copyright 2026 Muvon Un Limited\n// Copyright 2026 TrillionniumFoundation\n"
            "// SPDX-License-Identifier: Apache-2.0\n"
            "//! Frozen R23 public reference-buffer mechanism screen; no production service use.\n"
            "#![allow(dead_code, unused_imports)]\n"
            "#[cfg(not(target_os = \"linux\"))]\ncompile_error!(\"this screen requires Linux\");\n")
    body += GUARD_PREFIX + guard + GUARD_SUFFIX
    body += "\nmod arm16 {\n" + arm16 + "\n}\nmod arm64 {\n" + arm64 + "\n}\n" + driver
    files = source_map(source)
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    (out / "component.rs").write_text(body)
    (out / "source-map.json").write_bytes(encoded(files))
    (out / "arm-diff.txt").write_text("".join(difflib.unified_diff(
        arm16.splitlines(True), arm64.splitlines(True), fromfile="arm16", tofile="arm64")))
    manifest = {"schema": "hepta-r23-reference-buffer-component/v1", "status": "prepared_not_compiled_or_run",
                "profile_sha256": EXPECTED_PROFILE, "validation_sha256": digest(source / VALIDATION),
                "test_clock_source_sha256": digest(source / TESTS), "source_input_count": len(files),
                "source_map_sha256": digest(out / "source-map.json"),
                "component_sha256": digest(out / "component.rs"),
                "arm_diff_sha256": digest(out / "arm-diff.txt"),
                "arm_bodies_differ_only_in_buffer_constant": True,
                "copied_sections_sha256": {
                    "profile_helpers": hashlib.sha256(section.encode()).hexdigest(),
                    "public_load_block": hashlib.sha256(load.encode()).hexdigest(),
                    "actual_check_current_method": hashlib.sha256(guard.encode()).hexdigest(),
                    "actual_test_clock": hashlib.sha256(clock.encode()).hexdigest()},
                "new_worker_or_owner_lifecycle": False,
                "guard_scope": "actual check_current body with CancellationToken and Tokio Instant; thin field shape only",
                "private_configuration_inputs": False}
    (out / "manifest.json").write_bytes(encoded(manifest))
    print(json.dumps({"prepared": str(out), "manifest": manifest}))


def bind_build(args):
    source, prepared, qualification = args.source.resolve(), args.prepared.resolve(), args.qualification.resolve()
    manifest = json.loads((prepared / "manifest.json").read_text())
    q_path = qualification / "report.json"
    q = json.loads(q_path.read_text())
    assert q["qualified"] is True and q.get("finished_utc"), "R23 qualification not terminal/successful"
    assert all(s["returncode"] == 0 for s in q["stages"])
    files = source_map(source)
    assert files == q["source_tested"] == q["source_after"]
    assert files == json.loads((prepared / "source-map.json").read_text())
    assert digest(prepared / "component.rs") == manifest["component_sha256"]
    assert files[PROFILE] == EXPECTED_PROFILE
    artifact_path = qualification / "cargo-no-run.jsonl"
    stage = [s for s in q["stages"] if s["name"] == "test-build"]
    assert len(stage) == 1 and digest(artifact_path) == stage[0]["stdout_sha256"]
    found = {name: {} for name in RLIBS}
    native = set()
    for line in artifact_path.read_text().splitlines():
        event = json.loads(line)
        if event.get("reason") == "build-script-executed":
            for item in event.get("linked_paths", []):
                if item.startswith("native="):
                    native.add(item)
        name = event.get("target", {}).get("name")
        if event.get("reason") != "compiler-artifact" or name not in found:
            continue
        profile = event.get("profile", {})
        if profile.get("test") or str(profile.get("opt_level")) != "1":
            continue
        for filename in event.get("filenames", []):
            if filename.endswith(".rlib"):
                found[name][filename] = {"package_id": event["package_id"], "profile": profile}
    assert all(len(rows) == 1 for rows in found.values()), "missing/ambiguous qualified dev rlib; stop without Cargo fallback"
    deps = {}
    for name, rows in found.items():
        filename, metadata = next(iter(rows.items()))
        path = Path(filename)
        assert path.is_absolute() and path.is_file() and not path.is_symlink()
        deps[name] = dict(metadata, path=str(path), bytes=path.stat().st_size, sha256=digest(path))
    attempt = args.output.resolve()
    attempt.mkdir(mode=0o700, parents=False, exist_ok=False)
    argv = [str(args.rustc), "+1.95.0", "--edition=2021",
            "--crate-name=hepta_reference_buffer_screen", "-C", "opt-level=1",
            "-C", "debug-assertions=yes", "-C", "overflow-checks=yes",
            "-C", "lto=off", "-C", "codegen-units=1", "-C", "debuginfo=0"]
    for directory in sorted({str(Path(v["path"]).parent) for v in deps.values()}):
        argv += ["-L", "dependency=" + directory]
    for item in sorted(native):
        argv += ["-L", item]
    for name, row in deps.items():
        argv += ["--extern", name + "=" + row["path"]]
    argv += [str(prepared / "component.rs"), "-o", str(attempt / "component")]
    plan = {"schema": "hepta-r23-buffer-screen-build-binding/v1",
            "qualification_report": {"path": str(q_path), "sha256": digest(q_path)},
            "qualified_artifact_stream": {"path": str(artifact_path), "sha256": digest(artifact_path)},
            "component": {"path": str(prepared / "component.rs"), "sha256": manifest["component_sha256"]},
            "source_map_sha256": manifest["source_map_sha256"], "dependencies": deps,
            "rustc_argv": argv, "run_argv": [str(attempt / "component")],
            "environment": {"RUSTUP_AUTO_INSTALL": "0", "MALLOC_ARENA_MAX": "1"},
            "required_raw_records": ["rustc-vV.stdout", "compile.stdout", "compile.stderr",
                                    "compile-receipt.json", "run.stdout", "run.stderr",
                                    "run-receipt.json", "machine-before.json", "machine-after.json"],
            "execution": "caller uses existing owned-process runner; this command performs no compilation or measurement",
            "limits": {"compiler_seconds": 90, "post_compile_quiescence_seconds": 30, "screen_seconds": 60},
            "fallback": "none: missing rlibs/link error/timeout ends this screen; never invoke Cargo or recompile dependencies"}
    (attempt / "build-plan.json").write_bytes(encoded(plan))
    print(json.dumps({"bound": str(attempt / "build-plan.json"), "rustc_argv": argv, "run_argv": plan["run_argv"]}))


def summarize(args):
    raw = args.stdout.read_bytes()
    rows = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    setup = [r for r in rows if r.get("kind") == "setup"]
    samples = [r for r in rows if r.get("kind") == "sample"]
    done = [r for r in rows if r.get("kind") == "complete"]
    assert len(setup) == len(done) == 1 and len(samples) == 48
    setup = setup[0]
    assert setup["profile_sha256"] == EXPECTED_PROFILE
    assert setup["buffers"] == [16384, 65536] and setup["iterations"] == 256 and setup["blocks"] == 3
    assert setup["rss_comparable"] is False and setup["private_profile_read"] is False
    assert done[0]["sample_cells"] == 48 and done[0]["automatic_retries"] == 0 and done[0]["final_public_checks_passed"]
    assert rows[0]["kind"] == "setup" and rows[-1]["kind"] == "complete"
    scenarios = ("ssh", "false", "shell", "public_triplet")
    for i, row in enumerate(samples):
        assert row["scenario"] == scenarios[i // 12]
        assert row["block"] == (i % 12) // 4 and row["position"] == i % 4
        assert row["buffer_bytes"] == [16384, 65536, 65536, 16384][i % 4]
        assert row["iterations"] == 256
        for clock in ("wall", "thread_cpu", "process_cpu"):
            assert row[clock + "_end_ns"] > row[clock + "_start_ns"]
    result = {}
    for scenario in scenarios:
        arms = {}
        for size in (16384, 65536):
            group = [r for r in samples if r["scenario"] == scenario and r["buffer_bytes"] == size]
            arms[str(size)] = {clock + "_ns_per_call":
                sum(r[clock + "_end_ns"] - r[clock + "_start_ns"] for r in group)
                / sum(r["iterations"] for r in group)
                for clock in ("wall", "thread_cpu", "process_cpu")}
        ratio = {k: arms["65536"][k] / arms["16384"][k] for k in arms["16384"]}
        blocks = []
        for block in range(3):
            sums = {size: sum(r["thread_cpu_end_ns"] - r["thread_cpu_start_ns"]
                             for r in samples if r["scenario"] == scenario and r["block"] == block
                             and r["buffer_bytes"] == size) for size in (16384, 65536)}
            blocks.append(sums[65536] / sums[16384])
        result[scenario] = {"arms": arms, "B_over_A": ratio, "block_thread_cpu_B_over_A": blocks}
    weighted = sum(result[k]["arms"]["65536"]["thread_cpu_ns_per_call"] for k in scenarios[:3]) / sum(
        result[k]["arms"]["16384"]["thread_cpu_ns_per_call"] for k in scenarios[:3])
    gates = {"public_triplet_cpu_at_least_20_percent_lower":
                result["public_triplet"]["B_over_A"]["thread_cpu_ns_per_call"] <= .80,
             "false_cpu_regression_at_most_2_percent": result["false"]["B_over_A"]["thread_cpu_ns_per_call"] <= 1.02,
             "shell_cpu_regression_at_most_2_percent": result["shell"]["B_over_A"]["thread_cpu_ns_per_call"] <= 1.02}
    report = {"schema": "hepta-r23-reference-buffer-component-screen/v1",
              "component_records_valid": True, "mechanism_gate_passed": all(gates.values()),
              "candidate_adopted": False, "scope": "single-process public-file component; not RPC/owner lifecycle or whole-profile qualification",
              "source_profile_sha256": EXPECTED_PROFILE,
              "raw_stdout": {"path": str(args.stdout), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
              "public_inputs": setup["public_inputs"], "cases": result, "gates": gates,
              "equal_frequency_sum_of_individual_file_cpu_B_over_A_diagnostic": weighted,
              "automatic_retries": 0, "requires_original_compile_and_run_receipts": True,
              "global_buffer_private_and_sha_fallback_paths_tested": False}
    with args.output.open("xb") as stream:
        stream.write(encoded(report))
    print(json.dumps({"mechanism_gate_passed": report["mechanism_gate_passed"], "candidate_adopted": False, "gates": gates}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare")
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("bind-build")
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--prepared", type=Path, required=True)
    p.add_argument("--qualification", type=Path, required=True)
    p.add_argument("--rustc", type=Path, default=Path("/home/qian/.cargo/bin/rustc"))
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("summarize")
    p.add_argument("--stdout", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    {"prepare": prepare, "bind-build": bind_build, "summarize": summarize}[args.command](args)


if __name__ == "__main__":
    main()
