#!/usr/bin/env python3
"""Read-only independent numeric aggregation of one frozen X230 evidence package.

Reads only the supplied manifest/archive, verifies each consumed original member,
and creates one new JSON result. Does not execute tests, remote commands or code
from evidence. All latency quantiles are recomputed from original call rows.
Explicit comparison identities allow an A62/R3 native series and an R2/R3
registry comparison without conflating their baselines. This script does not
infer paired R2/R3 effects from separate A62/R2 and A62/R3 experiment sessions.
"""
import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import statistics
import tarfile


BASELINE = "fbc9cb15fb425e0d17ce570b52b9ba3e70d689c7c5d1ec68b99ac742d4879dde"
CANDIDATE = "2f0e92e0225f0396565aa0939ef010574c888fd308f34f6de7aa65e53b513639"
BASELINE_TEST = "5951a3222468ce17daa427eb0d936464fad85b69bf6a8ac8d7b41bb0bc722e33"
CANDIDATE_TEST = "8a7a043f2296f41aaea91c95ce58b9cef1e08dbc86a03fecbaadd215a830a18d"
KNOWN_IDENTITIES = {
    "A62": {"release_sha256": BASELINE, "library_test_sha256": BASELINE_TEST},
    "R2": {"release_sha256": CANDIDATE, "library_test_sha256": CANDIDATE_TEST},
    "R3": {"release_sha256": "5e670e58d1c8067df594fcc256a2b88bd52cb60a443cadb36e2a7dc0f49effa7",
           "library_test_sha256": "2d932d972ac7dae751bfeffdcdd925893e5267ecec460ba391fc8625c94257d3"},
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def change(candidate, baseline):
    return 100 * (candidate / baseline - 1) if baseline else None


def latency(rows):
    values = sorted(row["elapsed_ms"] for row in rows)
    need(values and all(math.isfinite(x) and x >= 0 for x in values), "invalid latency rows")
    return {"samples": len(values), "mean_ms": statistics.mean(values),
            "p50_ms": statistics.median(values),
            "p95_ms": values[math.ceil(.95 * len(values)) - 1],
            "p99_ms": values[math.ceil(.99 * len(values)) - 1], "max_ms": values[-1]}


class Package:
    def __init__(self, manifest, archive):
        self.manifest_path, self.archive_path = manifest, archive
        raw = gzip.decompress(manifest.read_bytes()) if manifest.name.endswith(".gz") else manifest.read_bytes()
        self.manifest = json.loads(raw)
        need(self.manifest["complete"] is True, "package manifest incomplete")
        with archive.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        need(actual == self.manifest["archive"]["sha256"], "package archive SHA differs")
        self.files = {row["path"]: row for row in self.manifest["files"]}
        need(len(self.files) == len(self.manifest["files"]), "duplicate original path in manifest")
        self.archive = tarfile.open(archive, "r:gz")
        self.members = {row.name: row for row in self.archive.getmembers()}
        need(len(self.members) == len(self.archive.getmembers()), "duplicate archive member")
        self.consumed = {}
        self.inputs = {row["label"]: row["report"] for row in self.manifest["inputs"]}
        need(len(self.inputs) == len(self.manifest["inputs"]), "duplicate input label")

    def read(self, path):
        row = self.files[str(path)]
        name = row["archive_name"]
        pure = PurePosixPath(name)
        need(not pure.is_absolute() and ".." not in pure.parts and "\\" not in name, "unsafe member")
        member = self.members[name]
        need(member.isfile(), "nonregular member")
        raw = self.archive.extractfile(member).read()
        need(len(raw) == row["bytes"] and digest(raw) == row["sha256"], "member hash/size differs: " + name)
        self.consumed[str(path)] = {"archive_name": name, "sha256": row["sha256"], "bytes": row["bytes"]}
        return raw

    def json(self, path):
        return json.loads(self.read(path))

    def lines(self, path, compressed=False):
        raw = self.read(path)
        if compressed:
            raw = gzip.decompress(raw)
        need(not raw or raw.endswith(b"\n"), "partial JSONL line")
        return [json.loads(line) for line in raw.splitlines()]


def aggregate(cells, rows, success_key, cpu_key=None):
    calls = sum(cell["calls"] for cell in cells)
    successes = sum(cell[success_key] for cell in cells)
    seconds = sum(cell["seconds"] for cell in cells)
    need(calls == successes == len(rows) and all(row["okay"] is True for row in rows), "incomplete measured comparison")
    result = {"calls": calls, "successes": successes, "wall_seconds": seconds,
              "successful_calls_per_second": successes / seconds, "latency": latency(rows)}
    if cpu_key:
        cpu = sum(cell[cpu_key] if cpu_key != "cpu_ms_per_call" else cell[cpu_key] * cell["calls"] / 1000 for cell in cells)
        result.update(controller_cpu_seconds=cpu, controller_cpu_ms_per_success=cpu * 1000 / successes)
    return result


def contrasts(arms, left="baseline", right="candidate"):
    a, b = arms[left], arms[right]
    return {"throughput_change_percent": change(b["successful_calls_per_second"], a["successful_calls_per_second"]),
            "controller_cpu_per_success_change_percent": change(b["controller_cpu_ms_per_success"], a["controller_cpu_ms_per_success"]),
            "p95_change_percent": change(b["latency"]["p95_ms"], a["latency"]["p95_ms"]),
            "p99_change_percent": change(b["latency"]["p99_ms"], a["latency"]["p99_ms"])}


def native(package, identities):
    report = package.json(package.inputs["native"])
    need(report.get("passed") is True and report.get("complete") is True, "native series did not pass")
    need(report["qualifications"]["baseline"]["binary"]["sha256"] == identities["baseline"]["release_sha256"] and
         report["qualifications"]["candidate"]["binary"]["sha256"] == identities["candidate"]["release_sha256"], "native ELF mismatch")
    stages = report["stages"]
    need(len(stages) == 8 and all(stage["status"] == "passed" for stage in stages), "native stage set incomplete")
    file_stages = [stage for stage in stages if stage["kind"] == "file_abba"]
    need([s["arm"] for s in file_stages] == ["baseline", "candidate", "candidate", "baseline"], "native ABBA differs")
    raw = {}
    resources = []
    for stage in file_stages + [s for s in stages if s["kind"] == "soak"]:
        original = package.json(stage["output"] + "/report.json")
        rows = package.lines(stage["output"] + "/calls.jsonl")
        need(digest(package.read(stage["output"] + "/calls.jsonl")) == original["calls_sha256"], "native call journal binding differs")
        item = original["rounds"][0]
        need(original["complete"] and all(r["okay"] for r in rows), "native helper incomplete")
        raw[stage["name"]] = (item["cells"], [r for r in rows if r["phase"] == "measured"])
        resources.append({"stage": stage["name"], "arm": stage["arm"],
            "sampled_peaks": item["shutdown"]["resources"]["peaks"],
            "resource_error_count": len(item["shutdown"]["resources"].get("errors", [])),
            "whole_round_waited_process_tree_cpu_seconds": item["waited_process_tree_cpu_seconds"],
            "measured_calls": sum(c["calls"] for c in item["cells"]), "total_tool_calls": len(rows)})
    comparison = {}
    for concurrency in (1, 4, 8):
        arms = {}
        for arm in ("baseline", "candidate"):
            selected = [raw[s["name"]] for s in file_stages if s["arm"] == arm]
            cells = [c for cs, _ in selected for c in cs if c["concurrency"] == concurrency]
            rows = [r for _, rs in selected for r in rs if r["concurrency"] == concurrency]
            arms[arm] = aggregate(cells, rows, "success", "cpu_ms_per_call")
        comparison[str(concurrency)] = {**arms, **contrasts(arms)}
    soak = next(stage for stage in stages if stage["kind"] == "soak")
    soak_cells, soak_rows = raw[soak["name"]]
    return {"passed": True, "identities": identities, "file_abba": comparison,
            "soak": {"configured_seconds": 120, "helper_elapsed_seconds": soak["helper_elapsed_seconds"],
                     **aggregate(soak_cells, soak_rows, "success", "cpu_ms_per_call")},
            "round_resources": resources,
            "scope": "six immutable 44-48 byte files; file_info/binary_read; one short ABBA block; remote CPU excluded",
            "resource_scope": "whole controller rounds; RSS peaks are sampled, non-atomic tree aggregates; whole-round waited CPU includes warmup, negative cases and shutdown"}


def small(package, path):
    report = package.json(path)
    need(report["complete"] and report["comparison_valid"] and report["measured_attempted"] == 4096, "small archive incomplete")
    rows = package.lines(str(PurePosixPath(path).parent / "calls.jsonl"))
    need(digest(package.read(str(PurePosixPath(path).parent / "calls.jsonl"))) == report["calls_file"]["sha256"], "small journal mismatch")
    measured = [r for r in rows if r["purpose"] == "measured"]
    need(len(measured) == 4096 and all(r["okay"] for r in rows), "small coverage differs")
    arms = {}
    for arm in ("A", "B"):
        rr = [r for r in report["rounds"] if r["arm"] == arm]
        selected = [r for r in measured if r["arm"] == arm]
        cells = [{"calls": len(r["measured"]), "success": len(r["measured"]), "seconds": r["measured_wall_seconds"],
                  "cpu": r["measured_controller_cpu_seconds"]} for r in rr]
        arms[arm] = aggregate(cells, selected, "success", "cpu")
        arms[arm]["tools"] = {tool: latency([r for r in selected if r["tool"] == tool]) for tool in {r["tool"] for r in selected}}
        arms[arm]["original_wait4_max_rss_kib"] = [r["shutdown"]["waited"]["max_rss_kib"] for r in rr]
        arms[arm]["whole_round_wait4_cpu_seconds"] = sum(r["shutdown"]["waited"]["total_cpu_seconds"] for r in rr)
        arms[arm]["controller_cpu_tick_hz"] = [r["process_before_measured"]["cpu_tick_hz"] for r in rr]
    return {"passed": True, **arms, **contrasts(arms, "A", "B"),
            "scope": "64-record C1 hot small-archive native MCP guard; 1024 measured queries per fresh round"}


def reuse(package, identities):
    report = package.json(package.inputs["reuse"])
    need(report.get("passed") is True and report["real_ssh_execs"] == report["remote_effects"] == 0, "reuse comparison failed or not denied")
    rr = report["rounds"]
    need([r["arm"] for r in rr] == list("ABBA") and all(r["passed"] for r in rr), "reuse order/inventory differs")
    need(report["qualifications"]["A"]["binary"]["sha256"] == identities["baseline"]["release_sha256"] and
         report["qualifications"]["B"]["binary"]["sha256"] == identities["candidate"]["release_sha256"], "reuse ELF mismatch")
    raw = {r["round"]: package.lines(r["directory"] + "/events.jsonl.gz", compressed=True) for r in rr}
    need(all(row["okay"] for rows in raw.values() for row in rows), "failed original reuse/ping row")
    comparison = {}
    for concurrency in (1, 4, 8):
        comparison[str(concurrency)] = {}
        for phase in ("cold-six-originals", "warm"):
            name = f"C{concurrency}-{phase}"
            arms = {}
            for arm in ("A", "B"):
                chosen = [r for r in rr if r["arm"] == arm]
                phases = [p for r in chosen for cell in r["cells"] for p in cell["phases"] if p["phase"] == name]
                rows = [row for r in chosen for row in raw[r["round"]] if row["phase"] == name and row.get("kind") != "ping"]
                pings = [row for r in chosen for row in raw[r["round"]] if row["phase"] == name and row.get("kind") == "ping"]
                arms[arm] = aggregate(phases, rows, "successes", "controller_cpu_seconds")
                arms[arm]["ping_latency"] = latency(pings)
            comparison[str(concurrency)][phase] = {**arms, **contrasts(arms, "A", "B"),
                "ping_p95_change_percent": change(arms["B"]["ping_latency"]["p95_ms"], arms["A"]["ping_latency"]["p95_ms"]),
                "ping_p99_change_percent": change(arms["B"]["ping_latency"]["p99_ms"], arms["A"]["ping_latency"]["p99_ms"])}
    resources = [{"round": r["round"], "arm": r["arm"], "blocked_status_attempts": r["blocked_status_attempts"],
        "whole_round_wait4_cpu_seconds": r["shutdown"]["user_seconds"] + r["shutdown"]["system_seconds"],
        "original_wait4_maxrss_kib": r["shutdown"]["maxrss_kib"],
        "sampled_peaks": r["shutdown"]["resources"]["peaks"],
        "resource_error_count": r["shutdown"]["resources"]["error_count"],
        "resource_error_counts_by_field": r["shutdown"]["resources"]["error_counts_by_field"],
        "timeline_max_controller_threads": max((x["controller"]["threads"] for x in r["shutdown"]["resources"]["timeline"] if x["controller"]["threads"] is not None), default=None)} for r in rr]
    return {"passed": True, "identities": identities, "comparisons": comparison, "round_resources": resources,
            "scope": report["scope"], "real_ssh_execs": 0, "remote_effects": 0,
            "notes": ["C8 cold wave has six unique original keys and at most six simultaneous distinct requests",
                      "controller CPU is /proc own-process tick difference; deny-wrapper CPU excluded",
                      "round resource peaks accumulate for entire controller lifetime; not separate phase peaks",
                      "wait4 resources cover controller lifetime including initialization, ping and shutdown",
                      "100ms sampled tree metrics are non-atomic estimates, not strict lower bounds",
                      "latency p95/p99 are nearest rank over raw rows; cold p99 has only twelve request samples per arm/C"]}


def registry(package, identities, report_path):
    summary = package.json(report_path)
    need(summary["success"] and summary["samples"] == 16 and summary["failed_samples"] == 0, "registry ABBA incomplete")
    need(summary["blocks"] == 4 and summary["order"] == "ABBA" and summary["retries"] == 0,
         "registry scope differs from four blocks without retries")
    need(all(summary["variants"][arm]["sha256"] == identities[arm]["library_test_sha256"]
             for arm in ("baseline", "candidate")), "registry test ELF differs")
    rows = package.lines(str(PurePosixPath(report_path).parent / "samples.jsonl"))
    need(len(rows) == 16 and all(r["success"] and r["attempt"] == 1 for r in rows), "registry raw sample failure/retry")
    need([r["variant"] for r in rows] == ["baseline", "candidate", "candidate", "baseline"] * 4, "registry order differs")
    need(all(r["binary_sha256"] == identities[r["variant"]]["library_test_sha256"]
             and r["sample"] == index + 1 and r["block"] == index // 4 + 1
             and r["position"] == index % 4 + 1 for index, r in enumerate(rows)),
         "registry per-sample identity/order differs")
    metrics = {}
    for field in ("cold_lookup_ms", "hot_reuse_ms", "legacy_sorted_median_ms", "streamed_median_ms"):
        arms = {arm: [r["metrics"][field] for r in rows if r["variant"] == arm] for arm in ("baseline", "candidate")}
        need(all(math.isfinite(x) and x > 0 for xs in arms.values() for x in xs), "invalid registry metric")
        medians = {arm: statistics.median(xs) for arm, xs in arms.items()}
        for arm in arms:
            need(medians[arm] == summary["per_variant"][arm][field]["median"], "registry median differs")
            need(arms[arm] == summary["per_variant"][arm][field]["samples"], "registry summary/raw samples differ")
        metrics[field] = {"samples": arms, "medians": medians, "median_change_percent": change(medians["candidate"], medians["baseline"]),
                         "paired_block_ratios": [statistics.mean(r["metrics"][field] for r in rows if r["block"] == block and r["variant"] == "candidate") /
                                                  statistics.mean(r["metrics"][field] for r in rows if r["block"] == block and r["variant"] == "baseline") for block in range(1, 5)]}
    return {"passed": True, "identities": identities, "source_report": report_path,
            "process_samples": 16, "metrics": metrics, "scope": summary["scope"],
            "notes": [summary["cold_definition"], summary["internal_samples"], "No discarded or retried sample; eight process samples per binary"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-label", default="A62", help="human-readable baseline version")
    parser.add_argument("--candidate-label", default="R2", help="human-readable candidate version")
    parser.add_argument("--baseline-elf-sha256", default=BASELINE,
                        help="explicit qualified baseline release SHA")
    parser.add_argument("--baseline-test-sha256", default=BASELINE_TEST,
                        help="explicit qualified baseline library-test SHA")
    parser.add_argument("--candidate-elf-sha256", default=CANDIDATE,
                        help="explicit qualified candidate release SHA; defaults to R2")
    parser.add_argument("--candidate-test-sha256", default=CANDIDATE_TEST,
                        help="explicit qualified candidate library-test SHA; defaults to R2")
    parser.add_argument("--registry-baseline-label", help="override label for a direct registry baseline")
    parser.add_argument("--registry-baseline-test-sha256", help="override SHA for a direct registry baseline")
    parser.add_argument("--registry-candidate-label", help="override label for a direct registry candidate")
    parser.add_argument("--registry-candidate-test-sha256", help="override SHA for a direct registry candidate")
    parser.add_argument("--registry-report", help="original registry report path within this package; defaults to manifest input")
    parser.add_argument("--sections", nargs="+", choices=("native", "reuse", "registry"),
                        help="analyze only these sections; default is every available section")
    args = parser.parse_args()
    identities = {arm: {"label": getattr(args, arm + "_label"),
                        "release_sha256": getattr(args, arm + "_elf_sha256"),
                        "library_test_sha256": getattr(args, arm + "_test_sha256")}
                  for arm in ("baseline", "candidate")}
    registry_identities = {arm: {"label": getattr(args, "registry_" + arm + "_label") or identities[arm]["label"],
                                 "library_test_sha256": getattr(args, "registry_" + arm + "_test_sha256") or identities[arm]["library_test_sha256"]}
                           for arm in ("baseline", "candidate")}
    for arm in ("baseline", "candidate"):
        need(bool(getattr(args, "registry_" + arm + "_label")) == bool(getattr(args, "registry_" + arm + "_test_sha256")),
             "registry override requires both explicit label and test SHA")
    need(all(len(value) == 64 and set(value) <= set("0123456789abcdef")
             for identity in list(identities.values()) + list(registry_identities.values())
             for field, value in identity.items() if field.endswith("sha256")), "invalid explicit binary digest")
    need(all(identity["label"].strip() for identity in list(identities.values()) + list(registry_identities.values())),
         "empty version label")
    for identity in list(identities.values()) + list(registry_identities.values()):
        known = KNOWN_IDENTITIES.get(identity["label"])
        need(not known or all(value == known[field] for field, value in identity.items() if field.endswith("sha256")),
             "known version label and explicit SHA disagree")
    package = Package(args.manifest, args.archive)
    registry_report = args.registry_report or package.inputs.get("registry")
    available = {name for name in ("native", "reuse") if name in package.inputs}
    if registry_report:
        need(registry_report in package.files, "registry report is not a verified original member")
        available.add("registry")
    selected = set(args.sections) if args.sections else available
    need(selected and selected <= available, "selected section absent from evidence")
    result = {"schema": "hepta-x230-independent-numeric-review/v2", "archive_sha256": package.manifest["archive"]["sha256"],
              "analyzer_sha256": digest(Path(__file__).read_bytes()),
              "native_reuse_identities": identities if selected & {"native", "reuse"} else None,
              "registry_identities": registry_identities if "registry" in selected else None,
              "comparison_design": "within each original experiment only; separate sessions are not paired contrasts",
              "quantiles": "median p50; nearest rank p95/p99; raw pooled call rows", "sections": {}}
    for name, fn in (("native", native), ("reuse", reuse)):
        if name in selected:
            result["sections"][name] = fn(package, identities)
    if "registry" in selected:
        result["sections"]["registry"] = registry(package, registry_identities, registry_report)
    if "native" in selected:
        native_report = package.json(package.inputs["native"])
        stage = next(s for s in native_report["stages"] if s["kind"] == "small")
        result["sections"]["small_archive"] = small(package, stage["output"] + "/report.json")
        result["sections"]["small_archive"]["identities"] = identities
    result["consumed_originals"] = package.consumed
    result["complete"] = True
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"output": str(args.output), "sections": list(result["sections"]), "consumed_original_files": len(package.consumed)}))


if __name__ == "__main__":
    main()
