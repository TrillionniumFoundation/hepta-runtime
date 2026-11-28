#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind original native execution observations to independently admitted tools.

Frozen Git source F and its distribution D select the initial entry. Native
construction receipts then select the cold/post entries and the release entry.
No execution receipt chooses its own trusted path, executable or arguments.
"""
from __future__ import annotations

from hashlib import sha256
import importlib.util
from pathlib import Path
import stat
import struct


SPEC = importlib.util.spec_from_file_location(
    "selected_runtime_bootstrap_distribution", Path(__file__).with_name("hia_native_bootstrap_distribution.py"))
distribution_reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(distribution_reader)
custody = distribution_reader.custody
observer = custody.native_execution_observer()
MIB = 1024 * 1024


def recipe_layout(hepta, name, sources):
    """Read the frozen native recipe's own stage and publication boundaries."""
    authority_name = "examples/hia_bootstrap/cold_build_sources.hiadat"
    custody.require(name in sources and authority_name in sources, "native recipe is outside frozen source custody")
    authority = custody.ordinary_bytes(hepta / authority_name, MIB)
    custody.require(sha256(authority).hexdigest() == sources[authority_name],
                    "native recipe authority changed after frozen source admission")
    custody.require(len(authority) >= 32 and authority[:8] == b"HIATBS01"
                    and struct.unpack_from("<3Q", authority, 8) == (1, len(sources), 0),
                    "native recipe authority differs from the frozen source count")
    paths, cursor = [], 32
    for _ in sources:
        custody.require(cursor + 8 <= len(authority), "native recipe authority is truncated")
        size, = struct.unpack_from("<Q", authority, cursor)
        cursor += 8
        extent = size + (-size) % 8
        custody.require(1 <= size <= 4095 and cursor + extent <= len(authority)
                        and not any(authority[cursor + size:cursor + extent]),
                        "native recipe authority has an invalid path extent")
        path = authority[cursor:cursor + size].decode("ascii")
        distribution_reader.relative_name(path)
        paths.append(path)
        cursor += extent
    custody.require(cursor == len(authority) and paths == sorted(sources),
                    "native recipe authority differs from the complete frozen source")
    raw = custody.ordinary_bytes(hepta / name, 2 * MIB)
    custody.require(sha256(raw).hexdigest() == sources[name], "native construction recipe changed after source admission")
    custody.require(len(raw) >= 128 and raw[:8] == b"HIATBR01", "native construction recipe has an invalid header")
    words = struct.unpack_from("<16Q", raw)
    _, version, stages, bindings, publications, count, stage_at, binding_at, publication_at, extent, *reserved = words
    custody.require(version == 1 and 1 <= stages <= 64 and stages * 2 <= bindings <= 4096
                    and 1 <= publications <= 4096 and count == len(sources) and not any(reserved)
                    and stage_at == 128 and binding_at == stage_at + stages * 64
                    and publication_at == binding_at + bindings * 128
                    and extent == len(raw) == publication_at + publications * 320,
                    "native construction recipe has invalid counts or offsets")
    stage_rows, next_binding, next_publication = [], 0, 0
    for index in range(stages):
        row = struct.unpack_from("<8Q", raw, stage_at + index * 64)
        custody.require(row[0] == index and row[1] < len(paths)
                        and row[2] == next_binding and 2 <= row[3] <= 64
                        and row[4] == next_publication and row[5] > 0 and row[6:] == (0, 0),
                        "native construction recipe stage inventory is inconsistent")
        next_binding += row[3]
        next_publication += row[5]
        stage_rows.append({"id": index, "plan": paths[row[1]]})
    custody.require((next_binding, next_publication) == (bindings, publications),
                    "native construction recipe stages do not cover their records")
    installed = {}
    for index in range(publications):
        at = publication_at + index * 320
        size, path_size, mode, flag, maximum, *reserved = struct.unpack_from("<8Q", raw, at)
        custody.require(1 <= size <= 63 and path_size <= 191 and mode in (0o400, 0o500)
                        and flag in (0, 1) and maximum <= 64 * MIB and not any(reserved)
                        and not any(raw[at + 64 + size:at + 128])
                        and not any(raw[at + 128 + path_size:at + 320]),
                        "native construction publication has invalid bounds or mode")
        distribution_reader.relative_name(raw[at + 64:at + 64 + size].decode("ascii"))
        if flag:
            path = raw[at + 128:at + 128 + path_size].decode("ascii")
            distribution_reader.relative_name(path)
            custody.require(path not in installed, "native construction publication repeats a path")
            installed[path] = {"mode": mode, "maximum": maximum}
        else:
            custody.require(path_size == 0, "private native publication declares an installed path")
    custody.require(bool(installed), "native construction recipe has no installed outputs")
    return stage_rows, installed


def admit_construction(hepta, output, sources, *, magic, recipe):
    """Read physical stage journals and source/tool manifests bound by stdout."""
    stages, installed = recipe_layout(hepta, recipe, sources)
    receipt_path = output / "build.receipt"
    receipt = custody.ordinary_bytes(receipt_path, 128)
    custody.require(len(receipt) == 128 and receipt[:8] == magic,
                    "native construction receipt belongs to another domain")
    source_raw = custody.ordinary_bytes(output / "source.manifest.hiasxm", MIB)
    tool_raw = custody.ordinary_bytes(output / "toolchain.manifest.hiasxm", MIB)
    custody.require(struct.unpack_from("<7Q", receipt, 8)
                    == (1, len(stages), len(sources), len(installed), len(source_raw), len(tool_raw), 0)
                    and receipt[64:96] == sha256(source_raw).digest()
                    and receipt[96:128] == sha256(tool_raw).digest(),
                    "native construction receipt does not bind its exact recipe and manifests")
    source_rows = custody.native_file_manifest(source_raw)
    custody.require(source_rows == {name: {"bytes": (hepta / name).stat().st_size, "sha256": pin}
                                   for name, pin in sources.items()},
                    "native construction source manifest differs from frozen F")
    tools = custody.native_file_manifest(tool_raw)
    custody.require(set(tools) == set(installed), "native construction tool inventory differs from its frozen recipe")
    for name, row in tools.items():
        path = output / name
        raw = custody.ordinary_bytes(path, installed[name]["maximum"])
        custody.require(len(raw) == row["bytes"] and sha256(raw).hexdigest() == row["sha256"]
                        and stat.S_IMODE(path.stat().st_mode) == installed[name]["mode"],
                        "native construction output differs from its bound manifest: " + name)
    evidence = []
    for stage in stages:
        plan = custody.ordinary_bytes(hepta / stage["plan"], 64 * MIB)
        custody.require(sha256(plan).hexdigest() == sources[stage["plan"]],
                        "native construction plan changed after source admission")
        custody.require(len(plan) >= 32 and plan[:8] == b"HIAQPL01", "native construction plan has an invalid header")
        nodes, = struct.unpack_from("<Q", plan, 8)
        directory = output / "build-evidence" / ("s" + str(stage["id"]))
        driver = custody.ordinary_bytes(directory / "driver.receipt", 64)
        journal = observer.pin(directory / "evidence.hiaqj")
        custody.require(len(driver) == 64 and driver[:8] == b"HIAQOK01"
                        and struct.unpack_from("<3Q", driver, 8) == (nodes, len(plan), journal["bytes"])
                        and driver[32:].hex() == journal["sha256"],
                        "native construction stage receipt differs from its physical plan or journal")
        evidence.append({**stage, "nodes": nodes, "plan": observer.pin(hepta / stage["plan"]),
                         "receipt": {"bytes": len(driver), "sha256": sha256(driver).hexdigest()}, "journal": journal})
    return tools, {"receipt": observer.pin(receipt_path), "source_manifest": observer.pin(output / "source.manifest.hiasxm"),
                   "tool_manifest": observer.pin(output / "toolchain.manifest.hiasxm"), "stages": evidence,
                   "tools": tools}


def admit_chain(*, hepta, source, distribution, distribution_commit, staging, toolchain,
                prebuild_execution, cold_report, cold_execution, post, post_execution,
                release_execution=None, release_package=None, release_receipt=None):
    """Select all four entries/argv from F/D and native predecessor products."""
    custody.require(all(value is not None for value in (hepta, source, distribution, distribution_commit,
                    staging, toolchain, prebuild_execution, cold_report, cold_execution, post, post_execution)),
                    "native qualification requires its complete distribution and prebuild execution chain")
    hepta, distribution, staging, toolchain, post = (
        Path(value).absolute() for value in (hepta, distribution, staging, toolchain, post))
    cold_report = Path(cold_report).absolute()
    cold = cold_report.parent
    binding, sources = distribution_reader.admit_staged_distribution(
        hepta, distribution, source, distribution_commit, staging)
    source_path, roots = staging / "source", staging / "bootstrap"
    entry = staging / distribution_reader.ENTRY
    entry_pin = {key: binding["executables"][distribution_reader.ENTRY][key] for key in ("bytes", "sha256")}
    result = {"distribution": binding,
        "prebuild": observer.admit_execution(prebuild_execution, source=source, stage="prebuild",
            expected_argv=[str(entry), "--source", str(source_path), "--bootstrap", str(roots), "--output", str(toolchain)],
            expected_entry=entry_pin, expected_result=toolchain / "build.receipt",
            owner_receipt=toolchain / "process-owner.receipt")}
    pre_tools, result["prebuild_products"] = admit_construction(hepta, toolchain, sources,
        magic=b"HIATBOK1", recipe="examples/hia_bootstrap/cold_build_recipe.hiadat")
    custody.require({"hia-cold", "hia-source-bootstrap", "hia-cold-build", "cold-bundle.hiadat"} <= pre_tools.keys(),
                    "native prebuild does not publish its required successor entries")
    for name in (*distribution_reader.ROOT_NAMES, distribution_reader.ENTRY):
        custody.require(pre_tools.get(name) == {key: binding["executables"][name][key] for key in ("bytes", "sha256")},
                        "native prebuild did not reconstruct the admitted initial root or entry: " + name)
    result["cold"] = observer.admit_execution(cold_execution, source=source, stage="cold",
        expected_argv=[str(toolchain / "hia-cold"), "--source", str(source_path), "--output", str(cold),
                       "--toolchain", str(toolchain), "--bundle", str(toolchain / "cold-bundle.hiadat")],
        expected_entry=pre_tools["hia-cold"], expected_result=cold_report,
        owner_receipt=cold / "process-owner.receipt")
    result["post"] = observer.admit_execution(post_execution, source=source, stage="post",
        expected_argv=[str(toolchain / "hia-source-bootstrap"), "--source", str(source_path), "--cold", str(cold),
                       "--bootstrap", str(roots), "--output", str(post)],
        expected_entry=pre_tools["hia-source-bootstrap"], expected_result=post / "build.receipt",
        owner_receipt=post / "process-owner.receipt")
    post_tools, result["post_products"] = admit_construction(hepta, post, sources,
        magic=b"HIASBOK1", recipe="examples/hia_bootstrap/cold_source_bootstrap_recipe.hiadat")
    custody.require(post_tools.get("hia-source-bootstrap") == pre_tools["hia-source-bootstrap"]
                    and "hia-release-build" in post_tools,
                    "native post-cold products do not preserve their entry or release successor")
    release_inputs = (release_execution, release_package, release_receipt)
    custody.require(all(value is not None for value in release_inputs) or all(value is None for value in release_inputs),
                    "native release execution requires its package and original stdout receipt")
    if release_execution is not None:
        release_execution, release_package, release_receipt = (Path(value).absolute() for value in release_inputs)
        custody.require(release_package.name == "store.hiapack" and release_receipt == release_execution / "stdout",
                        "native release paths do not select its original published output")
        result["release"] = observer.admit_execution(release_execution, source=source, stage="release",
            expected_argv=[str(post / "hia-release-build"), "--output", str(release_package.parent),
                           "--compiler", str(cold / "qualification/base/B3.flat"), "--cold-report", str(cold_report),
                           "--source", str(source_path), "--timeout-seconds", "1800"],
            expected_entry=post_tools["hia-release-build"])
    return result
