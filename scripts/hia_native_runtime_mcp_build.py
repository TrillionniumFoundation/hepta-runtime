"""Build the current fixed public HIA stdio executable from one source checkout.

The default build includes 130 direct HIA members, the exact eight-member
shared worker capability, and thirty-three native I/O dependency image instances plus four additional
full-catalog HIA images inside the retained-catalog capability. It needs no existing worker or public binary. The
previous 58/91/102 graph qualifications keep their explicit frozen source views.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from public_nine_build import (MEMBERS, EXTRA, BASE, BOUNDARIES, FIXTURE_BOUNDARIES,
    TRANSPORT, VIEW, CONFIG, CONFIG_SYMBOLS, FENCE, FALSE_FLAGS, adapter_source,
    source_check, build_runtime_mcp, PORT_PACKAGE_SHA256)

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
WORKER_SOURCE_SHA256 = "6b5983d351b380b53f5838dc7ca8adac523d6c95ac12df51c3f975faf60d53c2"
B3_SHA256 = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"


def require(value, message):
    if not value:
        raise ValueError(message)


def put(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def run_build_step(output, label, command):
    """Retain process output; each builder keeps its existing inner deadlines.

    This wrapper deliberately adds no process-group timeout: the inner native
    compiler/packer processes have their own session ownership and limits. CI
    retains the unchanged 15-minute overall job deadline.
    """
    folder = output / "processes"
    folder.mkdir(exist_ok=True)
    started = time.monotonic()
    result = {"command": command, "status": "RUNNING"}
    put(folder / (label + ".json"), result)
    try:
        with (folder / (label + ".stdout")).open("xb") as stdout, (folder / (label + ".stderr")).open("xb") as stderr:
            process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, check=False)
        result.update(returncode=process.returncode, status="PASS" if process.returncode == 0 else "FAIL")
        require(process.returncode == 0, "source dependency build failed: " + label)
    except BaseException as exc:
        result.update(status="FAIL", error=repr(exc))
        raise
    finally:
        result["elapsed_seconds"] = time.monotonic() - started
        put(folder / (label + ".json"), result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    for name in ("hepta", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--bootstrap", type=Path)
    parser.add_argument("--reuse-manifests", type=Path)
    args = parser.parse_args()
    source, hepta, output = args.source.resolve(strict=True), args.hepta.resolve(strict=True), args.output.absolute()
    require(sys.version_info[:2] == (3, 14), "Qualified Python authoring requires CPython 3.14.")
    require(source == ROOT, "Invoke the default builder from the source checkout being built.")
    require(not output.exists(), "Build output must be fresh.")
    source_identity = source_check(source)
    if os.environ.get("CI") != "true":
        require(args.bootstrap is not None, "Local builds require an already verified B3 copy.")
    if args.bootstrap is not None:
        require(SHA((args.bootstrap / "B3.image.bin").read_bytes()) == B3_SHA256, "Verified B3 bytes differ.")
    output.mkdir(parents=True)
    started = time.monotonic()
    report = dict(schema="hepta.runtime.public175-io-audit-routes.build.v1", status="RUNNING",
        source_binding_sha256=source_identity["manifest_sha256"], rust_executed=False,
        actual_target_handshake_compared=False, full_async_runtime_qualified=False,
        full_sdk_qualified=False, independent_cold_qualified=False, production_activated=False,
        old_path_removed=False, default_public_entrypoint=True,
        dependency_sources="runtime_support/bellman_port")

    def save():
        report["elapsed_seconds"] = time.monotonic() - started
        put(output / "BUILD.json", report)

    save()
    try:
        require(len(MEMBERS) == 130 and len(EXTRA) == 83, "Fixed combined graph count changed.")
        require(EXTRA[47:53] == ["batch_gateway", "batch_params", "batch_call", "batch_adapter", "batch_input", None]
                and EXTRA[53:59] == ["target_shutdown", "current_get_info", "target_connection", None, None, "request_tasks"]
                and EXTRA[59:64] == ["extract_gateway", "extract_params", "extract_call", "extract_adapter", None]
                and EXTRA[64:69] == ["publisher_gateway", "publisher_params", "publisher_call", None, None]
                and EXTRA[69:71] == ["binary_write_params", "binary_call_plan"]
                and EXTRA[71:73] == ["file_info_params", "binary_read_params"]
                and EXTRA[73:] == ["read_gateway", "read_ssh", "multi_read_params", "multi_read_plan",
                    "read_result", "read_wire", "read_bootstrap", "read_helpers", "read_serde_error", "jobs_audit"],
                "Fixed Batch/SDK descriptor bindings changed.")
        package = source / "runtime_support/bellman_port"
        require(SHA((package / "PACKAGE.json").read_bytes()) == PORT_PACKAGE_SHA256, "Fixed dependency package changed.")
        python = [sys.executable, "-I", "-S", "-B"]
        worker_command = python + [str(package / "worker-source/tests/hia_native/blocking_worker/worker_build.py"),
            "--source-root", str(package / "worker-source"), "--hepta", str(hepta),
            "--capture", str(output / "worker"), "--source-pins-sha256", WORKER_SOURCE_SHA256]
        if args.bootstrap is not None:
            worker_command += ["--bootstrap-cache", str(args.bootstrap.resolve(strict=True))]
        worker_process = run_build_step(output, "worker", worker_command)
        port_process = run_build_step(output, "port", python + [str(package / "recipe/build_capability.py"),
            "--package", str(package), "--hepta", str(hepta), "--worker-build", str(output / "worker"),
            "--output", str(output / "port"), "--package-sha256", PORT_PACKAGE_SHA256])
        shutil.copytree(output / "worker/build/bootstrap", output / "build/bootstrap")
        reuse = json.loads(args.reuse_manifests.resolve(strict=True).read_bytes()) if args.reuse_manifests else {}
        require(set(reuse).issubset({name for name, _, _ in MEMBERS}), "Unexpected direct member reuse.")
        put(output / "reuse.json", reuse)
        manifest = build_runtime_mcp(hepta, output / "build", name="public-task-batch-extract", source_root=source,
            manifests=reuse or None, bellman_port_build=output / "port/build-v3",
            bellman_port_package=package, bellman_worker_build=output / "worker")
        raw = manifest.read_bytes()
        md = json.loads(raw)
        require(md["physical_images"] == 133 and len(md["members"]) == 130 and md["runtime_hia_images"] == 175,
                "Combined physical or HIA count changed.")
        fresh = sum(row["fresh_compile"] is True for row in md["members"])
        require(fresh == 130 - len(reuse), "Direct member compile/reuse count changed.")
        binary = manifest.parent / md["elf"]
        require(SHA(binary.read_bytes()) == md["elf_sha256"], "Actual public binary identity changed.")
        report.update(status="NATIVE_BUILD_PASS", physical_images=133, runtime_hia_images=175,
            direct_hia_members=130, packed_hia_members=8, manifest=str(manifest),
            manifest_sha256=SHA(raw), elf=str(binary), elf_bytes=binary.stat().st_size,
            elf_sha256=md["elf_sha256"], fresh_member_compiles=fresh, checked_reused_members=len(reuse),
            fresh_packed_member_compiles=8, bootstrap_reused=args.bootstrap is not None,
            fresh_hia_link_and_pack=True, dependency_processes={"worker": worker_process, "port": port_process},
            target_get_info_integrated=True, target_serial_async_rw_framing_integrated=True,
            target_connection_lifecycle_integrated=True, target_connection_slot=55,
            serial_session_authority_integrated=True, authority_slot=56, batch_slots=[47,48,49,50,51,52],
            bellman_port_slot=57, sdk_request_registry_slot=58, task_event_pump_integrated=True,
            extract_slots=[59,60,61,62,63], extract_context_offset=456, extract_install_offset=464,
            binary_write_params_slot=69, binary_call_plan_slot=70, public_binary_write_registered=True,
            jobs_audit_slot=82, jobs_audit_native_integrated=True, jobs_audit_public_qualified=False,
            file_info_params_slot=71, binary_read_params_slot=72, configured_ssh_target_operation=10,
            public_read_routes_qualified=False,
            publication_slots=[64,65,66,67,68], publication_callable_context="descriptor67+8",
            publication_scope_forget_slot=68, publication_full_async_qualified=False,
            extract_shared_hub_offset=400, extract_local_body_integrated=True,
            extract_public_handler_qualified=False, extract_full_async_qualified=False,
            extract_remote_qualified=False, extract_catalog_policy_qualified=False,
            ordinary_notification_drops_handler_future=False, target_eof_policy_owner=58,
            historical_shutdown_owner53_retained=True, authority_public_handler_comparison=False,
            request_audit_integrated=False, annotation_integrated=False,
            authority_concurrent_binding_qualified=False, combined_graph_semantics_qualified=False)
    except BaseException as exc:
        report.update(status="FAIL", error=repr(exc))
        raise
    finally:
        save()
    print(json.dumps(report, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
