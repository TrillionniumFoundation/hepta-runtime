"""Build and verify the fixed HIA workdir caller without a host runtime.

Python is an explicit build/evidence driver. The resulting ELF executes the
21 HIA modules and the fixed kernel boundary. Public SDK routing and remote
filesystem execution remain separately qualified dependencies.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_build as native_build
import hia_native_effect_fence_build as evidence_build
from hia_native_build import ABI, BUFFER_PROFILES, NativeBuild, json_bytes, write_new
from hia_native_effect_fence_build import COMPILE_FILES, OBSERVER_FIELDS, receipt, process_stdout, verify_sha_import

PROFILE = 'native/workdir_service_profile.json'
PROFILE_SHA256 = 'a05664077035f297a14768462d47e21a585f95d2d85643281954411b0aeebc3b'
COMPILER = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
B3 = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
ELF = 'cb35cc75dc4f8c2b71ffb7d965a59563f468058f33183a46ed12f0a340488f22'
ELF_BYTES = 5483867
MEMBER_COUNT = 21
FRAME_MAGIC = b'HMWDPK02'
MEMBER_NAMES = ['owner', 'fs', 'json', 'validation', 'identity', 'policy', 'canonical', 'context', 'state', 'value', 'client', 'caller', 'params', 'path', 'raw_canonical', 'regex_syntax', 'regex_unicode_data', 'regex_hir', 'regex_nfa', 'regex_match', 'regex_controller']
PARTS = {'scripts/session_request_adapter.S': 'original_context_adapter_sha256', 'scripts/local_canonical_adapter.S': 'raw_canonical_adapter_sha256', 'scripts/workdir_routes.S': 'routing_source_sha256', 'scripts/workdir_validation_resume.S': 'regex_wrapper_sha256', 'scripts/workdir_regex_subtree.S': 'regex_subtree_sha256'}
HELPERS = ('scripts/hia_native_build.py', 'scripts/hia_native_loader.py', 'scripts/hia_native_effect_fence_build.py', 'scripts/hia_native_workdir_pack_child.py', 'scripts/hia_native_workdir_service_build.py')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def file(root, name):
    require(type(name) is str and name and not Path(name).is_absolute()
            and all(p not in ("", ".", "..") for p in name.split("/")),
            "workdir artifact path is not relative")
    root = Path(root).resolve(strict=True)
    path = root
    for part in name.split("/"):
        path = path / part
        require(not path.is_symlink(), "workdir artifact contains a symlink")
    require(stat.S_ISREG(path.lstat().st_mode), "workdir artifact is not regular")
    return path


def module_evidence(path, source, build, profile_name):
    data = json.loads(path.read_bytes())
    actual_source = file(path.parent, data.get("source")).read_bytes()
    image = file(path.parent, data.get("image")).read_bytes()
    require(profile_name in BUFFER_PROFILES, "workdir module profile is unknown")
    icap, ocap, wcap = BUFFER_PROFILES[profile_name]
    expected = dict(schema="hepta.runtime.native-module.v1", abi=ABI, target="linux-x86_64",
        compiler_commit=build.identity["commit"], compiler_sha256=build.compiler_sha256,
        source_sha256=sha(source), image_sha256=sha(image), input_capacity=icap,
        output_capacity=ocap, workspace_capacity=wcap, qualification="development_fixed_point", standalone=None)
    require(actual_source == source and all(data.get(k) == v for k, v in expected.items())
            and (("buffer_profile" not in data) if profile_name == "standard"
                 else data.get("buffer_profile") == profile_name)
            and 0 < len(image) <= 1 << 20 and not image.startswith(b"\x7fELF"),
            "workdir compiled module differs")
    records = {name: file(path.parent, name).read_bytes() for name in COMPILE_FILES}
    build_data = json.loads(records["build.json"])
    report = json.loads(records["module.receipt.json"])
    require(build_data.get("compiler_dependency") == build.identity
            and build_data.get("compile_receipt") == report
            and build_data.get("whole_runtime_replaced") is False,
            "workdir compiler source custody differs")
    require(report.get("runner_sha256") == build.identity["files"]["tools/hia_selfhost_child.py"]
            and records["module.input.bin"] == source
            and records["module.stderr.log"] == b""
            and len(records["module.output.bin"]) == 1 << 20,
            "workdir native compiler process differs")
    receipt(report, source, records["module.output.bin"], image, build.compiler_sha256)
    require(report.get("produced_bytes") == len(image) and report.get("produced_sha256") == sha(image)
            and report.get("source_sha256") == sha(source), "workdir compiler output differs")
    process_stdout(report, records["module.stdout.log"], capacity=1 << 20, workspace=1 << 20)
    request = json.loads(records["module.request.json"])
    require(request.get("format") == "flat-x86-64"
            and request.get("image_sha256") == build.compiler_sha256
            and request.get("source_sha256") == sha(source)
            and request.get("capacity") == 1 << 20 and request.get("workspace_size") == 1 << 20,
            "workdir compiler invocation differs")
    return data, image, {name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in records.items()}


def runtime_pack_stdout(report, raw, manifest_sha, loader_sha):
    value = json.loads(raw)
    fields = OBSERVER_FIELDS | {'manifest_sha256', 'loader_sha256',
        'borrowed_buffer_canaries_unchanged', 'native_profile'}
    require(type(value) is dict and set(value) == fields
            and json_bytes(value) == json_bytes({k: report.get(k) for k in fields})
            and value['manifest_sha256'] == manifest_sha and value['loader_sha256'] == loader_sha
            and value['source_unchanged'] is True and value['output_unchanged'] is False
            and value['borrowed_buffer_canaries_unchanged'] is True and value['native_profile'] == 'standard'
            and value['source_sha256'] == report.get('input_sha256')
            and value['image_sha256'] == report.get('artifact_sha256')
            and value['return_encoding'] == 'zero-extended-u32'
            and type(value['native_elapsed_ns']) is int and value['native_elapsed_ns'] >= 0
            and value['loader_operations'] == 'copy; sealed RX native runtime module; fixed ABI call',
            'workdir runtime packing observer differs')
    require(json_bytes(value['limits']) == json_bytes(dict(cpu_seconds=10, address_bytes=256 << 20,
            core_dumpable=False, stack_bytes=8 << 20, file_bytes=16 << 20, open_files=32,
            input_capacity=8 << 20, output_capacity=ELF_BYTES, workspace_bytes=4096)),
            'workdir runtime pack fixed limits differ')
    header = value['workspace_header']
    require(type(header) is dict and set(header) == {str(i) for i in
            (0, 8, 16, 24, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 224, 248, 1024)}
            and all(type(x) is int and 0 <= x < 1 << 64 for x in header.values()),
            'workdir runtime pack workspace differs')


def runtime_pack(destination, module, frame, source_root):
    label = 'service-pack'
    child = file(source_root, 'scripts/hia_native_workdir_pack_child.py')
    loader = file(source_root, 'scripts/hia_native_loader.py')
    manifest = json.loads(module.read_bytes())
    child_sha, loader_sha = sha(child.read_bytes()), sha(loader.read_bytes())
    wire, output, request_path = [destination / (label + suffix)
                                  for suffix in ('.input.bin', '.output.bin', '.request.json')]
    request = dict(format='flat-x86-64', manifest=str(module.resolve()),
        manifest_sha256=sha(module.read_bytes()), image_sha256=manifest['image_sha256'],
        source=str(wire.resolve()), source_sha256=sha(frame), capacity=ELF_BYTES,
        workspace_size=4096, output=str(output.resolve()), loader_sha256=loader_sha)
    write_new(wire, frame); write_new(request_path, json_bytes(request))
    started = time.monotonic_ns()
    process = subprocess.Popen([sys.executable, '-I', '-S', '-B', str(child), str(request_path)],
        cwd=destination, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill(); stdout, stderr = process.communicate()
    write_new(destination / (label + '.stdout.log'), stdout)
    write_new(destination / (label + '.stderr.log'), stderr)
    report = (dict(status='timeout', wall_limit_seconds=20) if timed_out else
              dict(status='child_failed') if process.returncode else json.loads(stdout))
    report.update(case=label, input_sha256=sha(frame), input_bytes=len(frame),
        artifact_sha256=manifest['image_sha256'], format='flat-x86-64', runner_sha256=child_sha,
        wall_elapsed_ns=time.monotonic_ns() - started,
        completed_process=dict(pid=process.pid, exit_code=process.returncode, reaped=True,
            timed_out=timed_out, timeout_seconds=20))
    write_new(destination / (label + '.receipt.json'), json_bytes(report))
    require(sha(child.read_bytes()) == child_sha and sha(loader.read_bytes()) == loader_sha
            and sha(module.read_bytes()) == request['manifest_sha256'],
            'workdir runtime packing observer inputs changed')
    return report, output.read_bytes() if output.exists() else b''


def run_evidence(destination, label, frame, image, expected, build, source_root):
    output = file(destination, label + ".output.bin").read_bytes()
    report = json.loads(file(destination, label + ".receipt.json").read_bytes())
    request = json.loads(file(destination, label + ".request.json").read_bytes())
    require(file(destination, label + ".input.bin").read_bytes() == frame
            and file(destination, label + ".stderr.log").read_bytes() == b""
            and len(output) == len(expected) and output == expected,
            "workdir actual packer process files differ")
    receipt(report, frame, output, expected, sha(image))
    require(request.get("format") == "flat-x86-64"
            and request.get("image_sha256") == sha(image)
            and request.get("source_sha256") == sha(frame)
            and request.get("capacity") == len(expected) and request.get("workspace_size") == 4096,
            "workdir native packer invocation differs")
    stdout = file(destination, label + '.stdout.log').read_bytes()
    if label == 'service-pack':
        require(report.get('runner_sha256') == sha(file(source_root, 'scripts/hia_native_workdir_pack_child.py').read_bytes())
                and request.get('manifest_sha256') == sha(file(destination, 'packer/manifest.json').read_bytes())
                and request.get('loader_sha256') == sha(file(source_root, 'scripts/hia_native_loader.py').read_bytes()),
                'workdir runtime pack source or module differs')
        process = report.get('completed_process', {})
        require(type(process.get('pid')) is int and process['pid'] > 0
                and process.get('exit_code') == 0 and process.get('reaped') is True
                and process.get('timed_out') is False and process.get('timeout_seconds') == 20,
                'workdir runtime pack process did not complete')
        runtime_pack_stdout(report, stdout, request['manifest_sha256'], request['loader_sha256'])
    else:
        require(report.get('runner_sha256') == build.identity['files']['tools/hia_selfhost_child.py'],
                'workdir compiler child identity differs')
        process_stdout(report, stdout, capacity=len(expected), workspace=4096)
    return report


def load_sources(source_root):
    root = Path(source_root).resolve(strict=True)
    raw = file(root, PROFILE).read_bytes()
    require(sha(raw) == PROFILE_SHA256, "workdir frozen profile bytes differ")
    profile = json.loads(raw)
    require(profile.get("schema") == "hepta.runtime.workdir-service-profile.v1"
            and profile.get("compiler_commit") == COMPILER
            and profile.get("compiler_sha256") == B3
            and profile.get("elf_sha256") == ELF and profile.get("elf_bytes") == ELF_BYTES
            and profile.get("frame_magic") == FRAME_MAGIC.decode()
            and profile.get("regex_continuation_graph") is True
            and profile.get("configuration_validation_profile") == "native-config-regex-closed.v1"
            and profile.get("private_connection_snapshot_fd") == 4
            and all(profile.get(k) is False for k in ("remote_execution_qualified",
                "whole_runtime_replaced", "production_activated", "old_stack_removal_qualified"))
            and [m.get("id") for m in profile["members"]] == list(range(MEMBER_COUNT))
            and [m.get("name") for m in profile["members"]] == MEMBER_NAMES,
            "workdir fixed composition differs")
    sources = {PROFILE: raw}
    roles = [("member" + str(m["id"]), m["source"], m["buffer_profile"], m["source_sha256"],
              m["image_sha256"]) for m in profile["members"]]
    roles += [("prefix", profile["prefix_source"], "standard", profile["prefix_source_sha256"], None),
              ("packer", profile["packer_source"], "standard", profile["packer_source_sha256"], None)]
    for _, name, _, expected, _ in roles:
        sources[name] = file(root, name).read_bytes()
        require(sha(sources[name]) == expected, "workdir native source differs: " + name)
    proof_name = profile["adapter_proof"]
    proof_raw = file(root, proof_name).read_bytes()
    proof = json.loads(proof_raw)
    sources[proof_name] = proof_raw
    sources[profile["adapter_source"]] = file(root, profile["adapter_source"]).read_bytes()
    require(sha(proof_raw) == profile["adapter_proof_sha256"]
            and sha(sources[profile["adapter_source"]]) == profile["adapter_source_sha256"] == proof["source_sha256"]
            and proof["regex_continuation_graph"] is True and proof["mapping_bytes"] == 3489730624,
            "workdir adapter composition differs")
    for name, field in PARTS.items():
        sources[name] = file(root, name).read_bytes()
        require(sha(sources[name]) == proof[field], "workdir fixed adapter part differs: " + name)
    for name in HELPERS:
        sources[name] = file(root, name).read_bytes()
    require(sources["scripts/hia_native_build.py"] == Path(native_build.__file__).read_bytes()
            and sources["scripts/hia_native_effect_fence_build.py"] == Path(evidence_build.__file__).read_bytes()
            and sources[HELPERS[-1]] == Path(__file__).read_bytes(),
            "workdir actual build driver differs from source tree")
    sources["native/binary_codec.hepta"] = file(root, "native/binary_codec.hepta").read_bytes()
    return root, profile, sources, roles


def inspect_service(elf, images, prefix, profile):
    require(len(elf) == ELF_BYTES and sha(elf) == ELF
            and len(prefix) == profile["prefix_bytes"] and sha(prefix) == profile["prefix_sha256"],
            "workdir executable/prefix identity differs")
    require(elf[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<HH", elf, 16) == (2, 62)
            and struct.unpack_from("<Q", elf, 24)[0] == 0x4000b0
            and struct.unpack_from("<QQ", elf, 96) == (len(elf), len(elf))
            and struct.unpack_from("<H", elf, 56)[0] == 2,
            "workdir ELF header differs")
    normalized = bytearray(elf[:len(prefix)])
    struct.pack_into("<QQ", normalized, 96, 0, 0)
    cursor = len(prefix)
    require(len(images) == MEMBER_COUNT, "workdir member count differs")
    for member, image in zip(profile["members"], images, strict=True):
        hole = member["call_displacement_offset"]
        require(member["offset"] == cursor and len(image) == member["image_bytes"]
                and sha(image) == member["image_sha256"]
                and elf[cursor:cursor + len(image)] == image
                and 1 <= hole and hole + 4 <= len(prefix) and elf[hole - 1] == 0xe8
                and struct.unpack_from("<i", elf, hole)[0] == cursor - hole - 4,
                "workdir embedded image or call target differs")
        normalized[hole:hole + 4] = bytes(4)
        cursor += len(image)
    require(cursor == len(elf) and bytes(normalized) == prefix, "workdir native prefix differs")


def manifest_contract(profile, sources):
    return dict(schema="hepta.runtime.workdir-service-native.v2", target="linux-x86_64",
        compiler_commit=COMPILER, compiler_sha256=B3, profile_sha256=PROFILE_SHA256,
        executable="workdir-service.elf", elf_sha256=ELF, elf_bytes=ELF_BYTES,
        source_inventory={name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in sources.items()},
        runtime_python_required=False, runtime_libc_required=False, assembler_required=False,
        qualification_observation_only=True, private_connection_snapshot_fd=4,
        configuration_validation_profile="native-config-regex-closed.v1", regex_continuation_graph=True,
        public_mcp_transport_complete=False, remote_execution_qualified=False,
        fresh_full_cold_gate=False, whole_runtime_replaced=False,
        production_activated=False, old_stack_removal_qualified=False)


def verify_bundle(manifest_path, hepta, build_root, *, source_root=ROOT, build=None):
    path = Path(manifest_path).resolve(strict=True)
    root, profile, sources, roles = load_sources(source_root)
    if build is None:
        build = NativeBuild(hepta, build_root)
        build.bootstrap()
    require(build.identity["commit"] == COMPILER and build.compiler_sha256 == B3,
            "workdir compiler fixed point differs")
    build._recheck()
    data = json.loads(path.read_bytes())
    destination = path.parent
    require(all(data.get(k) == v for k, v in manifest_contract(profile, sources).items()),
            "workdir completed bundle contract differs")
    require(file(destination, "profile.json").read_bytes() == sources[PROFILE]
            and len(data.get("compiled", [])) == len(roles), "workdir retained profile differs")
    actual = {}
    for record, (role, name, buffer, source_sha, image_sha) in zip(data["compiled"], roles, strict=True):
        module_path = file(destination, role + "/manifest.json")
        require(record.get("role") == role and record.get("source") == name
                and record.get("manifest") == role + "/manifest.json"
                and record.get("manifest_sha256") == sha(module_path.read_bytes()),
                "workdir compiled manifest differs")
        metadata, image, files = module_evidence(module_path, sources[name], build, buffer)
        require(record.get("compile_files") == files and record.get("source_sha256") == source_sha
                and record.get("image_sha256") == sha(image)
                and record.get("buffer_profile") == buffer
                and (image_sha is None or image_sha == sha(image)), "workdir actual compile evidence differs")
        if role.startswith("member"):
            member = profile["members"][int(role.removeprefix("member"))]
            require(all(record.get(k) == v for k, v in member.items()), "workdir actual member differs")
        actual[role] = (metadata, image, record)
    verify_sha_import(sources[profile["packer_source"]], sources["native/binary_codec.hepta"], profile)
    prefix = file(destination, "prefix.bin").read_bytes()
    prefix_receipt = run_evidence(destination, "prefix-run", b"", actual["prefix"][1], prefix, build, root)
    require(data.get("prefix_receipt") == prefix_receipt, "workdir native prefix receipt differs")
    images = [actual["member" + str(i)][1] for i in range(MEMBER_COUNT)]
    pieces = [prefix, *images]
    frame = FRAME_MAGIC + b"".join(struct.pack("<Q", len(x)) for x in pieces) + bytes(24) + b"".join(pieces)
    elf = file(destination, "workdir-service.elf").read_bytes()
    require(stat.S_IMODE(file(destination, "workdir-service.elf").stat().st_mode) == 0o500,
            "workdir executable mode differs")
    result = run_evidence(destination, "service-pack", frame, actual["packer"][1], elf, build, root)
    inspect_service(elf, images, prefix, profile)
    from tools.qualify_hia_selfhost_cli import inspect_executable
    require(data.get("pack_receipt") == result
            and data.get("pack_input_sha256") == sha(frame) == profile["pack_input_sha256"]
            and len(frame) == profile["pack_input_bytes"]
            and data.get("inspection") == inspect_executable(elf)
            and data.get("members") == [actual["member" + str(i)][2] for i in range(MEMBER_COUNT)],
            "workdir final packing evidence differs")
    require(all(file(root, name).read_bytes() == raw for name, raw in sources.items()),
            "workdir source changed during verification")
    build._recheck()
    return data


def build_workdir_service(hepta, build_root, *, source_root=ROOT):
    root, profile, sources, roles = load_sources(source_root)
    build = NativeBuild(hepta, build_root)
    build.bootstrap()
    require(build.identity["commit"] == COMPILER and build.compiler_sha256 == B3,
            "workdir compiler fixed point differs")
    key = sha(b"".join(name.encode() + b"\0" + hashlib.sha256(raw).digest()
                      for name, raw in sorted(sources.items())))
    destination = Path(build_root).resolve() / "workdir-service" / key
    manifest_path = destination / "manifest.json"
    if manifest_path.exists():
        verify_bundle(manifest_path, hepta, build_root, source_root=root, build=build)
        return manifest_path
    compiled = {}
    for role, name, buffer, source_sha, image_sha in roles:
        label = "workdir-" + source_sha[:28] + "-" + str(tuple(BUFFER_PROFILES).index(buffer))
        path = build.root / "modules" / label / "manifest.json"
        if not path.exists():
            path = build.compile(label, root / name, standalone=None, buffer_profile=buffer)
        metadata, image, inventory = module_evidence(path, sources[name], build, buffer)
        require(image_sha is None or sha(image) == image_sha, "workdir fresh native image differs")
        compiled[role] = (path, metadata, image, inventory)
    destination.mkdir(parents=True, mode=0o700)
    write_new(destination / "profile.json", sources[PROFILE])
    records = []
    for role, name, buffer, source_sha, image_sha in roles:
        path, metadata, image, inventory = compiled[role]
        folder = destination / role
        folder.mkdir(mode=0o700)
        for filename in ("manifest.json", metadata["source"], metadata["image"], *COMPILE_FILES):
            write_new(folder / filename, file(path.parent, filename).read_bytes())
        record = dict(role=role, source=name, source_sha256=source_sha, image_sha256=sha(image),
            manifest=role + "/manifest.json", manifest_sha256=sha(path.read_bytes()),
            compile_files=inventory, buffer_profile=buffer)
        if role.startswith("member"):
            record.update(profile["members"][int(role.removeprefix("member"))])
        records.append(record)
    by_role = {r["role"]: r for r in records}
    from tools.qualify_hia_selfhost import invoke
    from tools.qualify_hia_selfhost_cli import inspect_executable
    prefix_path, prefix_metadata, prefix_image, _ = compiled["prefix"]
    prefix_receipt, prefix = invoke(destination, "prefix-run", prefix_path.parent / prefix_metadata["image"],
        b"", capacity=profile["prefix_bytes"], workspace_size=4096)
    require(prefix_receipt.get("core_u32") == len(prefix) == profile["prefix_bytes"]
            and sha(prefix) == profile["prefix_sha256"], "workdir native prefix output differs")
    write_new(destination / "prefix.bin", prefix)
    verify_sha_import(sources[profile["packer_source"]], sources["native/binary_codec.hepta"], profile)
    images = [compiled["member" + str(i)][2] for i in range(MEMBER_COUNT)]
    pieces = [prefix, *images]
    frame = FRAME_MAGIC + b"".join(struct.pack("<Q", len(x)) for x in pieces) + bytes(24) + b"".join(pieces)
    require(sha(frame) == profile["pack_input_sha256"], "workdir frozen pack input differs")
    report, elf = runtime_pack(destination, destination / "packer/manifest.json", frame, root)
    require(report.get("core_u32") == len(elf) == ELF_BYTES and sha(elf) == ELF,
            "workdir native packing failed")
    inspect_service(elf, images, prefix, profile)
    write_new(destination / "workdir-service.elf", elf, 0o500)
    data = dict(manifest_contract(profile, sources), compiled=records,
        members=[by_role["member" + str(i)] for i in range(MEMBER_COUNT)],
        prefix_receipt=prefix_receipt, pack_receipt=report, pack_input_sha256=sha(frame),
        inspection=inspect_executable(elf))
    write_new(manifest_path, json_bytes(data))
    verify_bundle(manifest_path, hepta, build_root, source_root=root, build=build)
    return manifest_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--build-root", required=True, type=Path)
    parser.add_argument("--source-root", default=ROOT, type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        verify_bundle(args.verify, args.hepta, args.build_root, source_root=args.source_root)
        result = args.verify
    else:
        result = build_workdir_service(args.hepta, args.build_root, source_root=args.source_root)
    print(json.dumps(dict(status="PASS", manifest=str(result), elf_sha256=ELF)))


if __name__ == "__main__":
    main()
