"""Build and verify the fixed native directory caller and shared fence process.

This file is an explicit build/evidence driver. The resulting ELF needs neither
this Python process nor libc, Rust, an assembler, or a semantic host dispatcher.
It is a private caller profile; it does not activate the public MCP handler.
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
import hia_native_effect_fence_build as fence_build
from hia_native_build import ABI, BUFFER_PROFILES, NativeBuild, json_bytes, write_new
from hia_native_effect_fence_build import (
    COMPILE_FILES, OBSERVER_FIELDS, receipt, process_stdout, verify_sha_import, inspect_embedded,
)
PROFILE = "native/directory_service_profile.json"
FENCE_PROFILE = "native/directory_fence_profile.json"
PROFILE_SHA256 = 'c4a7da9586160b0f78b7886262a39efef86f955e8328d6e9bd45b57ae27c4ba4'
FENCE_PROFILE_SHA256 = "60cb6fd30777cc92181d1ffb5a6531bc27bbf4720a8f0090d95fba630c1a26f6"
REGEX_DEPENDENCIES = "native/directory_regex_dependencies.json"
REGEX_DEPENDENCIES_SHA256 = '772fb83ffd2d876a2ba58e17e80d4a497b188f19d1532cbddf333e1a4f26cde1'
MEMBER_COUNT = 21
FRAME_MAGIC = b"HMDSVC02"
ELF_BYTES = 5924455
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
B3 = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
ELF = '0804d65702f08ba263b3093939e7b602e0a0f239ae2c17ca8a8e57695f290982'
HELPERS = ("scripts/hia_native_build.py", "scripts/hia_native_loader.py",
           "scripts/hia_native_effect_fence_build.py", "scripts/hia_native_directory_pack_child.py",
           "scripts/hia_native_directory_service_build.py")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def file(root, name):
    require(type(name) is str and name and not Path(name).is_absolute()
            and all(p not in ("", ".", "..") for p in name.split("/")),
            "directory artifact path is not relative")
    root = Path(root).resolve(strict=True)
    path = root
    for part in name.split("/"):
        path = path / part
        require(not path.is_symlink(), "directory artifact contains a symlink")
    require(stat.S_ISREG(path.lstat().st_mode), "directory artifact is not regular")
    return path


def module_evidence(path, source, build, profile_name):
    data = json.loads(path.read_bytes())
    actual_source = file(path.parent, data.get("source")).read_bytes()
    image = file(path.parent, data.get("image")).read_bytes()
    require(profile_name in BUFFER_PROFILES, "directory module profile is unknown")
    icap, ocap, wcap = BUFFER_PROFILES[profile_name]
    expected = dict(schema="hepta.runtime.native-module.v1", abi=ABI, target="linux-x86_64",
        compiler_commit=build.identity["commit"], compiler_sha256=build.compiler_sha256,
        source_sha256=sha(source), image_sha256=sha(image), input_capacity=icap,
        output_capacity=ocap, workspace_capacity=wcap, qualification="development_fixed_point", standalone=None)
    require(actual_source == source and all(data.get(k) == v for k, v in expected.items())
            and (("buffer_profile" not in data) if profile_name == "standard"
                 else data.get("buffer_profile") == profile_name)
            and 0 < len(image) <= 1 << 20 and not image.startswith(b"\x7fELF"),
            "directory compiled module differs")
    records = {name: file(path.parent, name).read_bytes() for name in COMPILE_FILES}
    build_data = json.loads(records["build.json"])
    report = json.loads(records["module.receipt.json"])
    require(build_data.get("compiler_dependency") == build.identity
            and build_data.get("compile_receipt") == report
            and build_data.get("whole_runtime_replaced") is False,
            "directory compiler source custody differs")
    require(report.get("runner_sha256") == build.identity["files"]["tools/hia_selfhost_child.py"]
            and records["module.input.bin"] == source
            and records["module.stderr.log"] == b""
            and len(records["module.output.bin"]) == 1 << 20,
            "directory native compiler process differs")
    receipt(report, source, records["module.output.bin"], image, build.compiler_sha256)
    require(report.get("produced_bytes") == len(image) and report.get("produced_sha256") == sha(image)
            and report.get("source_sha256") == sha(source), "directory compiler output differs")
    process_stdout(report, records["module.stdout.log"], capacity=1 << 20, workspace=1 << 20)
    request = json.loads(records["module.request.json"])
    require(request.get("format") == "flat-x86-64"
            and request.get("image_sha256") == build.compiler_sha256
            and request.get("source_sha256") == sha(source)
            and request.get("capacity") == 1 << 20 and request.get("workspace_size") == 1 << 20,
            "directory compiler invocation differs")
    return data, image, {name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in records.items()}


def load_sources(source_root):
    root = Path(source_root).resolve(strict=True)
    profile_raw = file(root, PROFILE).read_bytes()
    fence_raw = file(root, FENCE_PROFILE).read_bytes()
    require(sha(profile_raw) == PROFILE_SHA256 and sha(fence_raw) == FENCE_PROFILE_SHA256,
            "directory frozen profile bytes differ")
    profile, fence = json.loads(profile_raw), json.loads(fence_raw)
    require(profile["schema"] == "hepta.runtime.directory-service-profile.v1"
            and fence["schema"] == "hepta.runtime.directory-fence-profile.v1"
            and profile["compiler_commit"] == fence["compiler_commit"] == COMPILER
            and profile["compiler_sha256"] == fence["compiler_sha256"] == B3
            and profile["elf_sha256"] == ELF
            and profile['elf_bytes'] == ELF_BYTES and profile['frame_magic'] == FRAME_MAGIC.decode()
            and profile['regex_continuation_graph'] is True
            and [x["id"] for x in profile["members"]] == list(range(MEMBER_COUNT))
            and [x["id"] for x in fence["members"]] == list(range(5)),
            "directory closed composition differs")
    sources = {PROFILE: profile_raw, FENCE_PROFILE: fence_raw}
    dependency_raw = file(root, REGEX_DEPENDENCIES).read_bytes()
    require(sha(dependency_raw) == REGEX_DEPENDENCIES_SHA256,
            'directory fixed regex dependency profile differs')
    dependencies = json.loads(dependency_raw)
    require(dependencies['schema'] == 'hepta.directory.regex-dependencies.v1'
            and dependencies['ordinary_request_regex_installation'] is False,
            'directory regex installation authority differs')
    for member, dependency in [(profile['members'][3], dependencies['validation']), *[
            (member, dependencies['regex'][member['name']]) for member in profile['members'][15:]]]:
        require(all(member[key] == dependency[key] for key in
                    ('source', 'source_sha256', 'image_sha256', 'buffer_profile')),
                'directory actual regex source/image identity differs')
    sources[REGEX_DEPENDENCIES] = dependency_raw
    roles = []
    for index, member in enumerate(profile["members"]):
        roles.append(("member" + str(index), member["source"], member["buffer_profile"],
                      member["source_sha256"], member["image_sha256"]))
    for index, member in enumerate(fence["members"]):
        roles.append(("fence-member" + str(index), member["source"], "standard",
                      member["source_sha256"], member["image_sha256"]))
    roles += [("prefix", profile["prefix_source"], "standard", profile["prefix_source_sha256"], None),
              ("packer", profile["packer_source"], "standard", profile["packer_source_sha256"], None)]
    for label in ("production", "queue_fixture"):
        row = fence["profiles"][label]
        require(row["worker_limit"] == (512 if label == "production" else 1),
                "directory fence worker profile differs")
        roles.append(("fence-" + label + "-packer", row["packer_source"], "standard",
                      row["packer_source_sha256"], None))
    for _, name, _, expected, _ in roles:
        raw = file(root, name).read_bytes()
        require(sha(raw) == expected, "directory native source differs: " + name)
        sources[name] = raw
    proof_name = profile["adapter_proof"]
    proof_raw = file(root, proof_name).read_bytes()
    proof = json.loads(proof_raw)
    sources[proof_name] = proof_raw
    sources[profile["adapter_source"]] = file(root, profile["adapter_source"]).read_bytes()
    require(sha(proof_raw) == profile["adapter_proof_sha256"]
            and sha(sources[profile["adapter_source"]]) == profile["adapter_source_sha256"] == proof["adapter_sha256"],
            "directory fixed adapter source differs")
    for part, expected in proof["parts"].items():
        name = "scripts/" + part
        sources[name] = file(root, name).read_bytes()
        require(sha(sources[name]) == expected, "directory fixed adapter part differs")
    for name in HELPERS:
        sources[name] = file(root, name).read_bytes()
    require(sources["scripts/hia_native_build.py"] == Path(native_build.__file__).read_bytes()
            and sources["scripts/hia_native_effect_fence_build.py"] == Path(fence_build.__file__).read_bytes()
            and sources[HELPERS[-1]] == Path(__file__).read_bytes(),
            "directory actual build driver differs from the selected source tree")
    return root, profile, fence, sources, roles


def inspect_service(elf, images, embedded, prefix, profile):
    require(len(elf) == profile["elf_bytes"] and sha(elf) == ELF
            and sha(prefix) == profile["prefix_sha256"] and len(prefix) == profile["prefix_bytes"],
            "directory executable/prefix identity differs")
    require(elf[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<HH", elf, 16) == (2, 62)
            and struct.unpack_from("<Q", elf, 24)[0] == 0x4000b0
            and struct.unpack_from("<QQ", elf, 96) == (len(elf), len(elf))
            and struct.unpack_from("<H", elf, 56)[0] == 2,
            "directory ELF header differs")
    normalized = bytearray(elf[:len(prefix)])
    struct.pack_into("<QQ", normalized, 96, 0, 0)
    cursor = len(prefix)
    require(len(images) == MEMBER_COUNT, "directory member count differs")
    for member, image in zip(profile["members"], images, strict=True):
        hole = member["call_displacement_offset"]
        require(member["offset"] == cursor and len(image) == member["image_bytes"]
                and sha(image) == member["image_sha256"]
                and elf[cursor:cursor + len(image)] == image
                and 1 <= hole and hole + 4 <= len(prefix) and elf[hole - 1] == 0xe8
                and struct.unpack_from("<i", elf, hole)[0] == cursor - hole - 4,
                "directory actual embedded image or call target differs")
        normalized[hole:hole + 4] = bytes(4)
        cursor += len(image)
    hole, size = profile["fence_displacement_offset"], profile["fence_size_offset"]
    require(cursor == profile["fence_elf_offset"] and elf[cursor:] == embedded
            and len(embedded) == profile["fence_elf_bytes"]
            and sha(embedded) == profile["fence_elf_sha256"]
            and 3 <= hole and hole + 4 <= len(prefix)
            and elf[hole - 3:hole] == b"\x48\x8d\x35"
            and struct.unpack_from("<i", elf, hole)[0] == cursor - hole - 4
            and 1 <= size and size + 4 <= len(prefix) and elf[size - 1] == 0xba
            and struct.unpack_from("<I", elf, size)[0] == len(embedded),
            "directory embedded fence/loader target differs")
    normalized[hole:hole + 4] = bytes(4)
    normalized[size:size + 4] = bytes(4)
    require(bytes(normalized) == prefix, "directory actual adapter prefix differs")


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
            'directory runtime packing observer differs')
    require(json_bytes(value['limits']) == json_bytes(dict(cpu_seconds=10, address_bytes=256 << 20,
            core_dumpable=False, stack_bytes=8 << 20, file_bytes=16 << 20, open_files=32,
            input_capacity=8 << 20, output_capacity=ELF_BYTES, workspace_bytes=4096)),
            'directory runtime pack fixed limits differ')
    header = value['workspace_header']
    require(type(header) is dict and set(header) == {str(i) for i in
            (0, 8, 16, 24, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 224, 248, 1024)}
            and all(type(x) is int and 0 <= x < 1 << 64 for x in header.values()),
            'directory runtime pack workspace differs')


def runtime_pack(destination, module, frame, source_root):
    label = 'service-pack'
    child = file(source_root, 'scripts/hia_native_directory_pack_child.py')
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
            'directory runtime packing observer inputs changed')
    return report, output.read_bytes() if output.exists() else b''


def run_evidence(destination, label, frame, image, expected, build, source_root):
    output = file(destination, label + ".output.bin").read_bytes()
    report = json.loads(file(destination, label + ".receipt.json").read_bytes())
    request = json.loads(file(destination, label + ".request.json").read_bytes())
    require(file(destination, label + ".input.bin").read_bytes() == frame
            and file(destination, label + ".stderr.log").read_bytes() == b""
            and len(output) == len(expected) and output == expected,
            "directory actual packer process files differ")
    receipt(report, frame, output, expected, sha(image))
    require(request.get("format") == "flat-x86-64"
            and request.get("image_sha256") == sha(image)
            and request.get("source_sha256") == sha(frame)
            and request.get("capacity") == len(expected) and request.get("workspace_size") == 4096,
            "directory native packer invocation differs")
    stdout = file(destination, label + '.stdout.log').read_bytes()
    if label == 'service-pack':
        require(report.get('runner_sha256') == sha(file(source_root, 'scripts/hia_native_directory_pack_child.py').read_bytes())
                and request.get('manifest_sha256') == sha(file(destination, 'packer/manifest.json').read_bytes())
                and request.get('loader_sha256') == sha(file(source_root, 'scripts/hia_native_loader.py').read_bytes()),
                'directory runtime pack source or module differs')
        process = report.get('completed_process', {})
        require(type(process.get('pid')) is int and process['pid'] > 0
                and process.get('exit_code') == 0 and process.get('reaped') is True
                and process.get('timed_out') is False and process.get('timeout_seconds') == 20,
                'directory runtime pack process did not complete')
        runtime_pack_stdout(report, stdout, request['manifest_sha256'], request['loader_sha256'])
    else:
        require(report.get('runner_sha256') == build.identity['files']['tools/hia_selfhost_child.py'],
                'directory compiler child identity differs')
        process_stdout(report, stdout, capacity=len(expected), workspace=4096)
    return report


def verify_bundle(manifest_path, hepta, build_root, *, source_root=ROOT, build=None):
    path = Path(manifest_path).resolve(strict=True)
    root, profile, fence, sources, roles = load_sources(source_root)
    if build is None:
        build = NativeBuild(hepta, build_root)
        build.bootstrap()
    require(build.identity["commit"] == COMPILER and build.compiler_sha256 == B3,
            "directory exact compiler fixed point differs")
    build._recheck()
    data = json.loads(path.read_bytes())
    destination = path.parent
    inventory = {name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in sources.items()}
    expected = dict(schema="hepta.runtime.directory-service-native.v2", target="linux-x86_64",
        compiler_commit=COMPILER, compiler_sha256=B3, profile_sha256=PROFILE_SHA256,
        fence_profile_sha256=FENCE_PROFILE_SHA256, executable="directory-service.elf",
        elf_sha256=ELF, elf_bytes=profile["elf_bytes"], source_inventory=inventory,
        runtime_python_required=False, runtime_libc_required=False, assembler_required=False,
        qualification_transport=True, public_mcp_transport_complete=False,
        one_shared_fence_process=True, fresh_cold_qualified=False,
        production_activated=False, whole_runtime_replaced=False)
    require(all(data.get(k) == v for k, v in expected.items()), "directory completed bundle contract differs")
    require(file(destination, "profile.json").read_bytes() == sources[PROFILE]
            and file(destination, "fence-profile.json").read_bytes() == sources[FENCE_PROFILE]
            and len(data.get("compiled", [])) == len(roles), "directory retained profile differs")
    actual = {}
    for record, (role, name, buffer, source_sha, image_sha) in zip(data["compiled"], roles, strict=True):
        module_path = file(destination, role + "/manifest.json")
        require(record.get("role") == role and record.get("source") == name
                and record.get("manifest") == role + "/manifest.json"
                and record.get("manifest_sha256") == sha(module_path.read_bytes()),
                "directory compiled member manifest differs")
        metadata, image, files = module_evidence(module_path, sources[name], build, buffer)
        require(record.get("compile_files") == files and record.get("source_sha256") == source_sha
                and record.get("image_sha256") == sha(image)
                and (image_sha is None or image_sha == sha(image)),
                "directory compiled member actual evidence differs")
        actual[role] = (metadata, image, record)
    codec = sources["native/binary_codec.hepta"]
    verify_sha_import(sources[profile["packer_source"]], codec, profile)
    for label in ("production", "queue_fixture"):
        verify_sha_import(sources[fence["profiles"][label]["packer_source"]], codec, fence["profiles"][label])
    prefix = file(destination, "prefix.bin").read_bytes()
    prefix_receipt = run_evidence(destination, "prefix-run", b"", actual["prefix"][1], prefix, build, root)
    require(data.get("prefix_receipt") == prefix_receipt
            and sha(prefix) == profile["prefix_sha256"] and len(prefix) == profile["prefix_bytes"],
            "directory native prefix receipt differs")
    fence_images = [actual["fence-member" + str(i)][1] for i in range(5)]
    fence_frame = b"HFFPACK2" + b"".join(struct.pack("<Q", len(x)) for x in fence_images) + bytes(16) + b"".join(fence_images)
    fences = {}
    from tools.qualify_hia_selfhost_cli import inspect_executable
    for label in ("production", "queue_fixture"):
        selected = fence["profiles"][label]
        fm = json.loads(file(destination, "fence-" + label + ".json").read_bytes())
        blob = file(destination, "fence-" + label + ".elf").read_bytes()
        result = run_evidence(destination, "fence-" + label + "-pack", fence_frame,
            actual["fence-" + label + "-packer"][1], blob, build, root)
        inspect_embedded(blob, fence_images, fence, selected)
        require(fm.get("schema") == "hepta.runtime.directory-fence-probe.v2"
                and fm.get("compiler_commit") == COMPILER and fm.get("compiler_sha256") == B3
                and fm.get("worker_limit") == selected["worker_limit"]
                and fm.get("executable") == "fence-" + label + ".elf"
                and fm.get("elf_sha256") == sha(blob) and fm.get("pack_receipt") == result
                and fm.get("members") == [actual["fence-member" + str(i)][2] for i in range(5)]
                and fm.get("inspection") == inspect_executable(blob),
                "directory shared-fence bundle differs")
        require(data.get("fences", {}).get(label) == dict(manifest="fence-" + label + ".json",
                manifest_sha256=sha(file(destination, "fence-" + label + ".json").read_bytes()),
                elf_sha256=sha(blob)), "directory fence manifest binding differs")
        fences[label] = blob
    images = [actual["member" + str(i)][1] for i in range(MEMBER_COUNT)]
    pieces = [prefix, *images, fences["production"]]
    frame = FRAME_MAGIC + b"".join(struct.pack("<Q", len(x)) for x in pieces) + bytes(24) + b"".join(pieces)
    elf = file(destination, "directory-service.elf").read_bytes()
    require(stat.S_IMODE(file(destination, "directory-service.elf").stat().st_mode) == 0o500,
            "directory executable mode differs")
    result = run_evidence(destination, "service-pack", frame, actual["packer"][1], elf, build, root)
    inspect_service(elf, images, fences["production"], prefix, profile)
    require(data.get("pack_receipt") == result and data.get("pack_input_sha256") == sha(frame)
            and data.get("inspection") == inspect_executable(elf)
            and data.get("members") == [actual["member" + str(i)][2] for i in range(MEMBER_COUNT)],
            "directory actual final packing evidence differs")
    require(all(file(root, name).read_bytes() == raw for name, raw in sources.items()),
            "directory source changed during verification")
    build._recheck()
    return data


def build_directory_service(hepta, build_root, *, source_root=ROOT):
    root, profile, fence, sources, roles = load_sources(source_root)
    build = NativeBuild(hepta, build_root)
    build.bootstrap()
    require(build.compiler_sha256 == B3, "directory compiler fixed point differs")
    build._recheck()
    key = sha(b"".join(name.encode() + b"\0" + hashlib.sha256(raw).digest()
                      for name, raw in sorted(sources.items())))
    destination = Path(build_root).resolve() / "directory-service" / key
    manifest_path = destination / "manifest.json"
    if manifest_path.exists():
        verify_bundle(manifest_path, hepta, build_root, source_root=root, build=build)
        return manifest_path
    compiled = {}
    for role, name, buffer, source_sha, image_sha in roles:
        label = "directory-" + source_sha[:28] + "-" + str(tuple(BUFFER_PROFILES).index(buffer))
        path = build.root / "modules" / label / "manifest.json"
        if not path.exists():
            path = build.compile(label, root / name, standalone=None, buffer_profile=buffer)
        metadata, image, inventory = module_evidence(path, sources[name], build, buffer)
        require(image_sha is None or sha(image) == image_sha,
                "directory fresh native image differs from frozen runtime image")
        compiled[role] = (path, metadata, image, inventory)
    destination.mkdir(parents=True, mode=0o700)
    write_new(destination / "profile.json", sources[PROFILE])
    write_new(destination / "fence-profile.json", sources[FENCE_PROFILE])
    records = []
    for role, name, buffer, source_sha, image_sha in roles:
        path, metadata, image, inventory = compiled[role]
        folder = destination / role
        folder.mkdir(mode=0o700)
        for name_in in ("manifest.json", metadata["source"], metadata["image"], *COMPILE_FILES):
            write_new(folder / name_in, file(path.parent, name_in).read_bytes())
        records.append(dict(role=role, source=name, source_sha256=source_sha,
            image_sha256=sha(image), manifest=role + "/manifest.json",
            manifest_sha256=sha(path.read_bytes()), compile_files=inventory))
    by_role = {r["role"]: r for r in records}
    from tools.qualify_hia_selfhost import invoke
    from tools.qualify_hia_selfhost_cli import inspect_executable
    def invoke_exact(label, role, frame, size, expected_sha):
        mp, mm, image, _ = compiled[role]
        if label == 'service-pack':
            report, output = runtime_pack(destination, destination / 'packer/manifest.json', frame, root)
        else:
            report, output = invoke(destination, label, mp.parent / mm["image"], frame,
                                    capacity=size, workspace_size=4096)
        require(type(report.get("core_u32")) is int and report["core_u32"] == size
                and len(output) == size and sha(output) == expected_sha,
                "directory native prefix/packer refused or produced different bytes")
        receipt(report, frame, output, output, sha(image))
        return report, output
    prefix_receipt, prefix = invoke_exact("prefix-run", "prefix", b"", profile["prefix_bytes"], profile["prefix_sha256"])
    write_new(destination / "prefix.bin", prefix)
    codec = sources["native/binary_codec.hepta"]
    verify_sha_import(sources[profile["packer_source"]], codec, profile)
    fence_images = [compiled["fence-member" + str(i)][2] for i in range(5)]
    fence_frame = b"HFFPACK2" + b"".join(struct.pack("<Q", len(x)) for x in fence_images) + bytes(16) + b"".join(fence_images)
    fences = {}; fence_records = {}
    for label in ("production", "queue_fixture"):
        selected = fence["profiles"][label]
        role = "fence-" + label + "-packer"
        verify_sha_import(sources[selected["packer_source"]], codec, selected)
        report, blob = invoke_exact("fence-" + label + "-pack", role, fence_frame,
                                    selected["elf_bytes"], selected["elf_sha256"])
        inspect_embedded(blob, fence_images, fence, selected)
        exe = "fence-" + label + ".elf"
        write_new(destination / exe, blob, 0o500)
        fm = dict(schema="hepta.runtime.directory-fence-probe.v2", compiler_commit=COMPILER,
            compiler_sha256=B3, worker_limit=selected["worker_limit"], executable=exe,
            elf_sha256=sha(blob), elf_bytes=len(blob), pack_receipt=report,
            members=[by_role["fence-member" + str(i)] for i in range(5)],
            inspection=inspect_executable(blob), fixture_pool_profile=label == "queue_fixture",
            private_permits_per_instance="dynamic", notification_fd=3,
            production_activated=False, whole_runtime_replaced=False, fresh_cold_qualified=False)
        mp = destination / ("fence-" + label + ".json")
        write_new(mp, json_bytes(fm))
        fence_records[label] = dict(manifest=mp.name, manifest_sha256=sha(mp.read_bytes()), elf_sha256=sha(blob))
        fences[label] = blob
    images = [compiled["member" + str(i)][2] for i in range(MEMBER_COUNT)]
    pieces = [prefix, *images, fences["production"]]
    frame = FRAME_MAGIC + b"".join(struct.pack("<Q", len(x)) for x in pieces) + bytes(24) + b"".join(pieces)
    report, elf = invoke_exact("service-pack", "packer", frame, profile["elf_bytes"], ELF)
    inspect_service(elf, images, fences["production"], prefix, profile)
    write_new(destination / "directory-service.elf", elf, 0o500)
    data = dict(schema="hepta.runtime.directory-service-native.v2", target="linux-x86_64",
        compiler_commit=COMPILER, compiler_sha256=B3, profile_sha256=PROFILE_SHA256,
        fence_profile_sha256=FENCE_PROFILE_SHA256, executable="directory-service.elf",
        elf_sha256=ELF, elf_bytes=len(elf), compiled=records,
        members=[by_role["member" + str(i)] for i in range(MEMBER_COUNT)], fences=fence_records,
        source_inventory={name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in sources.items()},
        prefix_receipt=prefix_receipt, pack_receipt=report, pack_input_sha256=sha(frame),
        inspection=inspect_executable(elf), runtime_python_required=False,
        runtime_libc_required=False, assembler_required=False, qualification_transport=True,
        public_mcp_transport_complete=False, one_shared_fence_process=True,
        fresh_cold_qualified=False, production_activated=False, whole_runtime_replaced=False)
    write_new(manifest_path, json_bytes(data))
    verify_bundle(manifest_path, hepta, build_root, source_root=root, build=build)
    return manifest_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--build-root", required=True, type=Path)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        result = verify_bundle(args.verify, args.hepta, args.build_root, source_root=args.source_root)
        print(json.dumps(dict(status="PASS", manifest=str(args.verify), elf_sha256=result["elf_sha256"])))
    else:
        result = build_directory_service(args.hepta, args.build_root, source_root=args.source_root)
        print(json.dumps(dict(status="PASS", manifest=str(result), elf_sha256=ELF)))


if __name__ == "__main__":
    main()
