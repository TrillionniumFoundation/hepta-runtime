"""Build closed native HIA module tables and a kernel-only stdio ELF.

This is an artifact custody driver. HIA packs all ELF bytes. The executable
contains no Python parser, dispatcher, module loader, or semantic fallback.
"""
from __future__ import annotations
from dataclasses import dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_loader import NativeModule


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    source: Path
    flags: int = 0
    call_mask: int = 0
    input_capacity: int = 8 << 20
    output_capacity: int = 8 << 20
    workspace_capacity: int = 32 << 20


def _admit(manifest_path, compiler_sha, source_raw):
    manifest_raw = manifest_path.read_bytes()
    metadata = json.loads(manifest_raw)
    if metadata.get('compiler_sha256') != compiler_sha or metadata.get('source_sha256') != sha(source_raw):
        raise ValueError('composition module compiler/source identity differs')
    module = NativeModule(manifest_path, manifest_sha256=sha(manifest_raw))
    module.close()
    image = (manifest_path.parent / metadata['image']).read_bytes()
    if sha(image) != metadata['image_sha256']:
        raise ValueError('composition image changed after native admission')
    return metadata, image


def build_composition(hepta: Path, build_root: Path, members: list[ModuleSpec], *,
                      source_root: Path = ROOT) -> Path:
    if not 1 <= len(members) <= 16:
        raise ValueError('composition requires one to sixteen fixed modules')
    build = NativeBuild(hepta, build_root)
    compiler_sha = sha(build.bootstrap().read_bytes())
    packer_source = source_root / 'native/composition_packer.hepta'
    packer_raw = packer_source.read_bytes()
    io_raw = (source_root / 'native/io_policy.hepta').read_bytes()
    snapshots = [(spec, spec.source.read_bytes()) for spec in members]
    for i, (spec, raw) in enumerate(snapshots):
        if type(spec.name) is not str or not spec.name or len(spec.name) > 128:
            raise ValueError('composition member name is invalid')
        if any(type(v) is not int for v in (spec.flags, spec.call_mask, spec.input_capacity,
                                           spec.output_capacity, spec.workspace_capacity)):
            raise ValueError('composition profile fields must be exact integers')
        if (spec.flags not in (0, 1, 2) or not 0 <= spec.call_mask < (1 << len(members))
                or (spec.flags != 1 and spec.call_mask != 0)
                or not 0 < spec.input_capacity <= 8 << 20
                or not 0 < spec.output_capacity <= 8 << 20
                or not 0 < spec.workspace_capacity <= 32 << 20
                or (spec.flags == 1 and spec.workspace_capacity < 4096)):
            raise ValueError('composition member profile is outside its ABI')
        if spec.flags == 2 and (i != 3 or raw != io_raw or spec.workspace_capacity != 86016
                               or spec.input_capacity < 4208 or spec.output_capacity < 65664):
            raise ValueError('OS effects are confined to the pinned IO owner in slot three')
        if i == 0 and (spec.flags != 1 or spec.input_capacity != 8 << 20 or spec.output_capacity != 8 << 20):
            raise ValueError('composition root must be a full-width continuation controller')
    profile = [{'id': i, 'name': spec.name, 'source_sha256': sha(raw), 'flags': spec.flags,
                'call_mask': spec.call_mask, 'input_capacity': spec.input_capacity,
                'output_capacity': spec.output_capacity, 'workspace_capacity': spec.workspace_capacity}
               for i, (spec, raw) in enumerate(snapshots)]
    key = sha(json_bytes({'compiler': compiler_sha, 'members': profile, 'packer': sha(packer_raw)}))
    destination = Path(build_root).resolve() / 'composition' / key
    manifest_path = destination / 'manifest.json'

    def recheck_sources():
        if packer_source.read_bytes() != packer_raw:
            raise ValueError('composition packer source changed during build')
        if (source_root / 'native/io_policy.hepta').read_bytes() != io_raw:
            raise ValueError('composition IO source changed during build')
        for spec, raw in snapshots:
            if spec.source.read_bytes() != raw:
                raise ValueError('composition member source changed during build')
        build._recheck()

    if manifest_path.exists():
        saved = json.loads(manifest_path.read_bytes())
        if (saved.get('schema') != 'hepta.runtime.native-composition.v1'
                or saved.get('key') != key or saved.get('profile') != profile
                or saved.get('compiler_sha256') != compiler_sha):
            raise ValueError('cached composition profile differs')
        if sha((destination / 'native-local-read.elf').read_bytes()) != saved.get('executable_sha256'):
            raise ValueError('cached composition executable differs')
        if type(saved.get('members')) is not list or len(saved['members']) != len(members):
            raise ValueError('cached composition member count differs')
        rows = [(saved['packer'], packer_raw)] + list(zip(saved['members'], [v[1] for v in snapshots]))
        for index, (row, raw) in enumerate(rows):
            basename = 'packer.json' if index == 0 else f'module_{index - 1:02d}.json'
            if row.get('manifest') != basename:
                raise ValueError('cached composition member path differs')
            path = destination / basename
            if sha(path.read_bytes()) != row['manifest_sha256']:
                raise ValueError('cached composition member manifest differs')
            _admit(path, compiler_sha, raw)
        recheck_sources()
        return manifest_path

    compiled = []
    for role, source, raw in [('packer', packer_source, packer_raw)] + [(spec.name, spec.source, raw) for spec, raw in snapshots]:
        name = 'composition-' + sha(raw)[:24]
        path = Path(build_root).resolve() / 'modules' / name / 'manifest.json'
        if not path.exists():
            path = build.compile(name, source, standalone=None)
        metadata, image = _admit(path, compiler_sha, raw)
        compiled.append((path, metadata, image, raw))
    frame = bytearray(b'HIABND01' + struct.pack('<3Q', len(members), 0, 0))
    for (spec, raw), (_, meta, image, _) in zip(snapshots, compiled[1:]):
        for field in ('input_capacity', 'output_capacity', 'workspace_capacity'):
            if getattr(spec, field) > meta[field]:
                raise ValueError('composition exceeds a module manifest capacity')
        frame.extend(struct.pack('<8Q', len(image), spec.input_capacity, spec.output_capacity,
                                 spec.workspace_capacity, spec.flags, spec.call_mask, 0, 0))
        frame.extend(bytes.fromhex(sha(raw)))
        frame.extend(bytes.fromhex(sha(image)))
        frame.extend(image)
    if len(frame) > 8 << 20:
        raise ValueError('composition aggregate image exceeds its eight MiB profile')
    path, _, packer_image, _ = compiled[0]
    module = NativeModule(path, manifest_sha256=sha(path.read_bytes()))
    try:
        executable = module.invoke(bytes(frame), output_capacity=8 << 20, workspace_capacity=32 << 20)
    finally:
        module.close()
    from tools.qualify_hia_selfhost_cli import inspect_executable
    inspection = inspect_executable(executable)
    destination.mkdir(mode=0o700, parents=True)
    published = []
    for i, (_, meta, image, raw) in enumerate(compiled):
        stem = 'packer' if i == 0 else f'module_{i - 1:02d}'
        meta = dict(meta, source=stem + '.hepta', image=stem + '.image.bin')
        serialized = json_bytes(meta)
        write_new(destination / meta['source'], raw)
        write_new(destination / meta['image'], image)
        write_new(destination / (stem + '.json'), serialized)
        published.append({'manifest': stem + '.json', 'manifest_sha256': sha(serialized),
                          'source_sha256': sha(raw), 'image_sha256': sha(image)})
    write_new(destination / 'native-local-read.elf', executable, 0o500)
    metadata = {'schema': 'hepta.runtime.native-composition.v1', 'key': key,
                'target': 'linux-x86_64', 'transport': 'newline-json',
                'executable': 'native-local-read.elf', 'executable_sha256': sha(executable),
                'compiler_commit': compiled[0][1]['compiler_commit'], 'compiler_sha256': compiler_sha,
                'profile': profile, 'packer': published[0], 'members': published[1:],
                'frame_sha256': sha(frame), 'frame_bytes': len(frame),
                'runtime_python_required': False, 'runtime_libc_required': False,
                'whole_runtime_replaced': False, 'inspection': inspection,
                'packing': {'owner': 'HIA', 'input_unchanged': True, 'buffer_canaries_unchanged': True,
                            'packer_image_sha256': sha(packer_image)}}
    recheck_sources()
    write_new(manifest_path, json_bytes(metadata))
    return manifest_path


def build_local_read(hepta: Path, build_root: Path, *, source_root: Path = ROOT) -> Path:
    members = [ModuleSpec('local-service', source_root / 'native/local_service.hepta', flags=1, call_mask=62),
               ModuleSpec('policy', source_root / 'native/policy.hepta'),
               ModuleSpec('codec', source_root / 'native/binary_codec.hepta'),
               ModuleSpec('io', source_root / 'native/io_policy.hepta', flags=2, workspace_capacity=86016),
               ModuleSpec('stat-version', source_root / 'native/stat_version.hepta'),
               ModuleSpec('multi-read-service', source_root / 'native/multi_read_service.hepta', flags=1, call_mask=30)]
    return build_composition(hepta, build_root, members, source_root=source_root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--build-root', type=Path, default=os.environ.get('HIA_BUILD_ROOT'))
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args = parser.parse_args()
    if not args.hepta or not args.build_root:
        parser.error('--hepta and --build-root or their HIA environment variables are required')
    print(json.dumps({'manifest': str(build_local_read(args.hepta, args.build_root, source_root=args.source_root))}))
