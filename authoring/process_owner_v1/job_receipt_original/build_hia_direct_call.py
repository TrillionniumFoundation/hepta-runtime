"""Build a native call, receipt, or subprocess owner with a matching cold HIA compiler."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_direct_load_plan import (
    ADAPTER_PATH, PACKER_MAGIC, PACKER_PATH, ROOT, SOURCE_PATH,
)
from tools.generate_hia_job_receipt import (
    ADAPTER_PATH as RECEIPT_ADAPTER, PACKER_MAGIC as RECEIPT_MAGIC,
    PACKER_PATH as RECEIPT_PACKER, SOURCE_PATH as RECEIPT_SOURCE,
)
from tools.generate_hia_subprocess import (
    ADAPTER_PATH as SUBPROCESS_ADAPTER, PACKER_MAGIC as SUBPROCESS_MAGIC,
    PACKER_PATH as SUBPROCESS_PACKER, SOURCE_PATH as SUBPROCESS_SOURCE,
)
from tools.generate_hia_native_filter import read_adapter_binding, verify_adapter
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

DRIVER = 'tools/build_hia_direct_call.py'
ROLES = {
    'direct-call': (SOURCE_PATH, PACKER_PATH, ADAPTER_PATH, PACKER_MAGIC, 'direct-load-plan'),
    'job-receipt': (RECEIPT_SOURCE, RECEIPT_PACKER, RECEIPT_ADAPTER, RECEIPT_MAGIC, 'job-receipt'),
    'subprocess': (SUBPROCESS_SOURCE, SUBPROCESS_PACKER, SUBPROCESS_ADAPTER, SUBPROCESS_MAGIC, 'subprocess'),
}


def digest(raw):
    return sha256(raw).hexdigest()


def assemble(output, compiler, sources, binding, *, role='direct-call'):
    source, packer_path, _, magic, label = ROLES[role]
    image, image_receipt = compile_stage(output, label, compiler, sources[source])
    packer, packer_receipt = compile_stage(output, role + '-packer', compiler, sources[packer_path])
    code, packer_bytes = image.read_bytes(), packer.read_bytes()
    if digest(code) != image_receipt['produced_sha256'] or digest(packer_bytes) != packer_receipt['produced_sha256']:
        raise ValueError(f'{role} source or packer identity changed')
    request = struct.pack('<2Q', magic, len(code)) + code
    path, receipt = compile_stage(output, role + '-executable', packer, request, output_extension='.elf')
    binary = path.read_bytes()
    verify_adapter(binary, code, binding, entries=(0,))
    if (digest(binary) != receipt['produced_sha256']
            or image.read_bytes() != code or packer.read_bytes() != packer_bytes):
        raise ValueError(f'HIA packer changed the admitted {role} image or syscall adapter')
    return binary, {'executable': inspect_executable(binary), 'transport_adapter_sha256': binding[0].hex(),
                    'transport_assembled_during_build': False,
                    'native_compile_receipt': image_receipt, 'native_packer_receipt': packer_receipt,
                    'native_pack_receipt': receipt}


def build(output, compiler, cold_report, *, role='direct-call'):
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, cold_bytes)
    source, packer, adapter, _, _ = ROLES[role]
    paths = (source, packer, adapter, DRIVER, 'tools/generate_hia_native_filter.py')
    sources = {name: (ROOT / name).read_bytes() for name in paths}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError(f'standalone {role} needs matching cold source')
    binding = read_adapter_binding(sources[packer], sources[adapter], calls=1)
    output.mkdir(mode=0o700)
    binary, report = assemble(output, compiler, sources, binding, role=role)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes):
        raise ValueError(f'{role} inputs changed before publication')
    executable = output / ('hia-' + role)
    with executable.open('xb') as stream:
        stream.write(binary)
    executable.chmod(0o500)
    report.update({'schema': f'hepta.hia.{role}-build.v1',
                   'source_sha256': {name: digest(raw) for name, raw in sources.items()},
                   'compiler_sha256': digest(compiler_bytes), 'cold_report_sha256': digest(cold_bytes),
                   'executable_path': executable.name, 'executable_sha256': digest(binary)})
    with (output / 'build.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--role', choices=ROLES, default='direct-call')
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, role=args.role))


if __name__ == '__main__':
    main()
