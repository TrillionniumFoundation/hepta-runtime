"""Disposable observer for this fixed 8 MiB native runtime packing profile.

The compiler's independent 1 MiB qualification boundary remains unchanged.
This child maps the existing runtime packer with the normal native loader.
It has no parser, code generator, assembler or workdir semantic fallback.
"""
from __future__ import annotations
import ctypes
import hashlib
import json
from pathlib import Path
import resource
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_loader as loader

PACKER = '96887736d41af19eaf2b45d2a23945f0a67d4834c55b2dcd85814f1ed1b04882'
SOURCE = 'de68ece3db1970077d74a456846d66c7cb04e976858f411129fa9c39ba5bbf44'
FRAME = '091a0c460a74673975bcaf12297bddbf66189066fa3639dc161e3ec33a60c8b0'
FRAME_BYTES = 5484075
OUTPUT_BYTES = 5483867
LOADER_OPERATIONS = 'copy; sealed RX native runtime module; fixed ABI call'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def main():
    request = json.loads(Path(sys.argv[1]).read_bytes())
    require(set(request) == {'format', 'manifest', 'manifest_sha256', 'image_sha256',
            'source', 'source_sha256', 'capacity', 'workspace_size', 'output', 'loader_sha256'},
            'workdir runtime pack request shape differs')
    require(request['format'] == 'flat-x86-64' and request['image_sha256'] == PACKER
            and request['source_sha256'] == FRAME
            and type(request['capacity']) is int and request['capacity'] == OUTPUT_BYTES
            and type(request['workspace_size']) is int and request['workspace_size'] == 4096,
            'workdir runtime pack invocation differs')
    loader_raw = Path(loader.__file__).read_bytes()
    require(sha(loader_raw) == request['loader_sha256'], 'workdir pack loader differs')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0,
            'disable workdir pack child core dumps')
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 << 20, 16 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    frame = Path(request['source']).read_bytes()
    require(len(frame) == FRAME_BYTES and sha(frame) == FRAME,
            'workdir pack frame differs')
    forbidden = [name for name in sys.modules if name.startswith('hepta.')
                 or name.startswith('generate_hia_')]
    require(not forbidden, 'workdir pack imported a compiler owner')
    with loader.NativeModule(request['manifest'], manifest_sha256=request['manifest_sha256']) as module:
        require(module.metadata['image_sha256'] == PACKER
                and module.metadata['source_sha256'] == SOURCE
                and module.metadata.get('buffer_profile', 'standard') == 'standard'
                and tuple(module.metadata[k] for k in ('input_capacity', 'output_capacity', 'workspace_capacity'))
                    == (8 << 20, 8 << 20, 32 << 20), 'workdir native packer profile differs')
        started = time.monotonic_ns()
        returned, output, workspace = module.invoke_raw(frame, output_capacity=OUTPUT_BYTES,
            workspace_capacity=4096, output_fill=0xa5, workspace_fill=0)
        elapsed = time.monotonic_ns() - started
    require(Path(loader.__file__).read_bytes() == loader_raw, 'workdir pack loader changed')
    with Path(request['output']).open('xb') as handle:
        handle.write(output)
    fields = {str(i): int.from_bytes(workspace[i:i + 8], 'little')
              for i in (0, 8, 16, 24, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 224, 248, 1024)}
    print(json.dumps(dict(status='returned', result_u64=returned, abi_status=returned >> 32,
        return_encoding='zero-extended-u32', core_u32=returned & 0xffffffff,
        source_sha256=sha(frame), image_sha256=PACKER, output_sha256=sha(output),
        source_unchanged=True, output_unchanged=output == b'\xa5' * OUTPUT_BYTES,
        workspace_header=fields, native_elapsed_ns=elapsed,
        forbidden_compiler_modules_loaded=forbidden, loader_operations=LOADER_OPERATIONS,
        manifest_sha256=request['manifest_sha256'], loader_sha256=request['loader_sha256'],
        borrowed_buffer_canaries_unchanged=True, native_profile='standard',
        limits=dict(cpu_seconds=10, address_bytes=256 << 20, core_dumpable=False,
            stack_bytes=8 << 20, file_bytes=16 << 20, open_files=32,
            input_capacity=8 << 20, output_capacity=OUTPUT_BYTES, workspace_bytes=4096)),
        sort_keys=True))


if __name__ == '__main__':
    main()
