"""Bounded observer for the fixed fourteen-image HIA batch-write packer.

This uses the existing runtime standard profile. The compiler's separate
1 MiB native qualification boundary is unchanged. There is no assembly,
compilation or filesystem semantic implementation in this child.
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

PACKER = '794b3ac88e9def303fb01b84866a94a6b967cdd5d8ad21f5beddba445eaf018e'
SOURCE = '431209d33943460839d63ed4082b903432bdee2dc4901401ef3351071d2a80b7'
FRAME = '9dd7a4cc2b1afec2a4489ef0e20ff0b757daa2b2cb72a3b6786fd118d36dc960'
FRAME_BYTES, ELF_BYTES = 2719526, 2736334
LOADER = '58e2fe0492379340d7471a7857e1aa5de1a9a5d1e37a118852278b131bb1fe06'


def sha(raw): return hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value: raise ValueError(reason)


def main():
    request = json.loads(Path(sys.argv[1]).read_bytes())
    require(set(request) == {'format', 'manifest', 'manifest_sha256', 'image_sha256',
            'source', 'source_sha256', 'capacity', 'workspace_size', 'output', 'loader_sha256'},
            'batch-write pack request shape differs')
    require(request['format'] == 'flat-x86-64' and request['image_sha256'] == PACKER
            and request['source_sha256'] == FRAME and request['loader_sha256'] == LOADER
            and type(request['capacity']) is int and request['capacity'] == ELF_BYTES + 64
            and type(request['workspace_size']) is int and request['workspace_size'] == 4096,
            'batch-write pack invocation differs')
    loader_raw = Path(loader.__file__).read_bytes()
    require(sha(loader_raw) == LOADER, 'batch-write pack loaded loader differs')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0,
            'disable batch-write pack child core dumps')
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 << 20, 16 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    frame = Path(request['source']).read_bytes()
    require(len(frame) == FRAME_BYTES and sha(frame) == FRAME, 'batch-write pack frame differs')
    forbidden = [name for name in sys.modules if name.startswith('hepta.')
                 or name.startswith('generate_hia_')]
    require(not forbidden, 'batch-write pack imported a compiler owner')
    with loader.NativeModule(request['manifest'], manifest_sha256=request['manifest_sha256']) as module:
        require(module.metadata['image_sha256'] == PACKER
                and module.metadata['source_sha256'] == SOURCE
                and module.metadata.get('buffer_profile', 'standard') == 'standard'
                and tuple(module.metadata[k] for k in ('input_capacity', 'output_capacity', 'workspace_capacity'))
                    == (8 << 20, 8 << 20, 32 << 20), 'batch-write native packer profile differs')
        started = time.monotonic_ns()
        returned, output, workspace = module.invoke_raw(frame, output_capacity=ELF_BYTES + 64,
            workspace_capacity=4096, output_fill=0xa5, workspace_fill=0)
        elapsed = time.monotonic_ns() - started
    require(Path(loader.__file__).read_bytes() == loader_raw, 'batch-write pack loader changed')
    with Path(request['output']).open('xb') as handle: handle.write(output)
    print(json.dumps(dict(status='returned', result_u64=returned, abi_status=returned >> 32,
        return_encoding='zero-extended-u32', core_u32=returned & 0xffffffff,
        source_sha256=sha(frame), image_sha256=PACKER, output_sha256=sha(output),
        source_unchanged=True, output_unchanged=output == b'\xa5' * (ELF_BYTES + 64),
        workspace_sha256=sha(workspace), native_elapsed_ns=elapsed,
        forbidden_compiler_modules_loaded=forbidden,
        loader_operations='copy; sealed RX native runtime module; fixed ABI call',
        manifest_sha256=request['manifest_sha256'], loader_sha256=LOADER,
        borrowed_buffer_canaries_unchanged=True, native_profile='standard',
        limits=dict(cpu_seconds=10, address_bytes=256 << 20, core_dumpable=False,
            stack_bytes=8 << 20, file_bytes=16 << 20, open_files=32,
            input_capacity=8 << 20, output_capacity=ELF_BYTES + 64, workspace_bytes=4096)),
        sort_keys=True))


if __name__ == '__main__': main()
