"""Bounded observer for the fixed eight-image HIA write-chain packer.

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

PACKER = 'f2d3e517a0cb00085c2d2043d5deae83c0947a991b6a9275c044ee91427df579'
SOURCE = 'f85594673a0b96ac908d64917db18349478559359e60c3c333b58384967049a4'
FRAME = 'b92f7a6b05ceda92c06e08f8c167e943f6b6f627bfeb11c896653a6a6bd92244'
FRAME_BYTES, ELF_BYTES = 1438734, 1453462
LOADER = '331b1fdc693df44847723f7171a1338918d1558f1cdc48f558cd29b32f2971e2'


def sha(raw): return hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value: raise ValueError(reason)


def main():
    request = json.loads(Path(sys.argv[1]).read_bytes())
    require(set(request) == {'format', 'manifest', 'manifest_sha256', 'image_sha256',
            'source', 'source_sha256', 'capacity', 'workspace_size', 'output', 'loader_sha256'},
            'write-chain pack request shape differs')
    require(request['format'] == 'flat-x86-64' and request['image_sha256'] == PACKER
            and request['source_sha256'] == FRAME and request['loader_sha256'] == LOADER
            and type(request['capacity']) is int and request['capacity'] == ELF_BYTES + 64
            and type(request['workspace_size']) is int and request['workspace_size'] == 4096,
            'write-chain pack invocation differs')
    loader_raw = Path(loader.__file__).read_bytes()
    require(sha(loader_raw) == LOADER, 'write-chain pack loaded loader differs')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0,
            'disable write-chain pack child core dumps')
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_STACK, (8 << 20, 8 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 << 20, 16 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    frame = Path(request['source']).read_bytes()
    require(len(frame) == FRAME_BYTES and sha(frame) == FRAME, 'write-chain pack frame differs')
    forbidden = [name for name in sys.modules if name.startswith('hepta.')
                 or name.startswith('generate_hia_')]
    require(not forbidden, 'write-chain pack imported a compiler owner')
    with loader.NativeModule(request['manifest'], manifest_sha256=request['manifest_sha256']) as module:
        require(module.metadata['image_sha256'] == PACKER
                and module.metadata['source_sha256'] == SOURCE
                and module.metadata.get('buffer_profile', 'standard') == 'standard'
                and tuple(module.metadata[k] for k in ('input_capacity', 'output_capacity', 'workspace_capacity'))
                    == (8 << 20, 8 << 20, 32 << 20), 'write-chain native packer profile differs')
        started = time.monotonic_ns()
        returned, output, workspace = module.invoke_raw(frame, output_capacity=ELF_BYTES + 64,
            workspace_capacity=4096, output_fill=0xa5, workspace_fill=0)
        elapsed = time.monotonic_ns() - started
    require(Path(loader.__file__).read_bytes() == loader_raw, 'write-chain pack loader changed')
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
