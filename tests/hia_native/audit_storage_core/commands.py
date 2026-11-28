"""Frozen process argv and budgets shared by producer and read-only custody validation."""
from pathlib import Path
import json
BUDGETS={'format':60,'toolchain':60,'cargo-version':60,'strace-version':60,'native-build':900,
         'rust-fetch':180,'rust-vendor':180,'rust-build':900,'native':180,'original':180}
def commands(m):
    root=Path(m['source_root']);run=Path(m['producer_root']);rust=Path(m['rust_bin'])
    reference=run/'reference';python=m['python']
    config=['--config','source.crates-io.replace-with="fixed-vendor"','--config',
            'source.fixed-vendor.directory='+json.dumps(str(run/'vendor'))]
    rows=[
        ('format',[rust/'rustfmt','--check','--edition','2021','--config',
                   'skip_children=true,hard_tabs=true,max_width=100',
                   root/'reference/main.rs',root/'reference/mcp/runtime/storage.rs'],root),
        ('toolchain',[rust/'rustc','--version','--verbose'],root),
        ('cargo-version',[rust/'cargo','--version','--verbose'],root),
        ('strace-version',['/usr/bin/strace','--version'],root),
        ('native-build',[python,'-I','-B',root/'build_native.py','--hepta',m['compiler_root'],
                         '--output',run/'build'],root),
        ('rust-fetch',[rust/'cargo','fetch','--locked','--manifest-path',reference/'Cargo.toml'],reference),
        ('rust-vendor',[rust/'cargo','vendor','--locked','--offline','--versioned-dirs',
                        '--manifest-path',reference/'Cargo.toml',run/'vendor'],reference),
        ('rust-build',[rust/'cargo','build','--frozen','--verbose','--target','x86_64-unknown-linux-gnu',
                       '--manifest-path',reference/'Cargo.toml',*config],reference),
        ('native',[python,'-I','-B',root/'native_process.py','--build',run/'build',
                   '--output',run/'native','--fixture',m['owned_fixture']],root),
        ('original',['/usr/bin/strace','-qq','-f','-s','65536','-xx','-o',run/'original.strace',
                     '-e','trace=openat,newfstatat,fstat,statx,geteuid,read,write,writev,fsync,close,linkat,unlinkat,renameat,fcntl,getdents64',
                     python,'-I','-B',root/'original_process.py','--binary',run/'original.elf',
                     '--output',run/'original','--fixture',m['owned_fixture']],root)]
    return [dict(name=n,argv=[str(v) for v in argv],cwd=str(cwd),timeout=BUDGETS[n]) for n,argv,cwd in rows]
