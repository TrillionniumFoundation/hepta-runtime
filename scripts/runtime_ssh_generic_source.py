"""Exact source projection of the retained original direct-SSH mechanical owner.

The five HIA policy images are unchanged. Only three final-notification labels
are wrapped by the explicit runtime extension. Read-only legacy singleton
storage remains unreachable from the private runtime constructor.
"""
from pathlib import Path
import hashlib,json,stat
SHA=lambda b:hashlib.sha256(b).hexdigest()
EXPECTED={'asm/ssh_direct/core.S': {'bytes': 16914, 'sha256': '6032713d4ff69dfb5968f39ce1d75d32a1beb6f4a8e505c0dd2bc22a7f7ea979'}, 'asm/ssh_direct/api.S': {'bytes': 17156, 'sha256': '2cbdb8b069f5118f1202bc67e6937f91937e4c4fbdc857042da97ffdd4284ae9'}, 'asm/ssh_direct/spawn.S': {'bytes': 7056, 'sha256': '59d056b323660fc8ceaecee024cbd5795a5899562bcb4a28a7a135bdae393036'}, 'asm/ssh_direct/ownership.S': {'bytes': 12672, 'sha256': '00010530d34a8e95871ea5c8e40ed8b7a6dba74529dc7812790846fc86f0a96e'}, 'asm/ssh_direct/io.S': {'bytes': 11579, 'sha256': 'e12fde415ca6936ce6ff094179a0be7bb47734baec1d772e14481778d3f9f331'}, 'asm/ssh_direct/owner.S': {'bytes': 10906, 'sha256': '2ebdfc6f455e9db175573a58cb7639e518df31e006315d2902245f7b93a43ca6'}, 'asm/ssh_direct/future.S': {'bytes': 4064, 'sha256': '39caf8cb278b49689cb135454c04eae56ab2468f8f67e709bf93043904aaa3c4'}, 'asm/ssh_direct/private.S': {'bytes': 6925, 'sha256': '29f86e80c841562415f93b0d643fd1843bfb053714fdb6a062649c330189864c'}}
SOURCES=tuple(EXPECTED)
EXTENSION='asm/ssh_direct/runtime.S'
def generic_owner_source(root:Path)->str:
    root=root.resolve(strict=True)
    captured={}
    for name,expected in EXPECTED.items():
        p=root/name;st=p.lstat()
        if p.resolve(strict=True)!=p or not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:
            raise ValueError('generic SSH source is not a private regular input: '+name)
        raw=p.read_bytes()
        if {'bytes':len(raw),'sha256':SHA(raw)}!=expected:
            raise ValueError('retained generic SSH whole source differs: '+name)
        captured[name]=raw
    e=root/EXTENSION;st=e.lstat()
    if e.resolve(strict=True)!=e or not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:
        raise ValueError('generic SSH runtime extension differs')
    extension=e.read_bytes()
    text='\n'.join(raw.decode('utf-8') for raw in captured.values())
    for label in ('ssh_finish_request','ssh_quarantine','ssh_join_notify'):
        old='\n'+label+':'
        if text.count(old)!=1:raise ValueError('retained method definition differs: '+label)
        text=text.replace(old,'\n'+label+'_runtime_inner:',1)
    # The actual HIA static linker consumes one RX text section. This projection
    # relocates constants and unreachable legacy singleton words, not policy.
    text=text.replace('.section .rodata','.section .text').replace('.section .bss','.section .text')
    for name,raw in captured.items():
        if (root/name).read_bytes()!=raw:raise ValueError('generic SSH source changed: '+name)
    if e.read_bytes()!=extension:raise ValueError('generic SSH extension changed')
    return text+'\n'+extension.decode('utf-8')
