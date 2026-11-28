# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Byte-only installed state inventory shared with the actual recorder."""
from pathlib import Path
import stat
from common import pin,require
def state_inventory(folder):
    out={}
    if not folder.exists():return out
    for path in [folder,*sorted(folder.rglob("*"))]:
        st=path.lstat();require(stat.S_ISREG(st.st_mode)or stat.S_ISDIR(st.st_mode),"native state entry kind")
        row=dict(mode=stat.S_IMODE(st.st_mode),uid=st.st_uid,gid=st.st_gid,nlink=st.st_nlink,kind="file"if stat.S_ISREG(st.st_mode)else"directory")
        if stat.S_ISREG(st.st_mode):row.update(pin(path))
        out["."if path==folder else path.relative_to(folder).as_posix()]=row
    return out
