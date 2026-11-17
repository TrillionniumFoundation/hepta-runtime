#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Only inherited test capabilities; exec the exact admitted native image."""
import os,sys
assert len(sys.argv)==11
image,config=sys.argv[1:3];sources=list(map(int,sys.argv[3:]))
targets=(3,4,6,5,7,8,9,10)
assert len(set(sources))==8 and min(sources)>=32
for source,target in zip(sources,targets,strict=True):
    os.fstat(source);os.dup2(source,target,inheritable=True)
for source in sources:os.close(source)
os.execve(image,[image,"--runtime-config",config],os.environ.copy())
