#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Test-owned inherited descriptors only; then exec the exact native image."""
import os,sys
assert len(sys.argv)==6
image,config=sys.argv[1:3];sources=list(map(int,sys.argv[3:]))
assert len(set(sources))==3 and min(sources)>=20
for source,target in zip(sources,(3,4,6)):
    os.fstat(source)
    os.dup2(source,target,inheritable=True)
for source in sources:os.close(source)
os.execve(image,[image,"--runtime-config",config],os.environ.copy())
