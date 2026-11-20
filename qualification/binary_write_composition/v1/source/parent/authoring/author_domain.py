#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Freeze every parent input; this author never runs either application or oracle."""
import base64
import hashlib
import json
from pathlib import Path


def domain():
    cases=[]

    def add(name,root="{R}",path="{R}/file",prior="absent",data="AA==",plans=(),actor=0,fd0=False,nofile=0,fsize=None):
        cases.append(dict(id=len(cases),name=name,root=root,path=path,expected_version=prior,data_base64=data,
                          fault_plans=[list(plan)for plan in plans],descriptor_actor=actor,fd0=fd0,
                          nofile=nofile,fsize=fsize))

    roots=("{R}","{R}/","{R}/./","{R}//a/..","{R}/a","//{R0}","/","//",".","","relative","{R}/\0")
    paths=("{R}/file","{R}//a/./b//file/","{R}/a/../file","{R}","{R}/.hepta-private",
           "{R}/a/.hepta-","{R}/.hepta","{R}/.Hepta-x","{R}/a/雪.bin","//{R0}/file",
           "relative","",".","/outside/file","{R}/nul\0part/file","{R}/name\0tail")
    for root_index,root in enumerate(roots):
        for path_index,path in enumerate(paths):
            add("lexical-root-%02d-path-%02d"%(root_index,path_index),root,path)
    for name,path in (
        ("missing-parent","{R}/missing/file"),("regular-parent","{R}/ordinary/file"),
        ("symlink-parent","{R}/linkdir/file"),("symlink-outside","{R}/outside-link/file"),
        ("denied-parent","{R}/denied/file"),("double-leading-root","//{R0}/a/b/file"),
        ("triple-leading-path","///{R0}/a/b/file"),("four-leading-path","////{R0}/file"),
        ("unicode-bmp","{R}/a/雪.bin"),("unicode-supplementary","{R}/a/𐐷.bin"),
        ("backslash-component","{R}/back\\slash/file"),("long-component-255","{R}/"+"x"*255+"/file"),
        ("long-component-256","{R}/"+"x"*256+"/file"),("destination-directory","{R}/directory"),
        ("destination-symlink","{R}/targetlink"),("destination-fifo","{R}/fifo"),
        ("prior-existing","{R}/existing.bin"),("deep-12","{R}/"+"/".join("d"+str(i)for i in range(12))+"/file"),
        ("nul-first-component","/\0/file"),("nul-parent-after-two","{R}/a/b\0/file"),
        ("nul-basename","{R}/a/name\0tail")):
        add(name,root="/"if name=="nul-first-component"else"//{R0}"if name=="double-leading-root"else"{R}",path=path)
    add("empty-data",data="")
    add("binary-data",data=base64.b64encode(bytes(range(256))*8).decode())
    add("maximum-write",data=base64.b64encode(b"x"*1048576).decode())
    add("too-large-write",data=base64.b64encode(b"x"*1048577).decode())
    add("expected-none",prior=None)
    add("expected-wrong",prior="0:0:0:0:0")
    add("base64-invalid",data="!bad")
    for number in (1,2,5,13,24,36):
        add("root-open-errno-"+str(number),plans=((6,2,1,1,257,number,0),))
    for number in (1,2,5,13,20,24,36):
        add("child-open-errno-"+str(number),plans=((6,4,2,1,257,number,1),))
    for number in (4,5,9,28):
        add("old-close-twice-errno-"+str(number),plans=((6,5,3,1,3,number,1),))
    add("second-close-overrides-first",plans=((6,5,3,1,3,5,1),(6,6,3,1,3,13,1)))
    add("cleanup-close-overrides-open",plans=((6,4,2,1,257,2,1),(6,91,3,1,3,9,1)))
    add("old-close-fails-second-succeeds",actor=1)
    for number in (4,5,9,28):
        add("outer-close-after-success-"+str(number),plans=((6,9,3,1,3,number,1),))
    for name,prior,data,path in (
        ("prior",None,"AA==","{R}/file"),("base64","absent","!bad","{R}/file"),
        ("nul","absent","AA==","{R}/name\0tail"),("directory","absent","AA==","{R}/directory")):
        add("outer-close-overrides-"+name,prior=prior,data=data,path=path,plans=((6,9,3,1,3,5,1),))
    add("fd-zero-regular",fd0=True)
    add("fd-zero-deep",path="{R}/a/b/file",fd0=True)
    add("fd-zero-nul-basename",path="{R}/name\0tail",fd0=True)
    add("fd-zero-second-close",fd0=True,plans=((6,5,3,1,3,5,1),(6,6,3,1,3,13,1)))
    add("nofile-root-open",nofile=6)
    add("nofile-child-open",nofile=7)
    add("fsize-zero-body",fsize=0)
    add("fsize-zero-outer-overrides",fsize=0,plans=((6,9,3,1,3,5,1),))
    names=[row["name"]for row in cases]
    assert len(names)==len(set(names)) and len(cases)==256
    retries=[]
    for identifier,phase,operation,label in((0,2,1,"root"),(1,4,2,"child")):
        retries.append(dict(id=identifier,name=label+"-open-eintr-cancellation",root="{R}",path="{R}/file",
            expected_version="absent",data_base64="AA==",fault_plans=[[6,phase,operation,1,257,4,int(phase==4)]],
            descriptor_actor=0,fd0=False,nofile=0,fsize=None,retry_phase=phase,
            actual_eintr_returns_before_sigterm=8))
    return dict(schema="hepta.runtime.binary-parent-domain.v1",cases=cases,case_count=len(cases),
                retry_controls=retries,retry_lanes=["original-1","original-2","native-observed"],
                retry_control_count=6,retry_terminal="actual SIGTERM after eight actual unchanged -EINTR returns; no normal result",
                complete_lexical_product=dict(root_variants=len(roots),path_variants=len(paths),cases=len(roots)*len(paths)),
                ordinary_cases=len(cases)-len(roots)*len(paths),
                original_source_sha256="c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12",
                original_python=dict(version=[3,12,3],bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"),
                limits=dict(exchange_seconds=60,case_seconds=180,whole_capture_seconds=1800,cleanup_seconds=5,
                            input_bytes=134217728,output_bytes=134217728,workspace_bytes=268435456),
                lanes=["original-1","original-2","native-observed","native-unobserved"],
                native_unobserved_domain="all cases without actual kernel fault plans, descriptor actor or nofile limit",
                scope="complete retained parent and main(write) final-close composition for the frozen input matrix",
                old_body_101_requalified=False,public_route_qualified=False,whole_runtime_replaced=False)


if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise ValueError("fresh domain output required")
    value=domain()
    raw=(json.dumps(value,indent=2,sort_keys=True)+"\n").encode()
    args.output.write_bytes(raw)
    print(json.dumps(dict(cases=value["case_count"],bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),sort_keys=True))
