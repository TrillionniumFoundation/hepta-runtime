#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Input-only current publication body domain; no expected wire or synthetic result."""
import hashlib
from pathlib import Path
from common import canonical

def file(path="file", data=b"old text\n", mode=0o600, **kwargs):
    row=dict(kind="file", path=path, data=data.hex(), mode=mode)
    row.update(kwargs); return row

def repeated(path, unit, count, mode=0o600):
    return dict(kind="file", path=path, repeat=dict(unit=unit.hex(), count=count), mode=mode)

def payload(row):
    if "data" in row:
        return bytes.fromhex(row["data"])
    value=row["repeat"]
    return bytes.fromhex(value["unit"])*value["count"]

def cases():
    rows=[]
    def add(name, mode, content="", initial=None, expected=None, path="file", path_form="absolute"):
        rows.append(dict(id=len(rows), name=name, mode=mode, content=content,
            initial=list(initial or []), expected=expected, path=path, path_form=path_form))
    for mode in ("create","replace","append"):
        for label,text in (("empty",""),("ascii","new text\n"),("unicode","中文 α 🦀\n"),
                           ("controls","A\0B\tC\r\n\"\\\b\f"),("multiline","a\nb\nc\n")):
            add(mode+"-"+label,mode,text,[] if mode=="create" else [file()])
    for mode in ("create","replace","append"):
        initial=[] if mode=="create" else [file()]
        add(mode+"-input-exact64k",mode,"x"*65536,initial)
        add(mode+"-input-over64k",mode,"x"*65537,initial)
    add("create-already-existing","create","new",[file()])
    for mode in ("replace","append"):
        add(mode+"-missing-source",mode,"new",[],expected="0"*64)
        add(mode+"-stale-digest",mode,"new",[file()],expected="0"*64)
        add(mode+"-empty-existing",mode,"new",[file(data=b"")])
        add(mode+"-unicode-existing",mode,"tail",[file(data="中文\n".encode())])
    for value in ("", "absent", "f"*63, "f"*65, "A"*64, "g"*64, "0 "*32):
        add("replace-expect-"+str(len(rows)),"replace","new",[file()],expected=value)
    for value in ("", "ABSENT", "0"*64):
        add("create-expect-"+str(len(rows)),"create","new",expected=value)
    add("validation-order","replace","x"*65537,[file()],expected="wrong")
    for mode in ("create","replace","append"):
        add(mode+"-unicode-path",mode,"ok",[] if mode=="create" else [file("目录/λ.txt")],path="目录/λ.txt")
        add(mode+"-quotes-path",mode,"ok",[] if mode=="create" else [file('space a/"quote\\tail')],path='space a/"quote\\tail')
    for mode in ("replace","append"):
        for bits in (0o644,0o640,0o600,0o400,0o700,0o2600):
            add(mode+"-permissions-"+oct(bits),mode,"new",[file(mode=bits)])
        add(mode+"-source-utf8-error",mode,"new",[file(data=b"\xff\xfe")])
        add(mode+"-source-xattr",mode,"new",[file(xattr={"user.publication-test":"kept"})])
        add(mode+"-source-hardlink",mode,"new",[file(),dict(kind="hardlink",path="other",target="file")])
        add(mode+"-source-symlink",mode,"new",[file("real"),dict(kind="symlink",path="file",target="real")],expected=hashlib.sha256(b"old text\n").hexdigest())
        add(mode+"-directory-target",mode,"new",[dict(kind="dir",path="file",mode=0o700)],expected="0"*64)
    for mode in ("create","replace","append"):
        add(mode+"-missing-parent",mode,"x",[],expected="absent" if mode=="create" else "0"*64,path="missing/file")
    add("create-parent-symlink","create","new",[dict(kind="dir",path="real",mode=0o700),dict(kind="symlink",path="alias",target="real")],path="alias/file")
    add("create-relative-path","create","new",path_form="relative")
    add("create-redundant-separators","create","new",path="sub//./file")
    add("create-final-dot","create","new",[dict(kind="dir",path="sub",mode=0o700)],path="sub/.")
    add("create-trailing-slash","create","new",path="file/")
    add("create-nul-name","create","new",path="nu\0l")
    add("replace-max-reader","replace","short",[repeated("file",b"x",4*1024*1024)])
    add("append-max-result","append","z"*65536,[repeated("file",b"x",4*1024*1024)])
    add("replace-reader-over","replace","short",[repeated("file",b"x",4*1024*1024+1)])
    add("append-reader-over","append","short",[repeated("file",b"x",4*1024*1024+1)])
    return rows

def request(case, root):
    target=case["path"] if case["path_form"]=="relative" else str(Path(root))+"/"+case["path"]
    expected=case["expected"]
    if expected is None:
        if case["mode"]=="create":
            expected="absent"
        else:
            matching=[r for r in case["initial"] if r["kind"]=="file" and r["path"]==case["path"]]
            expected=hashlib.sha256(payload(matching[0])).hexdigest() if matching else "0"*64
    return dict(id=case["id"], path=target, mode=case["mode"], content=case["content"], expected_sha256=expected)

def domain():
    rows=cases()
    return dict(schema="hepta.runtime.text-publication.body-domain.v1", cases=rows,
        input_only=True, expected_wire_embedded=False, configured_path_is_precondition=True,
        ordinary_source_tests_retained=8, limit_seconds_per_exchange=60, limit_seconds_per_native_process=180)
