#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Freeze actual runtime files and decode-expression source; zero decoder cases."""
import argparse,ast,codecs,importlib,json,os,platform,shutil,stat,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,require,pin,sha
NAMES=("json","json.decoder","json.encoder","codecs","encodings","encodings.aliases","encodings.utf_8",
    "encodings.utf_8_sig","encodings.utf_16","encodings.utf_16_le","encodings.utf_16_be",
    "encodings.utf_32","encodings.utf_32_le","encodings.utf_32_be","_json","_codecs")
def profile():
    return dict(version=list(sys.version_info[:3]),version_text=sys.version,platform=sys.platform,
        machine=platform.machine(),byteorder=sys.byteorder,integer_digits=sys.get_int_max_str_digits(),
        recursion_limit=sys.getrecursionlimit(),isolated=sys.flags.isolated,no_site=sys.flags.no_site,
        python=str(Path("/proc/self/exe").resolve()),executable=sys.executable)
def modules():
    for encoding in("utf-8","utf-8-sig","utf-16","utf-16-le","utf-16-be","utf-32","utf-32-le","utf-32-be"):
        codecs.lookup(encoding)
    return {name:importlib.import_module(name)for name in NAMES}
def function(raw,name):
    node=next(n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))and n.name==name)
    return ast.dump(node,include_attributes=False)
def prepare(output):
    require(not output.exists(),"fresh complete runtime source");output.mkdir(parents=True)
    p=profile();require(p["version"]==[3,12,3]and p["platform"]=="linux"and p["machine"]=="x86_64"
        and p["byteorder"]=="little"and p["integer_digits"]==4300 and p["recursion_limit"]==1000
        and p["isolated"]==p["no_site"]==1,"exact original runtime profile")
    loaded=modules();rows={};images={}
    executable=Path("/proc/self/exe").read_bytes();(output/"python.elf").write_bytes(executable);(output/"python.elf").chmod(0o755)
    images["python.elf"]=dict(path=p["python"],**pin(output/"python.elf"),mode=0o755)
    for name,module in loaded.items():
        origin=getattr(getattr(module,"__spec__",None),"origin",None);location=getattr(module,"__file__",None)
        row=dict(origin=origin,location=str(Path(location).resolve())if location else None)
        if location:
            path=Path(location).resolve();target=output/"modules"/name
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(path.read_bytes());target.chmod(0o644)
            row.update(file=target.relative_to(output).as_posix(),**pin(target))
        else:row.update(file="python.elf",**pin(output/"python.elf"))
        rows[name]=row
    actual=(output/rows["json"]["file"]).read_bytes()
    reference=(ROOT/"trusted-build/reference/cpython/Lib/json/__init__.py").read_bytes()
    require(function(actual,"detect_encoding")==function(reference,"detect_encoding"),"complete actual detect_encoding AST")
    maps=Path("/proc/self/maps").read_bytes();(output/"process-maps.txt").write_bytes(maps)
    for line in maps.decode().splitlines():
        parts=line.split(maxsplit=5)
        if len(parts)!=6 or not parts[5].startswith("/")or parts[5].endswith(" (deleted)"):continue
        path=Path(parts[5])
        if not path.is_file():continue
        body=path.read_bytes();digest=sha(body);name="images/"+digest
        target=output/name
        if not target.exists():target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body);target.chmod(0o644)
        images[name]=dict(path=str(path),**pin(target),mode=0o644)
    result=dict(schema="hepta.runtime.python-json-bytes.runtime.v1",profile=p,modules=rows,images=images,
        actual_detect_encoding_ast_sha256=sha(function(actual,"detect_encoding").encode()),maps=pin(output/"process-maps.txt"),
        application_calls=0)
    (output/"RUNTIME.json").write_bytes(canonical(result));return result
def verify_runtime(output):
    value=decode((output/"RUNTIME.json").read_bytes());require(profile()==value["profile"],"actual interpreter profile unchanged")
    loaded=modules()
    require(pin(output/"python.elf")==dict(bytes=len(Path("/proc/self/exe").read_bytes()),sha256=sha(Path("/proc/self/exe").read_bytes())),
        "whole actual running interpreter ELF")
    for name,row in value["modules"].items():
        module=loaded[name];origin=getattr(getattr(module,"__spec__",None),"origin",None);location=getattr(module,"__file__",None)
        require(origin==row["origin"]and(str(Path(location).resolve())if location else None)==row["location"],
            "exact module origin")
        require(pin(output/row["file"])=={k:row[k]for k in("bytes","sha256")},"whole copied runtime module")
        if location:require(pin(Path(location).resolve())=={k:row[k]for k in("bytes","sha256")},"actual runtime module bytes")
    for name,row in value["images"].items():
        require(pin(output/name)==pin(Path(row["path"]))=={k:row[k]for k in("bytes","sha256")},"whole runtime image source")
    return value
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    print(canonical(prepare(a.output.absolute())).decode(),end="")
