"""Read all retained actual interpreter/module bytes without loading that interpreter."""
from pathlib import Path
import stat
from common import decode,owned,pin,require,sha
from runtime import function,NAMES
def verify(source,folder):
    value=decode(owned(folder,"RUNTIME.json").read_bytes());p=value["profile"]
    require(value["schema"]=="hepta.runtime.python-json-bytes.runtime.v1"and value["application_calls"]==0
        and p["version"]==[3,12,3]and p["platform"]=="linux"and p["machine"]=="x86_64"and p["byteorder"]=="little"
        and p["integer_digits"]==4300 and p["recursion_limit"]==1000 and p["isolated"]==p["no_site"]==1,
        "retained actual interpreter profile")
    require(set(value["modules"])==set(NAMES)and value["maps"]==pin(owned(folder,"process-maps.txt")),
        "complete retained original module set")
    files={"RUNTIME.json","process-maps.txt"}
    for name,row in value["modules"].items():
        path=owned(folder,row["file"]);require(pin(path)=={k:row[k]for k in("bytes","sha256")},"retained runtime module bytes")
        require(stat.S_IMODE(path.stat().st_mode)==(0o755 if row["file"]=="python.elf"else 0o644),"retained runtime module mode")
        files.add(row["file"])
    for name,row in value["images"].items():
        path=owned(folder,name);require(pin(path)=={k:row[k]for k in("bytes","sha256")}
            and stat.S_IMODE(path.stat().st_mode)==row["mode"],"retained actual runtime image bytes")
        files.add(name)
    actual=owned(folder,value["modules"]["json"]["file"]).read_bytes()
    reference=owned(source,"trusted-build/reference/cpython/Lib/json/__init__.py").read_bytes()
    ast=function(actual,"detect_encoding")
    require(ast==function(reference,"detect_encoding")and sha(ast.encode())==value["actual_detect_encoding_ast_sha256"],
        "actual original detect_encoding function source")
    require({p.relative_to(folder).as_posix()for p in folder.rglob("*")if p.is_file()}==files,"complete retained runtime file set")
    return value
