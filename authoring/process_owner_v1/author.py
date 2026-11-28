"""Author private process parameter and control images; no runtime policy executes here."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, stat, sys
from pathlib import Path
SHA=lambda b:hashlib.sha256(b).hexdigest()
ENC=lambda x:(json.dumps(x,sort_keys=True,indent=2)+"\n").encode()
WORD=lambda x:int.from_bytes(x.encode(),"little")
ROOT=Path(__file__).resolve().parents[2]
KINDS={"string":1,"option_string":2,"option_u64":3,"option_u8":4,"option_u16":5,"string_vec":6,"string_map":7}

def fields(schemas):
    names={}
    for schema in schemas:
        for name,index,kind in schema["fields"]:
            if name in names and names[name]!=index:raise ValueError("field number changed")
            names[name]=index
    out=["def field_key(s: readbuf, start: u64, end: u64) -> u64:"]
    for name,index in sorted(names.items(),key=lambda kv:kv[1]):
        raw=json.dumps(name,separators=(",",":")).encode()
        out += [f"    if end - start == {len(raw)}:", "        same = 1"]
        chunks=len(raw)//8*8
        for i in range(0,chunks,8):
            out += [f"        if load(s, start + {i}) != {int.from_bytes(raw[i:i+8],'little')}:", "            same = 0"]
        for i in range(chunks,len(raw)):
            out += [f"        if byte(s, start + {i}) != {raw[i]}:", "            same = 0"]
        out += ["        if same != 0:",f"            return {index}"]
    out += ["    return 0","","def field_type(kind: u64, field: u64) -> u64:"]
    for schema in schemas:
        out += [f"    if kind == {schema['id']}:"]
        for name,index,kind in schema["fields"]:
            out += [f"        if field == {index}:",f"            return {KINDS[kind]}"]
        out += ["        return 0"]
    out += ["    return 0","","def required(kind: u64, present: u64) -> u64:"]
    for schema in schemas:
        required=[(name,index) for name,index,kind in schema["fields"] if kind=="string"]
        if not required:continue
        out += [f"    if kind == {schema['id']}:"]
        for name,index in required:
            code=210 if schema["id"]==1 else 100+index
            out += [f"        if (present & {1<<index}) == 0:",f"            return {code}"]
        out += ["        return 0"]
    return "\n".join(out+["    return 0"])+"\n"

def literals(schemas):
    values={3:b"invalid type: ",4:b", expected ",5:b"a string",14:b"unknown field \x60",
        16:b"invalid value: ",17:b"u64",18:b"u8",19:b"u16",20:b"a sequence",21:b"a map",
        210:b"Missing required 'command' parameter",211:b"Command parameter must be a string"}
    for schema in schemas:
        names=[name for name,index,kind in schema["fields"]]
        expected="one of "+", ".join("\x60"+name+"\x60" for name in names)
        if len(names)==1:expected="\x60"+names[0]+"\x60"
        if len(names)==2:expected=" or ".join("\x60"+name+"\x60" for name in names)
        values[300+schema["id"]]=("\x60, expected "+expected).encode()
        for name,index,kind in schema["fields"]:
            if kind=="string":values[100+index]=("missing field \x60"+name+"\x60").encode()
    out=["def literal(w: mutbuf, o: mutbuf, code: u64) -> u64:",
        "    size = literal_size(code)","    index = 0","    while index < size:",
        "        word = literal_word(code, index // 8)",
        "        emit(w, o, (word >> ((index % 8) * 8)) & 255)",
        "        index = index + 1","    return 0","",
        "def literal_size(code: u64) -> u64:"]
    for code,raw in sorted(values.items()):out += [f"    if code == {code}:",f"        return {len(raw)}"]
    out += ["    return 0","","def literal_word(code: u64, index: u64) -> u64:"]
    for code,raw in sorted(values.items()):
        out += [f"    if code == {code}:"]
        for i in range(0,len(raw),8):
            out += [f"        if index == {i//8}:",f"            return {int.from_bytes(raw[i:i+8],'little')}"]
        out += ["        return 0"]
    return "\n".join(out+["    return 0"])+"\n"

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta",type=Path,required=True)
    p.add_argument("--source",type=Path,default=ROOT)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args(); source=a.source.resolve(strict=True); output=a.output.absolute()
    if output.exists():raise FileExistsError(output)
    own="authoring/process_owner_v1/"
    names=[own+"author.py",own+"parameters.pseudo",own+"SCHEMAS.json",own+"original_sources.json",
        "authoring/public_publication_v1/source_support.py","native/binary_write_params.hepta",
        "native/binary_write_params_composition.json","src/mcp/runtime/jobs.rs",
        "src/mcp/runtime/operator.rs","src/mcp/fs/shell.rs"]
    def take(name):
        path=source/name; info=path.lstat()
        if path.resolve(strict=True)!=path or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
            raise ValueError("not an independent physical source: "+name)
        raw=path.read_bytes()
        after=path.lstat()
        fields=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
        if any(getattr(info,k)!=getattr(after,k) for k in fields):raise ValueError("source changed while read: "+name)
        return raw
    initial={name:take(name) for name in names}
    original=json.loads(initial[own+"original_sources.json"])
    for row in original["files"]:
        if row["path"] in initial:
            raw=initial[row["path"]]
            if len(raw)!=row["bytes"] or SHA(raw)!=row["sha256"]:
                raise ValueError("original whole source differs: "+row["path"])
    schema=json.loads(initial[own+"SCHEMAS.json"])["types"]
    if [s["id"] for s in schema]!=list(range(1,10)):raise ValueError("nine exact methods required")
    meta=json.loads(initial["native/binary_write_params_composition.json"])
    base=initial["native/binary_write_params.hepta"]
    if SHA(base)!=meta["source_sha256"] or len(base)!=meta["source_bytes"]:
        raise ValueError("parameter decoder source differs")
    path=source/"authoring/public_publication_v1/source_support.py"
    import types as _types
    support=_types.ModuleType("_process_original_source_support");support.__file__=str(path)
    exec(compile(initial["authoring/public_publication_v1/source_support.py"],str(path),"exec"),support.__dict__)
    api=support.tools(a.hepta)
    imported=["load","get","put","string_info","copy_string","skip_value","unexpected",
              "raw_scalar","unicode_table","unit","integer","emit"]
    roots={name:meta["aliases"][name] for name in imported}
    pseudo=initial[own+"parameters.pseudo"].decode()+"\n"+fields(schema)+"\n"+literals(schema)
    constants={"INVALID":0xffffffff,"CAPACITY":0xfffffffe,"MAXIMUM":(1<<64)-1,
        "REQUEST":WORD("HPRPAQ01"),"RESPONSE":WORD("HPRPAR01"),"HEADER":640,"META":65536}
    raw,aliases,proof=support.compile_new(api,base,roots,pseudo,constants,"runtime_process_params")
    if any(take(n)!=b for n,b in initial.items()):raise ValueError("author inputs changed")
    output.mkdir(parents=True)
    receipt={"schema":"hepta.runtime.process-params.v1",**proof,"aliases":aliases,"constants":constants,
        "source_sha256":SHA(raw),"source_bytes":len(raw),
        "input_files":{n:{"bytes":len(b),"sha256":SHA(b)} for n,b in initial.items()},
        "methods":[s["name"] for s in schema],"canonical_map_required":True,
        "body_policy":False,"installed_configuration":False,"effects":False,
        "native_compiled":False,"native_executed":False,"public_handler_qualified":False}
    (output/"process_params.hepta").write_bytes(raw)
    (output/"process_params_composition.json").write_bytes(ENC(receipt))
    (output/"process_params.pseudo").write_text(pseudo)
    if any(take(n)!=b for n,b in initial.items()):raise ValueError("author inputs changed at terminal")
    print(json.dumps({"source":str(output/"process_params.hepta"),"bytes":len(raw),"sha256":SHA(raw),
        "functions":proof["functions"],"blocks":proof["blocks"],"operations":proof["operations"]}))
if __name__=="__main__":main()
