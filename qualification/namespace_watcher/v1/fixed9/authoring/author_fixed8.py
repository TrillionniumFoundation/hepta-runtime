"""Reproduce the old Watcher then unroll only its three fixed-eight byte helpers.

The imported old helper proof is reused unchanged. This author requires the
entire original owner and proves every ordered checked access and return equal.
It neither runs Watcher nor calls Rust.
"""
import argparse, contextlib, hashlib, importlib.util, io, json, sys
from pathlib import Path

BEFORE = "df978d42a0777fcdbbd3b537611c9ea8bcf1dc5eb78bfa47a1ab2e4c87afe414"
AFTER = "b7947d6c8922b28a25499fd8bf20f84879f5fe32e8a33f546d0fdb16ec38a06f"
PROOF = "28fd569331b006d164322f3dce67a312c82d217bed01d9df39ce2b04cc2f2371"

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())

def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()

def linear(name, kind, put=False):
    n=3 if put else 2
    params="v0:"+kind+",v1:u64"+(",v2:u64" if put else "")
    lines=["fn "+name+"("+params+") -> (u64) effects(read,write,trap) entry(b0)",
           "block b0("+params+")"]
    def op(kind, rhs):
        nonlocal n
        v="v"+str(n);n+=1;lines.append("  "+v+":"+kind+" = "+rhs);return v
    def const(value):return op("u64",'const() {"value":'+str(value)+'}')
    value="v2" if put else const(0)
    for i in range(8):
        at=op("u64","int.add.wrap(v1,"+const(i)+")")
        if put:
            byte=op("u64","bit.and("+value+","+const(255)+")")
            index=op("usize",'int.cast('+at+') {"mode":"wrap"}')
            small=op("u8",'int.cast('+byte+') {"mode":"wrap"}')
            lines.append("  _ = buffer.store(v0,"+index+","+small+")")
            value=op("u64","int.shr.checked("+value+","+const(8)+")")
        else:
            index=op("usize",'int.cast('+at+') {"mode":"wrap"}')
            byte=op("u8","buffer.load(v0,"+index+")")
            wide=op("u64",'int.cast('+byte+') {"mode":"wrap"}')
            shifted=op("u64","int.shl.checked("+wide+","+const(i*8)+")")
            value=op("u64","bit.or("+value+","+shifted+")")
    result=const(0) if put else value
    lines.extend(["  ret("+result+")","end"])
    return "\n".join(lines)+"\n"

def generate(before):
    assert hashlib.sha256(before).hexdigest()==BEFORE
    text=before.decode()
    assert text.count("fn f26(")==text.count("fn f27(")==text.count("fn f28(")==1
    prefix=text[:text.index("fn f26(")]
    result=(prefix+linear("f26","mutbuf")+linear("f27","mutbuf",True)+linear("f28","readbuf")).encode()
    assert hashlib.sha256(result).hexdigest()==AFTER
    return result

def module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj

def run(root, hepta, output):
    sys.dont_write_bytecode=True;sys.path.insert(0,str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    before=(root/"baseline/namespace_watcher.hepta").read_bytes()
    baseline_composition=(root/"baseline/namespace_watcher.composition.json").read_bytes()
    after=generate(before)
    assert (root/"native/namespace_watcher.hepta").read_bytes()==after
    output.mkdir(parents=True,exist_ok=False)
    original=module("_watcher_original_owner_author",root/"authoring/author_owner.py")
    with contextlib.redirect_stdout(io.StringIO()):
        original.generate(root,hepta,output/"baseline-reproduced")
    assert (output/"baseline-reproduced/namespace_watcher.hepta").read_bytes()==before
    assert (output/"baseline-reproduced/namespace_watcher.composition.json").read_bytes()==baseline_composition
    report=proof(root,hepta)
    (output/"PROOF.json").write_bytes(encoded(report))
    print(encoded(report).decode(),end="")

def proof(root,hepta):
    sys.dont_write_bytecode=True;sys.path.insert(0,str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    before=(root/"baseline/namespace_watcher.hepta").read_bytes()
    baseline_composition=(root/"baseline/namespace_watcher.composition.json").read_bytes()
    after=generate(before)
    assert (root/"native/namespace_watcher.hepta").read_bytes()==after
    proof_path=root/"authoring/prove_fixed_byte_access.py"
    assert hashlib.sha256(proof_path.read_bytes()).hexdigest()==PROOF
    checker=module("_watcher_exact_fixed_eight_proof",proof_path)
    old=assemble_program(before).as_dict();new=assemble_program(after).as_dict()
    old_f={f["name"]:f for f in old["functions"]}
    new_f={f["name"]:f for f in new["functions"]}
    changed={"f26","f27","f28"}
    assert list(old_f)==list(new_f)==["f"+str(i) for i in range(29)]
    assert {k:v for k,v in old.items() if k!="functions"}=={k:v for k,v in new.items() if k!="functions"}
    assert all(old_f[k]==new_f[k] for k in old_f if k not in changed)
    rows=[]
    for name in sorted(changed):
        first=checker.symbolic(old_f[name]);second=checker.symbolic(new_f[name])
        assert first==second,(name,"ordered checked memory or return changed")
        assert len(new_f[name]["blocks"])==1
        rows.append(dict(function=name,proof=first,all_addresses_and_values_symbolic=True,
            ordered_bounds_checks_equal=True,partial_store_effects_equal=True))
    shape=dict(functions=len(new_f),blocks=sum(len(f["blocks"]) for f in new_f.values()),
        operations=sum(len(b["ops"]) for f in new_f.values() for b in f["blocks"]))
    assert shape["operations"]<=8192
    assert all(len(f["blocks"])<=256 and all(len(b["params"])<=16 for b in f["blocks"]) for f in new_f.values())
    report=dict(schema="hepta.namespace-watcher.fixed-eight-proof.v1",
        status="SYMBOLIC_FIXED_EIGHT_ACCESS_EQUIVALENCE_PASS",
        before=pin(before),after=pin(after),author=pin(Path(__file__).read_bytes()),
        symbolic_proof_source=pin(proof_path.read_bytes()),baseline_composition=pin(baseline_composition),
        shape=shape,functions=rows,unchanged_full_function_asts=26,
        unchanged_raw_prefix=pin(before[:before.index(b"fn f26(")]),
        cases_enumerated=False,application_native_executions=0,rust_executions=0,
        watcher_qualified=False,namespace_version_qualified=False,public_handler_qualified=False,
        whole_runtime_replaced=False)
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("root","hepta","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();run(a.root.resolve(strict=True),a.hepta.resolve(strict=True),a.output.absolute())
