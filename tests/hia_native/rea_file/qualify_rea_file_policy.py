"""Compare HIA REA path planning with the original Rust admission statements."""
from pathlib import Path
import argparse, hashlib, json, os, random, struct, subprocess, sys, time

MAGIC = b"HREAFPL1"
RESULT = b"HRFPLAN1"
U64 = (1 << 64) - 1

RUST_PREFIX = r'''
use std::ffi::{CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf, Component};
use std::io::{Read, Write};
type Result<T> = std::result::Result<T, String>;
macro_rules! bail { ($s:literal) => { return Err($s.to_string()) }; }
trait Context<T> { fn context(self, message: &str) -> Result<T>; }
impl<T,E> Context<T> for std::result::Result<T,E> {
 fn context(self, message: &str) -> Result<T> { self.map_err(|_| message.to_string()) }
}
fn plan(path: &Path, roots: &[PathBuf]) -> Result<(Vec<u8>,Vec<Vec<u8>>)> {
'''
RUST_SUFFIX = r'''
        return Ok((root_path.as_bytes().to_vec(),
                   components.into_iter().map(|v|v.into_bytes()).collect()));
    }
    bail!("REA inspection denied: path is outside controller workspace roots");
}
fn word(b:&[u8],p:usize)->u64 { u64::from_le_bytes(b[p..p+8].try_into().unwrap()) }
fn emit(v:&mut Vec<u8>,x:u64) { v.extend_from_slice(&x.to_le_bytes()); }
fn evaluate(b:&[u8])->Vec<u8> {
 assert!(b.len()>=32 && &b[..8]==b"HREAFPL1" && word(b,8)==1);
 let length=word(b,16) as usize;
 let path=PathBuf::from(OsString::from_vec(b[32..32+length].to_vec()));
 let mut p=32+length;
 let mut roots=Vec::new();
 for _ in 0..word(b,24) {
  let n=word(b,p)as usize; p+=8;
  roots.push(PathBuf::from(OsString::from_vec(b[p..p+n].to_vec())));p+=n;
 }
 assert_eq!(p,b.len());
 let result=plan(&path,&roots);
 let errors=[
 "REA native inspection requires an absolute local path",
 "REA inspection denied: no controller workspace roots configured",
 "REA inspection denied: configured workspace root must be absolute",
 "REA inspection denied: parent or non-normal path component",
 "REA inspection path contains NUL",
 "REA inspection requires a regular file, not a workspace root",
 "REA configured root contains NUL",
 "REA inspection denied: path is outside controller workspace roots"];
 let mut out=b"HRFPLAN1".to_vec();
 match result {
  Err(error)=> {
   let code=errors.iter().position(|s|*s==error).unwrap()as u64+1;
   emit(&mut out,1);emit(&mut out,code);
   emit(&mut out,0);emit(&mut out,0);emit(&mut out,0);
  }
  Ok((root,names))=> {
   emit(&mut out,0);emit(&mut out,0);emit(&mut out,root.len()as u64);
   emit(&mut out,names.len()as u64);
   emit(&mut out,names.iter().map(|s|s.len()as u64+1).sum());
   out.extend_from_slice(&root);out.push(0);
   for name in names {out.extend_from_slice(&name);out.push(0);}
  }
 }
 out
}
fn main() {
 let mut input=Vec::new();std::io::stdin().read_to_end(&mut input).unwrap();
 let mut p=0;let mut out=Vec::new();
 while p<input.len() {
  let n=word(&input,p)as usize;p+=8;let result=evaluate(&input[p..p+n]);p+=n;
  emit(&mut out,result.len()as u64);out.extend_from_slice(&result);
 }
 std::io::stdout().write_all(&out).unwrap();
}
'''

def frame(path, roots):
    return MAGIC + struct.pack("<3Q", 1, len(path), len(roots)) + path + b"".join(
        struct.pack("<Q", len(root)) + root for root in roots)

def reply(code):
    return RESULT + struct.pack("<5Q", bool(code), code, 0, 0, 0)

def main():
    ap = argparse.ArgumentParser()
    for name in ("source", "original", "manifest", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    ap.add_argument("--rustc", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(mode=0o700, exist_ok=False)
    out = args.output
    sha = lambda b: hashlib.sha256(b).hexdigest()
    original = args.original.read_bytes()
    if sha(original) != "a4c920dd16647f3a61cbf1f9e68b9510ae123d2d7b2a8fd6b72f13ec147f0d11":
        raise ValueError("original REA file admission source differs")
    text = original.decode()
    a = text.index("\tif !path.is_absolute()", text.index("pub(super) async fn open_confined("))
    b = text.index("\tlet chosen =", a)
    c = text.index("\tfor root in roots {", text.index("fn open_beneath_root("))
    d = text.index("\n\t\tlet root_fd = unsafe {", c)
    rust = (RUST_PREFIX + text[a:b] + text[c:d] + RUST_SUFFIX).encode()
    (out / "original-statements-path-oracle.rs").write_bytes(rust)
    compile_argv = [str(args.rustc), "+1.95.0", "--edition=2021", "-C", "opt-level=2",
                    str(out / "original-statements-path-oracle.rs"),
                    "-o", str(out / "original-statements-path-oracle")]
    p = subprocess.run(compile_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    (out / "rustc.stdout").write_bytes(p.stdout); (out / "rustc.stderr").write_bytes(p.stderr)
    if p.returncode:
        raise ValueError(p.stderr.decode(errors="replace"))
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.source / "scripts"))
    from hia_native_loader import NativeModule
    manifest_raw = args.manifest.read_bytes()
    meta = json.loads(manifest_raw)
    image_path = args.manifest.parent / meta["image"]
    image = image_path.read_bytes()
    module = NativeModule(args.manifest, manifest_sha256=sha(manifest_raw))
    rng = random.Random(0x52454146494C45)
    pieces = [b"",b"a",b"b",b".",b"..",b"\x00",b"a\x00",b"\xff",b"\xc3\xa9"]
    paths = [b"",b"a",b".",b"..",b"/",b"//",b"///",b"/.",b"/..",b"/./a",
             b"/a",b"/a/",b"/a/.",b"//a///b",b"/a/./b/.",b"/a/../b",
             b"/a/b/..",b"/a\x00/b",b"/\x00",b"/\xff/a",b"/\xc3\xa9/b"]
    roots = [b"",b".",b"a",b"/",b"//",b"/.",b"/..",b"/a",b"/a/",
             b"/a/.",b"/a/..",b"/a/b",b"/a\x00",b"/\x00",b"/\xff",b"/\xc3\xa9"]
    cases = [(path, []) for path in paths]
    cases += [(path, [root]) for path in paths for root in roots]
    for path in paths:
        for root in roots:
            cases.extend([(path,[root,b""]), (path,[b"",root]),
                          (path,[root,b"/"]), (path,[b"/missing",root,b"relative"])])
    for _ in range(256):
        path = (b"/" if rng.randrange(4) else b"") + b"/".join(rng.choices(pieces, k=rng.randrange(1,8)))
        rs = [(b"/" if rng.randrange(4) else b"") + b"/".join(
              rng.choices(pieces, k=rng.randrange(1,5))) for _ in range(rng.randrange(5))]
        cases.append((path,rs))
    cases += [(b"/a/" + b"x"*65536,[b"/a"]), (b"/a/"+b"x"*4096+b"/../\x00",[b"/a"]),
              (b"/a/\x00/..",[b"/a"]), (b"/a/../\x00",[b"/a"])]
    requests = [frame(path,rs) for path,rs in cases]
    oracle_wire = b"".join(struct.pack("<Q",len(wire))+wire for wire in requests)
    (out/"oracle-input.bin").write_bytes(oracle_wire)
    start = time.monotonic()
    p = subprocess.run([str(out/"original-statements-path-oracle")],
                       input=oracle_wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    (out/"oracle-output.bin").write_bytes(p.stdout); (out/"oracle.stderr").write_bytes(p.stderr)
    if p.returncode:
        raise ValueError("original Rust Path oracle failed")
    expected=[]; at=0
    while at<len(p.stdout):
        n=struct.unpack_from("<Q",p.stdout,at)[0];at+=8
        expected.append(p.stdout[at:at+n]);at+=n
    assert at==len(p.stdout) and len(expected)==len(requests)
    rows=[]; native_calls=0; offset=0
    rawout=(out/"native-frames.bin").open("xb")
    def invoke(label,wire,want,cap=None,invalid=False):
        nonlocal native_calls,offset
        cap = max(128,len(want)+17) if cap is None else cap
        code,output,work=module.invoke_raw(wire,output_capacity=cap,workspace_capacity=64,
                                         output_fill=0xa5,workspace_fill=0x5a)
        native_calls+=1
        chunks=[wire,output,work]
        record={"label":label,"code":code,"output_capacity":cap,"offset":offset,
                "input_bytes":len(wire),"output_bytes":len(output),"workspace_bytes":len(work),
                "input_sha256":sha(wire),"output_sha256":sha(output),"workspace_sha256":sha(work)}
        for chunk in chunks:
            rawout.write(struct.pack("<Q",len(chunk))+chunk);offset+=8+len(chunk)
        rows.append(record)
        (out/"progress.json").write_text(json.dumps(rows[-1],sort_keys=True)+"\n")
        assert work==b"\x5a"*64,(label,"workspace")
        if invalid:
            assert code==0xffffffff and output==b"\xa5"*cap,(label,code)
        elif cap<len(want):
            assert code==0xfffffffe and output==b"\xa5"*cap,(label,code,len(want))
        else:
            assert code==len(want) and output[:code]==want and output[code:]==b"\xa5"*(cap-code),(
                label,code,want.hex(),output[:min(len(want),256)].hex())
    try:
        for j,(wire,want) in enumerate(zip(requests,expected)):
            invoke("rust-path-"+str(j),wire,want)
        for j in [0,1,2,21,69,len(requests)-4]:
            for cap in [0,1,47,len(expected[j])-1,len(expected[j])]:
                invoke("capacity-"+str(j)+"-"+str(cap),requests[j],expected[j],cap)
        metadata_controls=0
        for j in range(64):
            before=[rng.getrandbits(64) for _ in range(11)]
            for field in [-1,*range(11)]:
                after=list(before)
                if field>=0:after[field]^=1<<rng.randrange(64)
                wire=MAGIC+struct.pack("<Q22Q",2,*before,*after)
                invoke("metadata-"+str(j)+"-"+str(field),wire,reply(0 if field<0 else 10))
                metadata_controls+=1
        private_controls=0
        for mode in [0,0o100600,0o100400,0o100644,0o106600,0o140600,0o040600,0o100601,0o100660,0o104600]:
            for links in [0,1,2,U64]:
                for uid,euid in [(1000,1000),(0,1000),(1000,0),(0xffffffff,0xffffffff)]:
                    values=[1,2,3,mode,uid,7,links,8,9,10,11]
                    wire=MAGIC+struct.pack("<13Q",3,euid,*values)
                    error=0 if mode&0o170000==0o100000 and links==1 and uid==euid and mode&0o777==0o600 else 9
                    invoke("private-"+str(private_controls),wire,reply(error));private_controls+=1
        malformed=[b""]+[MAGIC[:n] for n in range(1,8)]
        malformed += [MAGIC+struct.pack("<Q",op) for op in [0,4,U64]]
        valid=frame(b"/a/b",[b"/a"])
        malformed += [valid[:n] for n in range(len(valid))]
        malformed += [valid+b"x",b"BADMAGIC"+valid[8:],
                      MAGIC+struct.pack("<3Q",1,U64,0),MAGIC+struct.pack("<3Q",1,0,U64),
                      MAGIC+struct.pack("<Q",2)+bytes(175),MAGIC+struct.pack("<Q",3)+bytes(97)]
        for j,wire in enumerate(malformed):invoke("malformed-"+str(j),wire,b"",invalid=True)
        assert args.original.read_bytes()==original and args.manifest.read_bytes()==manifest_raw and image_path.read_bytes()==image
        report={"status":"PASS","path_comparisons":len(requests),"path_differences":0,
                "metadata_controls":metadata_controls,"private_controls":private_controls,
                "malformed_controls":len(malformed),"native_calls":native_calls,
                "source_sha256":meta["source_sha256"],"image_sha256":sha(image),
                "original_admission_source_sha256":sha(original),"original_rust_statements_verbatim":True,
                "raw_capture_bytes":offset,"seconds":time.monotonic()-start,
                "descriptor_owner_qualified":False,"public_route_qualified":False}
    finally:
        rawout.close();module.close()
        (out/"all-observations.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n")
    (out/"terminal.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
