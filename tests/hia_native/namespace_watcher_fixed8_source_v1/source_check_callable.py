"""Pure exact source admission and syntax; does not execute native or Rust."""
import ast,hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,read,require,pin,source
def run():
    identity=source()
    from source_check import check
    require(check()["source_manifest_sha256"]==identity,"original source-only checks preserved")
    for path in ROOT.rglob("*.py"):compile(read(path),str(path),"exec")
    fixed=loads(read(ROOT/"SOURCE_QUALIFIED.json"))
    for name,key in (("native/namespace_watcher.hepta","owner"),("native/namespace_watcher.composition.json","composition")):
        raw=read(ROOT/name);expected=fixed[key]
        require(pin(raw)=={k:expected[k] for k in ("bytes","sha256")},"actual source-build fixed owner")
        require(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==expected["git_blob"],"owner Git pin")
    spans=loads(read(ROOT/"reference/ORIGINAL_SPANS.json"))
    for name,row in spans["sources"].items():
        require(pin(read(ROOT/name))=={k:row[k] for k in ("bytes","sha256")},"whole target source")
    for row in spans["spans"]:
        raw=read(ROOT/row["source"])[row["start_byte"]:row["end_byte"]]
        require(raw==read(ROOT/row["extraction"]) and pin(raw)=={k:row[k] for k in ("bytes","sha256")},"original span unchanged")
    asm=read(ROOT/"authoring/namespace_watcher_callable.S.in").decode()
    require(asm.count("@OWNER_BYTES@")==1 and ".zero @OWNER_BYTES@" in asm,"one exact owner reservation")
    labels=re.findall(r"^(\.?[a-zA-Z_][a-zA-Z_0-9]*):",asm,re.M)
    require(len(labels)==len(set(labels)),"unique actual assembly labels")
    for target in re.findall(r"^\s+(?:j[a-z]+|call)\s+(\.?[a-zA-Z_][a-zA-Z_0-9]*)\s*(?:/\*.*)?$",asm,re.M):
        if target not in ("r15",):require(target in labels,"resolved source branch: "+target)
    before=read(ROOT/"previous/namespace_watcher_callable.S.in").decode()
    prior=read(ROOT/"previous/namespace_watcher_callable-v2.S.in").decode()
    want=prior.replace(".equ NW_PIN_RESULT,6528\n",".equ NW_PIN_RESULT,6528\n.equ NW_READ,98336\n")
    want=want.replace("    mov qword ptr [r12+112],96\n    lea r14",
        "    mov qword ptr [r12+112],96\n    cmp rbp,2\n    je nw_clear_read\n    cmp rbp,3\n    jne nw_read_ready\n"
        "nw_clear_read:\n    lea rdi,[r12+NW_READ]\n    xor eax,eax\n    mov ecx,2048\n    rep stosq\nnw_read_ready:\n    lea r14")
    want=want.replace("    lea rsi,[r12+NW_INPUT+96]\n    mov edx,16384\n    call qword ptr [r15+8]",
        "    lea rsi,[r12+NW_READ]\n    mov edx,16384\n    call qword ptr [r15+8]")
    want=want.replace("    mov [r12+NW_INPUT+48],rax\n    mov [r12+NW_INPUT+72],rax\n    add rax,96",
        "    mov [r12+NW_INPUT+48],rax\n    mov [r12+NW_INPUT+72],rax\n    mov rcx,rax\n"
        "    lea rsi,[r12+NW_READ]\n    lea rdi,[r12+NW_INPUT+96]\n    rep movsb\n    add rax,96")
    require(asm==want,"only separate actual read-buffer framing; all HIA transitions unchanged")
    restored=prior
    for symbol,local in (("namespace_watcher_owner",".NW_owner_image"),("namespace_file_pin_adopt",".NW_pin_adopt"),
        ("namespace_file_pin_clone",".NW_pin_clone"),("namespace_file_pin_release",".NW_pin_release")):
        require(restored.count(local+":\n")==1,"one local alias per exported address")
        restored=restored.replace(symbol+":\n"+local+":\n",symbol+":\n").replace("    call "+local+"\n","    call "+symbol+"\n")
    require(restored==before,"sole local direct-call relocation fix")
    require("syscall" in asm and "lock cmpxchg" in asm and "namespace_watcher_owner:" in asm,"actual native mechanisms")
    result=dict(status="CALLABLE_SOURCE_ONLY_PASS",source_manifest_sha256=identity,
        owner=fixed["owner"],template=pin(asm.encode()),original_spans=len(spans["spans"]),
        native_or_rust_executions=0,watcher_qualified=False,namespace_version_qualified=False,
        public_handler_qualified=False)
    print(encoded(result).decode(),end="")
if __name__=="__main__":run()
