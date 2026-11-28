"""Assemble both exact extra engines with a deliberately test-only frame emitter.

Unused external capabilities trap. The fixture does not implement a public
handler or authority; it observes only result admission and slot dispatch.
"""
import argparse,hashlib,json,os,pathlib,shutil,sys
sys.dont_write_bytecode=True
BASE=pathlib.Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def put(p,b):p.write_bytes(b if isinstance(b,bytes) else (json.dumps(b,sort_keys=True,indent=2)+'\n').encode())
WRAPPER='''
.intel_syntax noprefix
.section .text
.global _start
_start:
    mov edi,64
    mov eax,231
    syscall
    ud2
.global fixture_frame
fixture_frame:
    cmp rsi,rcx
    ja fixture_unexpected
    mov r10,rdi
    mov rdi,rdx
    mov rcx,rsi
    mov rsi,r10
    cld
    rep movsb
    mov eax,64
    ret
.global fixture_invoke
fixture_invoke:
    push r15
    mov r15,rdi
    mov r8,rsi
    mov rdi,rdx
    mov rsi,rcx
    call runtime_grow_owned
    pop r15
    ret
.global fixture_port_invoke
fixture_port_invoke:
    push r15
    mov r15,rdi
    mov rdi,rsi
    mov rsi,rdx
    mov r8d,57
    call runtime_grow_owned
    pop r15
    ret
.global fixture_destroy
fixture_destroy:
    push r15
    mov r15,rdi
    call runtime_grow_destroy
    pop r15
    ret
fixture_unexpected:
    mov edi,71
    mov eax,231
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
'''
def main():
 p=argparse.ArgumentParser()
 for name in ['package','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
 a=p.parse_args();a.output.mkdir();out=a.output.resolve();package=a.package.resolve()
 sys.path.insert(0,str(package/'worker-source/tests/hia_native/blocking_worker_ci'))
 from capture_writer_trace import run
 proof=json.loads((package/'engine-overlay/source-proof.json').read_bytes())
 paths={'old':package/'references/authority91-extra-engine.S','new':package/'engine-overlay/scripts/runtime_mcp_extra_engine.S'}
 env=dict(os.environ);env.update(LC_ALL='C',LANG='C');tools={n:str(pathlib.Path(shutil.which(n)).resolve()) for n in ['as','ld','objcopy','nm']};result={}
 for role,path in paths.items():
  target=out/role;target.mkdir();raw=path.read_bytes();expected=proof['baseline' if role=='old' else 'output']['sha256'];assert sha(raw)==expected
  put(target/'engine.S',raw);put(target/'wrapper.S',WRAPPER.encode())
  run(target,'engine-assemble',[tools['as'],'--64',str(target/'engine.S'),'-o',str(target/'engine.o')],env,limit=60)
  run(target,'undefined',[tools['nm'],'-u',str(target/'engine.o')],env,limit=60)
  undefined=[]
  for line in (target/'processes/undefined.stdout').read_text().splitlines():
   fields=line.split();assert len(fields)==2 and fields[0]=='U' and all(c.isalnum() or c=='_' for c in fields[1]);undefined.append(fields[1])
  assert undefined
  stubs='.intel_syntax noprefix\n.section .text\n'+''.join('.global '+name+'\n'+name+':\n' for name in undefined)+'    mov edi,71\n    mov eax,231\n    syscall\n    ud2\n.section .note.GNU-stack,"",@progbits\n'
  put(target/'stubs.S',stubs.encode())
  for name in ['wrapper','stubs']:run(target,name+'-assemble',[tools['as'],'--64',str(target/(name+'.S')),'-o',str(target/(name+'.o'))],env,limit=60)
  run(target,'link',[tools['ld'],'--build-id=none','-z','noexecstack','-e','_start','-Ttext=0','-o',str(target/'linked.elf'),str(target/'wrapper.o'),str(target/'engine.o'),str(target/'stubs.o')],env,limit=60)
  run(target,'flat',[tools['objcopy'],'-O','binary','--only-section=.text',str(target/'linked.elf'),str(target/'module.bin')],env,limit=60)
  run(target,'symbols',[tools['nm'],'-n','-P',str(target/'linked.elf')],env,limit=60)
  symbols={r[0]:int(r[2],16) for line in (target/'processes/symbols.stdout').read_text().splitlines() if len(r:=line.split())>=3 and r[1].lower()=='t'}
  module=(target/'module.bin').read_bytes();result[role]={'source_sha256':sha(raw),'image_sha256':sha(module),'image_bytes':len(module),'undefined_traps':undefined,'exports':{name:symbols[name] for name in ['fixture_frame','fixture_invoke','fixture_port_invoke','fixture_destroy','runtime_grow_target']}}
 put(out/'BUILD.json',{'status':'ACTUAL_GAS_ENGINE_FIXTURE_BUILD_PASS','images':result,'public_handler_qualified':False,'unused_capabilities':'trap; no synthetic successful operation'});print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
