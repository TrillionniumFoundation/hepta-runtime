"""Export the fixed worker graph while proving its worker algorithms unchanged."""
from __future__ import annotations
import argparse,hashlib,json,re,shutil
from pathlib import Path

PUBLIC = ['bellman_worker_init','bellman_worker_control','bellman_worker_poll','bellman_worker_receive',
          'bellman_worker_release','bellman_worker_wake_fd','bellman_worker_shutdown','bellman_worker_destroy']
EXTRA = '''
.equ G_OUTPUT,160
.equ G_OUTPUT_CAPACITY,168
.equ G_OUTPUT_USED,176
.equ G_OUTPUT_CURSOR,184
.equ G_BORROW_SEQUENCE,192
.equ G_BORROWED,200
.equ G_BORROW_EXTENT,208
.equ G_JOURNAL_FD,216
.equ G_API_LOCK,224
.equ G_MAGIC,232
'''

def sha(raw):return hashlib.sha256(raw).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--baseline',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    base=a.baseline.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    for path in base.rglob('*'):
        if not path.is_file() or '__pycache__' in path.parts or path.suffix=='.pyc':continue
        dest=out/path.relative_to(base);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dest)
    old={name:(base/'scripts'/('bellman_worker_'+name+'.S')).read_text() for name in ['adapter','common','run']}
    expected={'adapter':'a2fcf028dc8ec73f0e4553b8c3a75f6f47eec181aaf282a67e039d1d8056c58b',
              'common':'981f0c8bfa4f476b544cf057ca9abd5644dd7f57d7875f49f6be936fc72a5d83',
              'run':'194479b9b418702f3d374911c6982deee51db0bace2fbd8d18ad9b2e16b6e8d6'}
    for name,raw in old.items():assert sha(raw.encode())==expected[name]
    constants=old['adapter'][:old['adapter'].index('_start:')]
    transport=old['adapter'][old['adapter'].index('read_frame:'):old['adapter'].index('\ncontrol:')]
    assert transport.count('    call control\n')==1 and transport.count('    call begin_shutdown\n')==1
    transport=transport.replace('    call control\n','    mov rdi,r15\n    mov rsi,[r15+G_INPUT]\n    mov rdx,[r15+G_INPUT_LEN]\n    call bellman_worker_control\n    test rax,rax\n    jnz fatal\n')
    transport=transport.replace('    call begin_shutdown\n','    mov rdi,r15\n    call bellman_worker_shutdown\n    test rax,rax\n    jnz fatal\n')
    retained=old['adapter'][old['adapter'].index('\ncontrol:'):old['adapter'].index('\n.include "bellman_worker_common.S"')]
    templates=Path(__file__).parent/'templates';fixture=(templates/'fixture.S').read_text();api=(templates/'api.S').read_text()
    adapter=constants+EXTRA+'\n'+fixture+'\n'+transport+retained+'\n.include "bellman_worker_callable_api.S"\n.include "bellman_worker_common.S"\n.include "bellman_worker_run.S"\n'
    dispatch='''write_all:
    cmp edi,1
    je queue_append
    cmp edi,2
    jne write_all_kernel
    mov rdi,[r15+G_JOURNAL_FD]
    jmp write_all_kernel

write_all_kernel:'''
    assert old['common'].count('write_all:')==1
    common=old['common'].replace('write_all:',dispatch)
    assert common.replace(dispatch,'write_all:')==old['common']
    parts={'adapter':adapter,'common':common,'run':old['run'],'callable_api':api};names=set()
    for source in parts.values():
        names.update(re.findall(r'^([A-Za-z_][A-Za-z_0-9]*):',source,re.M))
        names.update(re.findall(r'^\.equ ([A-Za-z_][A-Za-z_0-9]*),',source,re.M))
    names.update(role+'_entry' for role in ['pool','core','commitment','elapsed','result'])
    names.difference_update(PUBLIC);names.discard('_start')
    mapping={name:'bwx_'+name for name in names};pattern=re.compile(r'\b(?:'+'|'.join(sorted(map(re.escape,names),key=len,reverse=True))+r')\b')
    rename=lambda text:pattern.sub(lambda m:mapping[m.group()],text)
    inverse={v:k for k,v in mapping.items()};reverse=re.compile(r'\b(?:'+'|'.join(sorted(map(re.escape,inverse),key=len,reverse=True))+r')\b')
    for name,raw in parts.items():
        rendered=rename(raw);assert reverse.sub(lambda m:inverse[m.group()],rendered)==raw
        (out/'scripts'/('bellman_worker_'+name+'.S')).write_text(rendered)
    for name,raw in old.items():
        dest=out/'tests/hia_native/blocking_worker/reference'/('standalone_'+name+'.S');dest.write_text(raw)
    author=out/'tests/hia_native/blocking_worker/author_worker_bridge.py';raw=author.read_text()
    raw=raw.replace("'scripts/bellman_worker_run.S']","'scripts/bellman_worker_run.S', 'scripts/bellman_worker_callable_api.S']")
    raw=raw.replace(".global {role}_entry\\n{role}_entry:",".global bwx_{role}_entry\\nbwx_{role}_entry:")
    raw=raw.replace("symbols['pool_entry']","symbols['bwx_pool_entry']").replace("symbols[role+'_entry']","symbols['bwx_'+role+'_entry']")
    old_line="'dynamic_loader':False,'actual_worker_qualified':False,'public_handler_qualified':False}"
    new_line="'dynamic_loader':False,'actual_worker_qualified':False,'public_handler_qualified':False,\n               'exports':{name:{'offset':symbols[name]-0x400000} for name in "+repr(PUBLIC)+"}}"
    assert raw.count(old_line)==1;raw=raw.replace(old_line,new_line);author.write_text(raw)
    dest=out/'tests/hia_native/blocking_worker/export_author';dest.mkdir()
    shutil.copyfile(Path(__file__),dest/'author_export.py');(dest/'templates').mkdir()
    for name in ['fixture.S','api.S']:shutil.copyfile(templates/name,dest/'templates'/name)
    proof={'schema':'hepta.runtime.bellman-worker-export.source-proof.v1','status':'SOURCE_ONLY',
           'baseline_assembly_sha256':expected,'old_control_and_submission_and_reap_exact_after_namespace_rename':True,
           'old_worker_and_clock_and_renderer_exact_after_namespace_rename':True,
           'only_common_function_adapter':'write_all fd1 becomes exact owned FIFO; fd2 uses supplied actual journal descriptor',
           'mapping':dict(sorted(mapping.items())),'exports':PUBLIC,'source_author_sha256':sha(Path(__file__).read_bytes()),
           'templates':{name:sha((templates/name).read_bytes()) for name in ['fixture.S','api.S']},
           'sources':{str(path.relative_to(out)):{'bytes':len(path.read_bytes()),'sha256':sha(path.read_bytes())}
                      for path in sorted((out/'scripts').glob('bellman_worker*.S'))},
           'runtime_logic_images_changed':False,'native_executed':False,'public_handler_qualified':False}
    (out/'native/bellman_worker_export_source_proof.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in proof.items() if k!='mapping'},sort_keys=True))

if __name__=='__main__':main()
