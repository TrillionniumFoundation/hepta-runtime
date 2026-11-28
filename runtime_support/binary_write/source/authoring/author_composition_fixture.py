#!/usr/bin/env python3
"""Exact reversible qualification-carrier extension; no HIA policy changes."""
import argparse,hashlib,json
from pathlib import Path
SHA=lambda b:hashlib.sha256(b).hexdigest()

def author(root):
 original=(root/'parent/asm/binary_parent_owner_fixture.S').read_bytes();text=original.decode();edits=[]
 def edit(before,after,count=1):
  nonlocal text
  assert text.count(before)==count,(before,text.count(before),count)
  row=dict(before=before,after=after,count=count,before_sha256=SHA(text.encode()))
  text=text.replace(before,after);row['after_sha256']=SHA(text.encode());edits.append(row)
 for name,count in (('create',4),('invoke',1),('release',2),('destroy',3)):
  edit('call binary_parent_owner_'+name,'call binary_write_composition_'+name,count)
 edit('lea rdi, [rip+.Lwbf_journal]','lea rdi, [rip+.Lbcf_journal]',2)
 edit('    cmp r14, 28\n    ja .Lwbf_fatal','    cmp r14, 34\n    ja .Lwbf_fatal')
 edit('    cmp r14, 19\n    je .Lwbf_no_context\n    jmp .Lwbf_fatal',
      '    cmp r14, 19\n    je .Lwbf_no_context\n'
      '    cmp r14, 29\n    je .Lbcf_context\n'
      '    cmp r14, 30\n    je .Lbcf_adapter_workspace\n'
      '    cmp r14, 31\n    je .Lbcf_planner_workspace\n'
      '    cmp r14, 32\n    je .Lbcf_adapter_output\n'
      '    cmp r14, 33\n    je .Lbcf_planner_output\n'
      '    cmp r14, 34\n    je .Lbcf_input\n    jmp .Lwbf_fatal')
 edit('    cmp r13, 96\n    jb .Lwbf_no_context','    cmp r13, 48\n    jb .Lwbf_no_context')
 edit('.Lwbf_context:\n    mov r14, r12','.Lwbf_context:\n    mov r14, [r12+384]')
 for name,pointer,capacity in (('workspace',88,96),('output',104,112),('input',64,72)):
  edit(f'.Lwbf_{name}:\n    mov r14, [r12+{pointer}]\n    mov rbp, [r12+{capacity}]',
       f'.Lwbf_{name}:\n    mov rax, [r12+384]\n    mov r14, [rax+{pointer}]\n    mov rbp, [rax+{capacity}]')
 edit('    cmp qword ptr [r12+rax], 0\n    jne .Lwbf_no_context\n    push rax\n    mov qword ptr [r12+rax], 1\n    mov rdi, r12',
      '    mov rcx, [r12+384]\n    cmp qword ptr [rcx+rax], 0\n    jne .Lwbf_no_context\n    push rax\n    mov qword ptr [rcx+rax], 1\n    mov rdi, r12')
 edit('    pop rdx\n    mov qword ptr [r12+rdx], 0','    pop rdx\n    mov rcx, [r12+384]\n    mov qword ptr [rcx+rdx], 0')
 extension=(root/'authoring/composition_fixture_extension.S').read_text()
 assert '.Lbcf_journal:'not in text
 body=text;text+='\n'+extension
 restored=text[:-len(extension)-1]
 for row in reversed(edits):
  assert SHA(restored.encode())==row['after_sha256']
  assert restored.count(row['after'])==row['count']
  restored=restored.replace(row['after'],row['before'])
  assert SHA(restored.encode())==row['before_sha256']
 assert restored.encode()==original
 return text.encode(),dict(schema='hepta.runtime.binary-write-composition-fixture.author.v1',original=SHA(original),source=SHA(text.encode()),extension=SHA(extension.encode()),complete_inverse=True,edits=edits)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 a.output.mkdir(parents=True,exist_ok=False);raw,record=author(a.source)
 (a.output/'binary_write_composition_fixture.S').write_bytes(raw)
 (a.output/'binary_write_composition_fixture_edits.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
 print(json.dumps({k:v for k,v in record.items()if k!='edits'},sort_keys=True))
if __name__=='__main__':main()
