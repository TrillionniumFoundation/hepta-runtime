#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Data replay of saved ServerMessage codec and private HIA captures.

No NativeModule is instantiated, no entry image is mapped, and no Original child
is started. The original assertion bodies execute over the saved full replies.
The exact AST replacements are inverted and the regenerated logs must be equal.
"""
from pathlib import Path
import ast,contextlib,copy,ctypes,gzip,io,json,struct,zlib
M=Path('/home/qq/hepta-server-message-codec-bd947-v1')
def clean(value):
    if isinstance(value,dict):return {k:clean(v)for k,v in value.items()if k!='elapsed_seconds'}
    if isinstance(value,list):return [clean(v)for v in value]
    return value
def transformed(C,path,sha,changes,expected):
    source=C.pin(path,sha).decode();tree=ast.parse(source);before=ast.dump(tree,include_attributes=False);edits=[]
    counts={k:0 for k in changes}
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call):continue
        if isinstance(node.func,ast.Attribute)and isinstance(node.func.value,ast.Name):
            name=node.func.value.id+'.'+node.func.attr
            if name in changes:
                old=copy.deepcopy(node.func);node.func=ast.Name(id=changes[name],ctx=ast.Load());edits.append((node,old));counts[name]+=1
    assert counts==expected,(counts,expected)
    restored=copy.deepcopy(tree)
    for node in ast.walk(restored):
        if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id in changes.values():
            oldname=next(k for k,v in changes.items()if v==node.func.id);parent,attr=oldname.split('.')
            node.func=ast.Attribute(value=ast.Name(id=parent,ctx=ast.Load()),attr=attr,ctx=ast.Load())
    assert ast.dump(restored,include_attributes=False)==before
    ast.fix_missing_locations(tree)
    return tree,dict(original_source=str(path),original_sha256=sha,ast_call_replacements=counts,complete_inverse=True,
        all_other_ast_nodes_unchanged=True,new_native_image_entries=0,new_original_processes=0)
def normal(C,outdir):
    source=M/'qualify_server_message_v4.py';root=M/'message-pairs-v4'
    report=C.js(root/'result.json','6f775fae8fcf6a2920ffee72fdf4d32afd0a15290461707a028bfecd5a347216')
    C.allpins(report['pins'])
    expected={k:v for k,v in report.items()if k not in('pins','mismatches','fixture_errors','traceback','native_module','native_initializer','native_emitter')}
    expected.update(mismatch_count=len(report['mismatches']),fixture_error_count=len(report['fixture_errors']),
        mismatch_labels=[x['label']for x in report['mismatches'][:20]])
    C.durable_object(C.js(M/'message-pairs-v4.external.json','9775dda1152b9f83175cb92b20502de7570e50905c67c9e99ed29dd69a65a9df'),
        expected,'1a1eb3e9d74-392-42fd',source)
    data=C.pin(root/'native-bytes.bin');log=C.pin(root/'native-calls.jsonl');records=[json.loads(v)for v in log.splitlines()]
    assert len(records)==2*report['actual_hia_entries']
    offset=0
    def blob(item):
        assert set(item)=={'offset','bytes','sha256'}
        a=item['offset'];n=item['bytes'];assert type(a)is int and type(n)is int and 0<=a<=a+n<=len(data)
        raw=data[a:a+n];assert C.SHA(raw)==item['sha256'];return raw
    # This writer never deduplicates. Its whole raw blob is covered in actual
    # append order, including zero-length outputs.
    for enter,returned in zip(records[::2],records[1::2],strict=True):
        assert enter['stage']=='ENTER'and returned['stage']=='RETURN'
        assert all(enter[k]==returned[k]for k in('ordinal','role','phase'))
        for ref in(enter['input'],returned['output'],returned['full_output_zlib'],returned['full_workspace_zlib']):
            assert ref['offset']==offset;offset+=ref['bytes'];blob(ref)
    assert offset==len(data)
    tree,deriv=transformed(C,source,'d149319fec689ecaf52b8431805d2710a9ac4b225474854dd62a084129be4773',
        {'loader.NativeModule':'_replay_module','subprocess.Popen':'_replay_process','os.getpgid':'_replay_pgid'},
        {'loader.NativeModule':3,'subprocess.Popen':1,'os.getpgid':1})
    ns={'__name__':'normal_captures_replayed','__file__':str(source)}
    at=0;opened=[];closed=[];original_calls=0
    class Session:
        def __init__(self,oc,wc):
            self.output_capacity=oc;self.workspace_capacity=wc
            self._output=ctypes.create_string_buffer(oc+16);self._workspace=ctypes.create_string_buffer(wc+16)
        def close(self):self._output=self._workspace=None
    class Module:
        def __init__(self,path,*,manifest_sha256):
            self.metadata=C.compiled(path,manifest_sha256);self.manifest_sha256=manifest_sha256
            self.role={'server-message':'parent','server-message-schema':'initializer','server-message-emitter':'emitter'}[self.metadata['name']]
            assert self.role not in opened;opened.append(self.role)
        def session(self,*,output_capacity,workspace_capacity):return Session(output_capacity,workspace_capacity)
        def _invoke_buffers(self,wire,output,workspace,oc,wc,*,raw=False):
            nonlocal at
            assert raw and at+1<len(records)
            enter,returned=records[at:at+2];at+=2
            assert enter['role']==self.role and enter['module_manifest_sha256']==self.manifest_sha256
            assert wire==blob(enter['input'])and (oc,wc)==(enter['output_capacity'],enter['workspace_capacity'])
            out=zlib.decompress(blob(returned['full_output_zlib']));work=zlib.decompress(blob(returned['full_workspace_zlib']))
            assert len(out)==oc and len(work)==wc==returned['workspace_bytes']
            assert C.SHA(out)==returned['full_output_sha256']and C.SHA(work)==returned['workspace_sha256']
            code=returned['code'];observed=out[:code]if code<=oc else out
            assert blob(returned['output'])==observed and returned['output_tail_bytes']==oc-len(observed)
            assert C.SHA(out[len(observed):])==returned['output_tail_sha256']
            ctypes.memmove(output,out,oc);ctypes.memmove(workspace,work,wc)
            ctypes.memset(ctypes.addressof(output)+oc,0xa5,16);ctypes.memset(ctypes.addressof(workspace)+wc,0x5a,16)
            return code,out,work
        def close(self):
            assert self.role not in closed;closed.append(self.role)
    class Process:
        def __init__(self,command,*,cwd,stdin,stdout,stderr):
            nonlocal original_calls
            original_calls+=1;assert original_calls==1 and command==report['original_process']['command']and Path(cwd)==outdir
            assert stdin.read()==C.pin(root/'original.stdin')
            stdout.write(C.pin(root/'original.stdout'));stderr.write(C.pin(root/'original.stderr'))
            self.pid=report['original_process']['pid'];self.returncode=0
        def wait(self,timeout):assert timeout==60;return 0
        def poll(self):return 0
    def pgid(pid):
        assert pid==report['original_process']['pid'];return report['original_process']['pgid']
    ns.update(_replay_module=Module,_replay_process=Process,_replay_pgid=pgid)
    exec(compile(tree,str(source)+'[saved-byte-replay]','exec'),ns);ns['OUT']=outdir
    stdout=io.StringIO()
    with contextlib.redirect_stdout(stdout):ns['main']()
    reconstructed=json.loads((outdir/'result.json').read_bytes())
    assert clean(reconstructed)==clean(report)
    assert at==len(records)and original_calls==1 and sorted(opened)==sorted(closed)==['emitter','initializer','parent']
    names=['cases.jsonl','original.stdin','original.stdout','original.stderr','native-bytes.bin','native-calls.jsonl','pair-outcomes.jsonl','process-start.json']
    for name in names:
        assert (outdir/name).read_bytes()==C.pin(root/name),name
    assert clean(json.loads((outdir/'process-finish.json').read_bytes()))==clean(C.js(root/'process-finish.json'))
    deriv.update(historical_original_requests=report['original_requests'],historical_hia_entries=at//2,
        all_recreated_public_and_native_capture_bytes_equal=True,private_output_path=str(outdir))
    reconstructed['data_replay_only']=deriv;(outdir/'result.json').write_bytes(C.J(reconstructed))
    (outdir/'derivation.json').write_bytes(C.J(deriv));return deriv
def private(C,outdir):
    source=M/'qualify_server_message_private_v1.py';root=M/'message-private-v1'
    report=C.js(root/'result.json','8ca7691fd5c1ab2625699f43488a294450ce8fca5ce9869b104db9666149feea')
    C.durable(M/'message-private-v1.external.json','6103e5a2c2291c4a158f41e740fb7c0be73a9432f369bd49ad13541f1aba2ab3',
        report,'1a1ebb919e8-392-4357',('pins','module_pins','captures','traceback'),source)
    C.allpins(report['pins']);C.directory(root,report['captures'])
    raw=C.pin(root/'small-bytes.bin');journal=C.pin(root/'calls.jsonl');rows=[json.loads(v)for v in journal.splitlines()]
    pairs=[];snapshots={};active=None;position=0
    def blob(row):
        nonlocal position
        a,n=row['offset'],row['bytes'];assert 0<=a<=a+n<=len(raw)
        value=raw[a:a+n];assert C.SHA(value)==row['sha256'];return value
    def snap(row):
        ident=row['id'];old=snapshots.setdefault(ident,row);assert old==row
        packed=C.pin(root/row['path'],row['gzip_sha256'],row['gzip_bytes'])
        data=gzip.decompress(packed);assert len(data)==row['bytes']and C.SHA(data)==row['sha256']
        assert row['guard_pages']is True and row['canary']in(0x5a,0xa5)
        return data
    for row in rows:
        event=row['event']
        if event=='SNAPSHOT':
            r={k:v for k,v in row.items()if k!='event'};snap(r)
        elif event=='ENTER':
            assert active is None;active=row;blob(row['input'])
            assert row['ordinal']==len(pairs)+1
        elif event=='RETURN':
            assert active and all(row[k]==active[k]for k in('ordinal','role','label'))
            if row['observed']is not None:blob(row['observed'])
            assert row['input_unchanged']and row['all_canaries_intact']
            assert row['readonly_returned']==active['kernel_readonly_output_and_workspace']
            if row['readonly_returned']:
                assert row['output_snapshot']is row['workspace_snapshot']is None and row['code']==active['expected']in(0xffffffff,0xfffffffe)
            else:
                assert row['output_snapshot']==snapshots[row['output_snapshot']['id']]
                assert row['workspace_snapshot']==snapshots[row['workspace_snapshot']['id']]
            pairs.append((active,row));active=None
        else:assert event in('CONTROL_BATCH_RESTORED','ACTUAL_PURE_CHILD_RECEIPT','SYNTHETIC_VALUE_LEASE_ACK','OWNER_SEQUENCE_COMPLETE')
    assert active is None and len(pairs)==report['actual_hia_entries']==698
    tree,deriv=transformed(C,source,'604b2b4737de68421cebea98d1b89b9b5ecbfa92fb114a62a0366ee1618b0834',
        {'loader.NativeModule':'_replay_module'},{'loader.NativeModule':1})
    ns={'__name__':'private_captures_replayed','__file__':str(source)};at=0;opened=[];closed=[]
    class Module:
        def __init__(self,path,*,manifest_sha256):
            self.meta=C.compiled(path,manifest_sha256);self.manifest_sha256=manifest_sha256
            self.role=self.meta['name'];assert self.role not in opened;opened.append(self.role)
        def _entry(self,source_pointer,length,output,oc,workspace,wc):
            nonlocal at
            assert at<len(pairs);enter,returned=pairs[at];at+=1
            assert enter['role']==self.role and enter['manifest_sha256']==self.manifest_sha256
            assert enter['output_capacity']==oc and enter['workspace_capacity']==wc
            assert ctypes.string_at(source_pointer,length)==blob(enter['input'])
            if not returned['readonly_returned']:
                ob=returned['output_snapshot'];wb=returned['workspace_snapshot']
                assert ob['bytes']==enter['full_allocated_output_capacity']and wb['bytes']==enter['full_allocated_workspace_capacity']
                data=gzip.decompress((root/ob['path']).read_bytes());assert C.SHA(data)==ob['sha256']
                ctypes.memmove(output,data,len(data));del data
                data=gzip.decompress((root/wb['path']).read_bytes());assert C.SHA(data)==wb['sha256']
                ctypes.memmove(workspace,data,len(data));del data
            return returned['code']
        def close(self):
            assert self.role not in closed;closed.append(self.role)
    ns['_replay_module']=Module;exec(compile(tree,str(source)+'[saved-byte-replay]','exec'),ns);ns['OUT']=outdir
    stream=io.StringIO()
    with contextlib.redirect_stdout(stream):ns['main']()
    rebuilt=json.loads((outdir/'result.json').read_bytes())
    assert clean(rebuilt)==clean(report)and at==len(pairs)and sorted(opened)==sorted(closed)==sorted(report['module_pins'])
    assert (outdir/'calls.jsonl').read_bytes()==journal and (outdir/'small-bytes.bin').read_bytes()==raw
    for name,want in report['captures'].items():
        data=(outdir/name).read_bytes();assert len(data)==want['bytes']and C.SHA(data)==want['sha256']
    deriv.update(historical_actual_hia_entries=698,historical_immutable_refusals=601,
        historical_actual_pure_child_calls=9,historical_synthetic_value_lease_acknowledgements=3,
        all_recreated_capture_bytes_equal=True,kernel_protection_history_bound_to_completed_source=True,
        private_drop_headers_are_synthetic=True,private_output_path=str(outdir))
    rebuilt['data_replay_only']=deriv;(outdir/'result.json').write_bytes(C.J(rebuilt))
    (outdir/'derivation.json').write_bytes(C.J(deriv));return deriv
