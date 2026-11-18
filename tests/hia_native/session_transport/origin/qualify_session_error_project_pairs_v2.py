#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual Original/HIA SessionError, EventId and error source-chain pairs."""
from pathlib import Path
import ctypes,hashlib,importlib.util,json,os,signal,stat,struct,subprocess,sys,time,traceback
D=Path('/home/qq/hepta-http-transport-bd947-v1')
OUT=D/'session-error-project-pairs-v2'
SHA=lambda b:hashlib.sha256(b).hexdigest()
J=lambda o:(json.dumps(o,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()
U=lambda b,p:struct.unpack_from('<Q',b,p)[0]
PINS={}
def pin(path,digest=None):
    p=Path(path);s=p.lstat();assert stat.S_ISREG(s.st_mode)and not p.is_symlink()and s.st_nlink==1
    raw=p.read_bytes();row=dict(bytes=len(raw),sha256=SHA(raw),mode=stat.S_IMODE(s.st_mode))
    if digest:assert row['sha256']==digest,(p,row)
    key=str(p.resolve());assert key not in PINS or PINS[key]==row;PINS[key]=row;return raw
def module(path,digest,name):
    pin(path,digest);spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def decode(raw,kind_names):
    assert len(raw)>=1216 and raw[:8]==b'HRSER001'
    assert U(raw,160)==192 and U(raw,168)==704 and U(raw,184)==0
    assert U(raw,88)<=32 and U(raw,152)<=32
    def span(at):
        off=U(raw,at);size=U(raw,at+8)
        if off==0:assert size==0;return None
        assert 1216<=off<=len(raw)and size<=len(raw)-off
        return raw[off:off+size].decode()
    sources=[span(192+i*16)for i in range(U(raw,88))]
    iosources=[span(704+i*16)for i in range(U(raw,152))]
    assert raw[192+U(raw,88)*16:704]==bytes(512-U(raw,88)*16)
    assert raw[704+U(raw,152)*16:1216]==bytes(512-U(raw,152)*16)
    kind=U(raw,64);assert 0<=kind<=len(kind_names)
    code=U(raw,80);assert code<=0xffffffff
    if code>=0x80000000:code-=0x100000000
    assert U(raw,72)<=1 and U(raw,128)<=1
    return dict(value_class=U(raw,8),variant=U(raw,16),id_present=U(raw,24),id=U(raw,32),index=U(raw,40),
        event_error=U(raw,48),parse_kind=U(raw,56),display=span(96),sources=sources,
        io_display=span(112),io_kind=kind_names[kind-1]if kind else None,
        io_raw_os_error=code if U(raw,72)else None,io_has_inner=bool(U(raw,128)),
        io_inner_display=span(136),io_sources=iosources)
def main():
    assert os.getpid()==os.getpgrp();os.umask(0o077);OUT.mkdir(mode=0o700);started=time.monotonic()
    report=dict(schema='hepta.session-error.project-pairs.v2',status='RUNNING',original_processes=0,
        original_requests=0,actual_hia_entries=0,matching_pairs=0,mismatches=[],private_refusals=0,
        actual_native_compile_attempts=0,actual_native_compiles=0,actual_value_creations=0,
        actual_owned_drops=0,production_activated=False,whole_runtime_replaced=False,worker_integrated=False)
    journal=blob=None
    try:
        pin(__file__)
        corpus=module(D/'session_error_corpus_v1.py','9e769bcb9422f2613c2cab6ba088a11d6f9c6298640ba0fc71477d99efc611cc','error_corpus')
        reference=module(D/'session_error_reference_admit_v1.py','b844d80e0fec6eddd0d0c11ebfd401b1570cb255f8640f2a29721ad6eaded57a','error_admit')
        handoff=reference.admit(pin);report['original_full_sources_and_registry_admitted']=True
        build=json.loads(pin(D/'session-error-project-build-v3/result.json','9d159f426d3ba7449c7db2e38b7217b384b66c9214645277143d41a04473cef5'))
        ext=json.loads(pin(D/'session-error-project-build-v3.external.json','d6b420496e9ced61c11c54927ebc2ceb1b52a9f108934656bc9f412ec5d07a25'))
        assert build['status']=='BUILT_NOT_SEMANTICALLY_QUALIFIED'and build['actual_native_compiles']==1
        assert ext['status']['job_id']=='1a1eaa757d4-392-425c'and ext['status']['state']=='succeeded'
        for k in ('output_complete','output_durable','terminal_publication_confirmed'):assert ext['status'][k]
        assert ext['status']['exit_code']==0 and ext['status']['timed_out']is ext['status']['cancelled']is False
        for path,row in build['source_pins'].items():pin(path,row['sha256'])
        loader=module(D/'session-cache-native-source-v1/scripts/hia_native_loader.py',
            '58e2fe0492379340d7471a7857e1aa5de1a9a5d1e37a118852278b131bb1fe06','error_loader')
        spec=build['modules']['session-error-project']
        rows=corpus.cases();assert len(rows)==3672
        (OUT/'cases.jsonl').write_bytes(b''.join((json.dumps(dict(label=label,input=v),sort_keys=True,ensure_ascii=True)+'\n').encode()for label,v in rows))
        data=b''.join((json.dumps(v,sort_keys=True,ensure_ascii=True,separators=(',',':'))+'\n').encode()for _,v in rows)
        (OUT/'original.stdin').write_bytes(data);begin=time.monotonic()
        command=[handoff['binary']['path']];child=subprocess.Popen(command,cwd=OUT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        report['original_processes']=1
        try:stdout,stderr=child.communicate(data,timeout=30)
        except subprocess.TimeoutExpired:
            report['status']='FAIL';(OUT/'result.json').write_bytes(J(report));os.killpg(os.getpgrp(),signal.SIGKILL);raise
        (OUT/'original.stdout').write_bytes(stdout);(OUT/'original.stderr').write_bytes(stderr)
        report['original_process']=dict(command=command,pid=child.pid,exit_code=child.returncode,
            elapsed_seconds=time.monotonic()-begin,stdin_bytes=len(data),stdin_sha256=SHA(data),
            stdout_bytes=len(stdout),stdout_sha256=SHA(stdout),stderr_bytes=len(stderr),stderr_sha256=SHA(stderr),
            stdin_closed=True,stdout_eof=True,stderr_eof=True,timed_out=False)
        assert child.returncode==0 and not stderr
        actual=[json.loads(x)for x in stdout.splitlines()];assert len(actual)==len(rows)
        assert all(x['status']in ('OK','ERROR')for x in actual)
        report['original_requests']=len(actual)
        blob=(OUT/'native-bytes.bin').open('xb',buffering=0);journal=(OUT/'native-calls.jsonl').open('xb',buffering=0)
        def span(raw):
            at=blob.tell();blob.write(raw);return dict(offset=at,bytes=len(raw),sha256=SHA(raw))
        def log(obj):journal.write((json.dumps(obj,sort_keys=True)+'\n').encode())
        names=('DuplicatedRequestId','ChannelClosed','EventIdParseError','SessionServiceTerminated','InvalidEventId','Io','EventStore')
        parse_names=(None,'Empty','InvalidDigit','PosOverflow','NegOverflow','Zero')
        resultkeys=('display','sources','io_display','io_kind','io_raw_os_error','io_has_inner','io_inner_display','io_sources')
        with loader.NativeModule(spec['path'],manifest_sha256=spec['sha256'])as native:
            with native.session(output_capacity=1<<20,workspace_capacity=67174400)as session:
                def pair(label,wire,expected,keys,extra=None):
                    ordinal=report['actual_hia_entries']+1
                    log(dict(stage='ENTER',ordinal=ordinal,label=label,input=span(wire),output_capacity=1<<20,workspace_capacity=67174400))
                    report['actual_hia_entries']+=1
                    try:
                        raw=session.invoke(wire);value=decode(raw,corpus.KIND_NAMES)
                        log(dict(stage='RETURN',ordinal=ordinal,code=len(raw),output=span(raw)))
                        observed={k:value[k]for k in keys}
                        if extra is not None:observed.update(extra(value))
                        if observed!=expected:report['mismatches'].append(dict(label=label,expected=expected,actual=observed))
                        else:report['matching_pairs']+=1
                        return value
                    except (loader.NativeRejected,loader.NativeCapacityError)as error:
                        code=0xffffffff if isinstance(error,loader.NativeRejected)else 0xfffffffe
                        log(dict(stage='RETURN',ordinal=ordinal,code=code,output=span(b'')))
                        report['mismatches'].append(dict(label=label,native_exception=repr(error),expected=expected));return None
                for (label,value),original in zip(rows,actual,strict=True):
                    if value['op']=='session_error':
                        wanted={k:original[k]for k in resultkeys};wanted['variant']=original['variant'];wanted['value_class']=1
                        got=pair(label,corpus.frame(value),wanted,resultkeys+('value_class',),
                            lambda d:dict(variant=names[d['variant']-1]))
                        if value['variant']==6:
                            wanted={k:original[k]for k in resultkeys if k not in ('display','sources')}
                            wanted.update(display=original['io_display'],sources=original['io_sources'],value_class=4)
                            pair(label+':io-value',corpus.frame(value,4),wanted,resultkeys+('value_class',))
                        elif value['variant']==7:
                            wanted=dict(display=original['sources'][0],sources=original['sources'][1:],value_class=5)
                            pair(label+':source-value',corpus.frame(value,5),wanted,('display','sources','value_class'))
                        elif value['variant']==3:
                            wanted=dict(display=original['sources'][0],sources=original['sources'][1:],value_class=6)
                            pair(label+':event-error',corpus.frame(value,3),wanted,('display','sources','value_class'))
                    else:
                        if original['status']=='OK':wanted=dict(display=original['display'],value_class=2)
                        else:wanted=dict(display=original['display'],value_class=3,event_error=original['event_error'],parse_kind=original['parse_kind'])
                        keys=('display','value_class')if original['status']=='OK'else('display','value_class','event_error')
                        extra=None if original['status']=='OK'else lambda d:dict(parse_kind=parse_names[d['parse_kind']])
                        got=pair(label,corpus.frame(value),wanted,keys,extra)
                        if original['status']=='ERROR'and got:
                            derived=dict(op='session_error',variant=3,event_error=got['event_error'],parse_kind=got['parse_kind'])
                            pair(label+':session-error',corpus.frame(derived),
                                dict(display=original['session_display'],sources=original['session_sources'],value_class=1),
                                ('display','sources','value_class'))
                valid=corpus.frame(dict(op='session_error',variant=4))
                controls=[]
                for bit in range(64):
                    b=bytearray(valid);b[bit//8]^=1<<(bit%8);controls.append(('magic:'+str(bit),bytes(b),1<<20,67174400,0xffffffff))
                for at in (16,24,32,40,48,56,64,72,80,88,96,104,112,120):
                    b=bytearray(valid);struct.pack_into('<Q',b,at,0xffffffffffffffff);controls.append(('header:'+str(at),bytes(b),1<<20,67174400,0xffffffff))
                for n in (0,1,63,127,129):
                    controls.append(('length:'+str(n),valid[:n]if n<=128 else valid+b'X',1<<20,67174400,0xffffffff))
                for cap in (0,1,1215):
                    controls.append(('out-cap:'+str(cap),valid,cap,67174400,0xfffffffe))
                for cap in (0,1,67174399):
                    controls.append(('scratch-cap:'+str(cap),valid,1<<20,cap,0xfffffffe))
                for text in (b'\xff',b'\xc0\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xe2\x82',b'\x80',b'\xf5\x80\x80\x80'):
                    base=bytearray(corpus.frame(dict(op='event_id',text=''))[:128]);struct.pack_into('<Q',base,88,8+len(text))
                    controls.append(('utf8:'+text.hex(),bytes(base)+struct.pack('<Q',len(text))+text,1<<20,67174400,0xffffffff))
                output=ctypes.create_string_buffer((1<<20)+16);workspace=session._workspace
                for label,wire,oc,wc,wanted in controls:
                    assert 0<=oc<=1<<20 and 0<=wc<=67174400
                    ctypes.memset(output,169,(1<<20)+16)
                    ordinal=report['actual_hia_entries']+1
                    log(dict(stage='ENTER',ordinal=ordinal,label=label,input=span(wire),output_capacity=oc,workspace_capacity=wc,output_fill=169))
                    report['actual_hia_entries']+=1
                    try:
                        result=native._invoke_buffers(wire,output,workspace,oc,wc);code=len(result)
                    except loader.NativeRejected:code=0xffffffff
                    except loader.NativeCapacityError:code=0xfffffffe
                    observed=bytes(output.raw[:oc]);log(dict(stage='RETURN',ordinal=ordinal,code=code,output=span(observed)))
                    assert code==wanted and observed==b'\xa9'*oc,(label,code,wanted)
                    report['private_refusals']+=1
        assert reference.admit(pin)==handoff
        for path,row in list(PINS.items()):pin(path,row['sha256'])
        report['all_input_sources_rechecked']=True
        assert not report['mismatches'],report['mismatches'][:12]
        report['status']='PASS'
    except BaseException as error:
        report.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());raise
    finally:
        if journal:journal.close()
        if blob:blob.close()
        report['pins']=PINS;report['elapsed_seconds']=time.monotonic()-started
        (OUT/'result.json').write_bytes(J(report))
        print(json.dumps({k:v for k,v in report.items()if k not in ('pins','mismatches','traceback')},sort_keys=True))
if __name__=='__main__':main()
