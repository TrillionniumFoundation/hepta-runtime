#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Complete retained Worker inputs and raw Native/Original capture reconstruction."""
from pathlib import Path
import hashlib,importlib.util,json,stat,struct,tomllib
W=Path('/home/qq/hepta-worker-owners-original-bd947-v1')
D=Path('/home/qq/hepta-http-transport-bd947-v1')
B=Path('/home/qq/hepta-server-message-codec-bd947-v1')
SHA=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
U=lambda b,n=0:struct.unpack_from('<Q',b,n)[0]
PINS={}
def pin(path,digest=None,cargo_origin=False):
    p=Path(path);s=p.lstat();assert stat.S_ISREG(s.st_mode) and not p.is_symlink(),p
    raw=p.read_bytes();row=dict(bytes=len(raw),sha256=SHA(raw),mode=stat.S_IMODE(s.st_mode))
    if cargo_origin:
        assert p==W/'original-build-v1/target/release/hia-worker-owners-original'
        aliases=[]
        for q in sorted((p.parent/'deps').iterdir()):
            st=q.lstat()
            if (st.st_dev,st.st_ino)==(s.st_dev,s.st_ino):
                assert stat.S_ISREG(st.st_mode)and not q.is_symlink()and q.read_bytes()==raw
                aliases.append(str(q))
        assert len(aliases)+1==s.st_nlink and s.st_nlink in(1,2)
        row.update(cargo_origin=True,link_count=s.st_nlink,known_cargo_aliases=aliases)
    else:assert s.st_nlink==1,p
    if digest is not None:assert row['sha256']==digest,(str(p),row)
    key=str(p.resolve());assert key not in PINS or PINS[key]==row,(key,'changed')
    PINS[key]=row;return raw
def module(path,digest,name):
    pin(path,digest);spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
def durable(ext,job):
    status=ext['status'];read=ext['read']
    assert status['job_id']==read['job_id']==job
    assert status['state']=='succeeded'and status['exit_code']==0
    assert status['output_complete']and status['output_durable']and status['terminal_publication_confirmed']
    assert status['automatic_retry']is status['cancelled']is status['timed_out']is False
    channels=[]
    for name in('stdout','stderr'):
        stream=read[name];raw=bytes.fromhex(stream['bytes_hex'])
        assert stream['offset']==0 and stream['next_offset']==stream['size']==len(raw)
        assert stream['eof']and raw.decode()==stream['text']
        assert status['log_bytes'][name]==dict(seen=len(raw),stored=len(raw))
        assert status['log_synced'][name]and status['log_errors'][name]is None and status['log_truncated'][name]is False
        channels.append(raw)
    return channels
def admit_original():
    root=W/'original-build-v1'
    result=json.loads(pin(root/'result.json','e864076492a9da4019ee399305b296d8c6da5119c03932525dc5979ed502f28d'))
    ext=json.loads(pin(W/'original-build-v1.external.json','3dd6d1f51fa1f4303480792882bd434c471facafd7c963b2c843c26052bc2b2c'))
    out,err=durable(ext,'1a1eb6d0cd5-392-4316');assert not err
    assert json.loads(out)=={k:result[k]for k in('status','phase','fresh_cargo_builds','semantic_executions','elapsed_seconds')}
    assert result['status']=='BUILT_NOT_SEMANTICALLY_QUALIFIED'and result['fresh_cargo_builds']==1 and result['semantic_executions']==0
    source=W/'source-v1';deriv=json.loads(pin(source/'derivation.json','03c0d3baf676d4f9d549e2d8970e00b224f70c47b29255c7ca58e802454b0564'))
    builder=module('/home/qq/hepta-worker-owners-build-original-v1.py','e1be4a8b6952a66141996c2b2c74c1ea2877e092912f786652a6181ef07e7891','worker_original_builder')
    crates=builder.load_helper();assert builder.source_inputs()and builder.parent_checked(crates)
    def recheck():
        for project in(source/'project',root/'project'):
            assert crates.files(project)==result['source_files']==deriv['project_files']
            assert builder.strict_files(project)==result['source_inventory']==deriv['project_full_inventory']
            parent=builder.PARENT/'project';tail=bytes.fromhex(deriv['worker_append']['append_hex'])
            assert (project/builder.WORKER).read_bytes()==(parent/builder.WORKER).read_bytes()+tail
            assert (project/builder.LOCAL).read_bytes()==(parent/builder.LOCAL).read_bytes()
        for process in result['processes']:
            assert process['exit_code']==0 and not process['timed_out']
            for channel in('stdout','stderr'):
                raw=pin(root/(process['name']+'.'+channel),process[channel+'_sha256'])
                assert len(raw)==process[channel+'_bytes']
        metadata=json.loads(pin(root/'cargo-metadata.stdout'));project=root/'project'
        reg=crates.registry(metadata,tomllib.loads((project/'Cargo.lock').read_text()),
            tomllib.loads((project/'original-runtime.lock').read_text()),root/'registry')
        assert reg==result['registry_before']==result['registry_after']and len(reg)==139
        assert crates.files(project/'vendor/rmcp')==result['local_dependency']['members']
        assert len(result['local_dependency']['members'])==175
        for path,want in result['tools'].items():
            raw=pin(path,want['sha256']);assert len(raw)==want['bytes']
        binary=pin(result['binary']['path'],'847634c118a9c9fee29f8d62aab245b37ba54fe2f8acfa9a0fc0bccd115818da')
        assert len(binary)==3019064 and pin(result['binary']['origin'],SHA(binary),cargo_origin=True)==binary
        assert builder.source_inputs()and builder.parent_checked(crates)
    recheck();return result,recheck

def admit_callable(root,build_sha,external_path,external_sha,job):
    root=Path(root);build=json.loads(pin(root/'result.json',build_sha))
    ext=json.loads(pin(external_path,external_sha))
    stdout,stderr=durable(ext,job);assert stderr==b''
    omit=('source_pins','bootstrap_files','compiler_dependency','modules','packers','exports','call_holes','call_targets','call_displacements')
    assert json.loads(stdout)=={k:v for k,v in build.items()if k not in omit}
    assert build['status']=='BUILT_NOT_SEMANTICALLY_QUALIFIED'
    assert build['actual_native_semantic_executions']==build['actual_original_executions']==build['actual_semantic_compiles']==0
    assert build['semantic_images']==build['reused_semantic_images']==32 and build['unchanged_parent_semantic_images']==23
    assert build['unchanged_server_message_semantic_images']==5
    assert build['standard_profile_unchanged'] is True
    for path,want in build['source_pins'].items():
        raw=pin(path,want['sha256']);assert len(raw)==want['bytes']
    binary=pin(root/'adapter.bin')
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
        +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    prefix=header+binary;prefix+=bytes((-len(prefix))%8)
    assert len(prefix)==build['prefix_bytes'] and SHA(prefix)==build['prefix_sha256']
    assert pin(root/'undefined.stdout')==b'' and pin(root/'undefined.stderr')==b''
    assert b'There are no relocations'in pin(root/'relocations.stdout')
    images=[];at=len(prefix)
    for role in sorted(build['modules'],key=lambda name:build['call_targets'][name]):
        info=build['modules'][role];meta=json.loads(pin(info['path'],info['sha256']))
        assert meta==info['module']
        parent=Path(info['path']).parent;pin(parent/meta['source'],meta['source_sha256'])
        image=pin(parent/meta['image'],meta['image_sha256'])
        assert 0<len(image)<=1048576 and build['call_targets'][role]==at
        at+=len(image);images.append(image)
    expected=bytearray(prefix);struct.pack_into('<QQ',expected,96,at,at)
    for role,hole in build['call_holes'].items():
        assert prefix[hole-1:hole+4]==b'\xe8\0\0\0\0'
        delta=build['call_targets'][role]-(hole+4)
        assert delta==build['call_displacements'][role] and -(1<<31)<=delta<1<<31
        struct.pack_into('<I',expected,hole,delta&0xffffffff)
    expected+=b''.join(images)
    artifact=pin(build['artifact']['path'],build['artifact']['sha256'])
    assert artifact==expected and len(artifact)==build['artifact']['bytes']
    pieces=[]
    assert build['actual_packer_compiles']==build['actual_packer_compile_attempts']==len(build['packers'])
    assert build['actual_hia_pack_calls']==build['actual_hia_pack_attempts']==len(build['packers'])
    for i,pack in enumerate(build['packers']):
        meta=json.loads(pin(pack['manifest'],pack['manifest_sha256']));parent=Path(pack['manifest']).parent
        assert meta.get('buffer_profile','standard')=='standard'
        assert meta['input_capacity']==meta['output_capacity']==8388608 and meta['workspace_capacity']==33554432
        pin(parent/meta['source'],meta['source_sha256']);pin(parent/meta['image'],meta['image_sha256'])
        inp=pin(root/(pack['role']+'.input'),pack['input_sha256'])
        out=pin(root/(pack['role']+'.output'),pack['output_sha256'])
        assert len(inp)==pack['input_bytes'] and len(out)==pack['output_bytes']==pack['return_code']
        if i<len(build['packers'])-1:
            assert inp==struct.pack('<QQ',int.from_bytes(b'HRCMPFX1','little'),i)
            assert out==prefix[i*12288:(i+1)*12288];pieces.append(out)
        else:
            all_pieces=pieces+images
            want=struct.pack('<'+str(len(all_pieces)+1)+'Q',int.from_bytes(b'HRCMELF1','little'),*map(len,all_pieces))+b''.join(all_pieces)
            assert inp==want and out==artifact
    assert b''.join(pieces)==prefix
    return build

def recheck_all():
    for path,want in list(PINS.items()):
        pin(path,want['sha256'],cargo_origin=want.get('cargo_origin',False));assert PINS[path]==want
