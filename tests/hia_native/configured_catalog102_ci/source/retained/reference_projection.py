"""Fresh CI-only locked SDK projection of all 216 actual original contexts."""
import argparse
import os
from pathlib import Path
import shutil
import struct
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import static_common as c

def inputs(original):
    for profile_index,profile in enumerate(c.BASE.PROFILES):
        value=c.BASE.Reader(original).document('processes/profile-'+profile+'.stdout')
        flags=0 if profile=='disabled' else 1|(int(profile)<<1)
        assert value['target_commit']==c.BASE.TARGET and len(value['list_cases'])==24
        for index,case in enumerate(value['list_cases']):
            assert (case['protocol_version'],case['cursor_case'])==(c.BASE.VERSIONS[index//3],index%3)
            modern=int(case['protocol_version'] in ('2026-07-28','2026-08-01'))
            raw=case['result_wire'].encode()
            for offset,policy in enumerate((0,2 if modern else 1)):
                sequence=(profile_index*24+index)*2+offset
                header=b'HCATSP01'+struct.pack('<7Q',sequence,flags,modern,policy,len(raw),0,0)
                yield {'sequence':sequence,'profile':profile,'original_case':index,'flags':flags,
                    'modern':modern,'policy':policy,'original_wire':c.pin(raw)},header+raw

def environment(original):
    env={key:value for key,value in os.environ.items() if not (key.startswith('CARGO_') or key.startswith('RUST'))}
    env.update(RUSTUP_TOOLCHAIN='1.95.0',CARGO_TARGET_DIR=str(original/'cargo-target'),
        CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0',CARGO_PROFILE_DEV_DEBUG='0',
        CARGO_ENCODED_RUSTFLAGS='',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1')
    return env

def run(source,target,original,output):
    assert os.environ.get('GITHUB_ACTIONS')=='true','Rust execution is CI-only'
    c.source_check(source)
    c.BASE.reference_module(source/'pipeline/policy_base').verify(original)
    output.mkdir(parents=True,exist_ok=False)
    example=target/'examples/hia_eleven_sdk_projection.rs';assert not example.exists()
    raw=(source/'projection_oracle.rs').read_bytes();example.write_bytes(raw)
    c.put(output/'projection_oracle.rs',raw)
    index=[]
    with (output/'input.bin').open('xb')as stream:
        for row,wire in inputs(original):
            index.append({**row,'offset':stream.tell(),**c.pin(wire)})
            assert stream.write(wire)==len(wire)
    c.put(output/'input-index.json',index)
    from run_recipe import record_process
    env=environment(original)
    record_process(output/'processes','sdk-build',['cargo','build','--locked','--example','hia_eleven_sdk_projection'],
        target,180,env=env)
    binary=original/'cargo-target/debug/examples/hia_eleven_sdk_projection'
    shutil.copyfile(binary,output/'projection.elf');(output/'projection.elf').chmod(0o500)
    record_process(output/'processes','sdk-replay',[str(binary)],target,60,
        env=env,stdin=output/'input.bin')
    assert example.read_bytes()==raw
    assert (target/'src/mcp/server.rs').read_bytes()==(original/'instrumented-server.rs').read_bytes()
    for name in ('Cargo.toml','Cargo.lock'):
        assert (target/name).read_bytes()==(original/'original-source'/name).read_bytes()
    c.put(output/'result.json',{'schema':'hepta.runtime.catalog-eleven-sdk-original.v1','status':'PASS',
        'rows':432,'actual_original_contexts':216,'original_manifest':c.pin((original/'source.json').read_bytes()),
        'source':c.pin(raw),'binary':c.pin((output/'projection.elf').read_bytes()),
        'input':c.pin((output/'input.bin').read_bytes()),'environment':{k:env[k]for k in (
            'RUSTUP_TOOLCHAIN','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_INCREMENTAL','CARGO_PROFILE_DEV_DEBUG',
            'CARGO_ENCODED_RUSTFLAGS','LC_ALL','PYTHONDONTWRITEBYTECODE')},
        'target_root':str(target),'original_root':str(original),'projection_root':str(output)})

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('target','original','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();run(ROOT,a.target.resolve(strict=True),a.original.resolve(strict=True),a.output.absolute())
