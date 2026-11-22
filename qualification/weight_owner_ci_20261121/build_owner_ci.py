"""Build the complete root owner, run isolated synthetic tests, package binaries only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import time

PRIVATE_TEST='mcp::weight_artifact::private_tests::sufficient_positive::canonical_f64_sufficient_heads_accept_then_restore'
SYNTHETIC_TESTS=[
 'mcp::weight_tensor::tests::exact_f32_f16_bf16_offsets_and_noop_bits_are_preserved',
 'mcp::weight_tensor::tests::exact_f64_preserves_subnormals_signed_zero_and_large_finite_bits',
 'mcp::weight_tensor::tests::indices_lengths_unknown_layouts_and_nonfinite_values_are_refused',
 'mcp::weight_tensor::tests::ordering_is_canonical_but_signed_zero_is_not_a_byte_noop',
 'mcp::weight_artifact::tests::exact_patch_improves_a_separate_linear_fixture_and_restores_every_parent_byte',
 'mcp::weight_artifact::tests::no_op_and_f16_bf16_edits_roundtrip_exactly',
 'mcp::weight_artifact::tests::bad_source_identity_or_element_never_publishes_a_partial_artifact',
 'mcp::weight_artifact::tests::corruption_is_detected_before_restore_and_source_size_is_bounded',
]


def pin(path):
    path=Path(path).resolve()
    with path.open('rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
    return dict(path=str(path),bytes=path.stat().st_size,sha256=sha)


def save(path,value):
    with Path(path).open('x') as f:json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())


def main():
    p=argparse.ArgumentParser();p.add_argument('--contract',required=True);a=p.parse_args()
    c=json.loads(Path(a.contract).read_text());root=Path(c['cwd']);attempt=Path(c['attempt_root'])
    output=attempt/'output';output.mkdir(exist_ok=False)
    package=attempt/'public_artifact';package.mkdir(exist_ok=False)
    os.umask(0o022);env=dict(os.environ)
    for key in list(env):
        if key.startswith('HEPTA_PRIVATE_'):env.pop(key)
    env['RUSTUP_TOOLCHAIN']='1.95.0'
    rows=[];binaries=[];reused_lints=[]
    def run(command):
        index=len(rows);start=time.monotonic();before=resource.getrusage(resource.RUSAGE_CHILDREN)
        out=output/f'step_{index:02d}.stdout';err=output/f'step_{index:02d}.stderr'
        with out.open('xb') as stdout,err.open('xb') as stderr:
            r=subprocess.run(command,cwd=root,env=env,stdout=stdout,stderr=stderr,check=False)
        after=resource.getrusage(resource.RUSAGE_CHILDREN)
        row=dict(index=index,command=command,returncode=r.returncode,wall_seconds=time.monotonic()-start,
                 child_CPU_seconds=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                 stdout_pin=pin(out),stderr_pin=pin(err))
        save(output/f'step_{index:02d}.json',row);rows.append(row)
        if r.returncode:raise RuntimeError('failed command: '+str(command))
        return out
    status='FAILED';failure=None
    try:
        run(['rustup','toolchain','install','1.95.0','--profile','minimal'])
        run(['rustup','component','add','rustfmt','clippy','--toolchain','1.95.0'])
        versions={name:pin(run([name,'--version'])) for name in ['rustc','cargo']}
        run(['cargo','fmt','--all','--','--check'])
        if {key:env.get(key) for key in c['profile_overrides']}!=c['profile_overrides']:raise ValueError('actual build profile differs')
        for mode in ['no-default-features']:
            run(['cargo','clippy','--locked','--lib','--tests','--'+mode,'--','-D','warnings'])
            artifact=None;profile=None;reuse=None
            messages=run(['cargo','test','--locked','--lib','--'+mode,'--no-run','--message-format=json'])
            matches=[]
            for line in messages.read_text().splitlines():
                try:record=json.loads(line)
                except ValueError:continue
                if record.get('reason')=='compiler-artifact' and record.get('profile',{}).get('test') and 'lib' in record.get('target',{}).get('kind',[]) and record.get('executable'):
                    matches.append(record)
            if len(matches)!=1:raise ValueError('one exact root library test binary required')
            artifact=matches[0];profile=artifact['profile']
            if artifact['features']!=[]:raise ValueError('only no-default feature mode is admitted')
            expected_profile={'opt_level':'1','debuginfo':0,'debug_assertions':True,'overflow_checks':True,'test':True}
            if {key:profile[key] for key in expected_profile}!=expected_profile or type(profile['debuginfo']) is not int or any(profile[key] is not True for key in ['debug_assertions','overflow_checks','test']):raise ValueError('root compiler-artifact profile differs')
            if Path(artifact['manifest_path']).resolve()!=root/'Cargo.toml' or Path(artifact['target']['src_path']).resolve()!=root/'src/lib.rs':raise ValueError('compiler-artifact is not the root library')
            original=Path(artifact['executable']).resolve();expected_target=Path(env['CARGO_TARGET_DIR']).resolve()
            if not original.is_relative_to(expected_target):raise ValueError('binary outside isolated target')
            save(package/'COMPILER_ARTIFACT_no-default-features.json',artifact)
            original_pin=pin(original);binary=package/('owner-tests-'+mode)
            shutil.copyfile(original,binary);binary.chmod(0o700)
            run(['strip','--strip-debug',str(binary)])
            binary.chmod(0o500)
            listing=run([str(binary),'--list']).read_text().splitlines()
            found={line.removesuffix(': test') for line in listing if line.endswith(': test')}
            if not set(SYNTHETIC_TESTS+[PRIVATE_TEST]).issubset(found):raise ValueError('canonical owner test identity differs')
            ignored=run([str(binary),'--ignored','--list']).read_text()
            if PRIVATE_TEST+': test' not in ignored:raise ValueError('private test is not explicitly ignored')
            for test in SYNTHETIC_TESTS:
                stdout=run([str(binary),'--exact',test,'--test-threads=1','--nocapture'])
                if 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in stdout.read_text():raise ValueError('one synthetic test was not actually executed')
            binaries.append(dict(feature=mode,unstripped_binary_pin=original_pin,qualified_binary_pin=pin(binary),synthetic_tests=SYNTHETIC_TESTS,private_test=PRIVATE_TEST,private_test_executed=False,
                actual_compiler_profile=profile,compiler_artifact_identity={key:artifact[key] for key in ['package_id','manifest_path','target','features','fresh']} if artifact else None,
                reused_binary_provenance=reuse,original_build_source_head=reuse['source_head'] if reuse else c['source_head'],
                qualified_against_source_head=c['source_head'],same_Rust_Cargo_vendor_source=True,
                codegen_units_evidence='256 in unchanged Cargo.toml; compiler-artifact JSON does not report this field'))
        status='PASS'
    except Exception as error:
        failure=repr(error)
        if rows:
            # Only this synthetic-only producer's last step logs enter these named files.
            for stream in ['stdout','stderr']:
                source=Path(rows[-1][stream+'_pin']['path'])
                shutil.copyfile(source,package/('FAILED_STEP_'+stream.upper()+'.txt'))
    source_unchanged=all(pin(p['path'])==p for p in c['source_pins'])
    if not source_unchanged:status='FAILED'
    result=dict(schema='hepta.sufficient-owner-ci-results.v1',status=status,failure=failure,steps=rows,binaries=binaries,
                reused_lints=reused_lints,profile_overrides=c['profile_overrides'],runner_hardware=c['runner_hardware'],
                source_head=c['source_head'],source_tree=c['source_tree'],source_manifest_pin=c['source_manifest_pin'],source_unchanged=source_unchanged,
                planned_new_compile_feature_modes=['no-default-features'],
                actual_successful_new_compile_feature_modes=[row['command'][4].removeprefix('--') for row in rows if row['command'][:4]==['cargo','test','--locked','--lib'] and row['returncode']==0],
                reused_binary_qualified_feature_modes=[row['feature'] for row in binaries if row['reused_binary_provenance'] is not None],
                versions=versions if 'versions' in locals() else None,private_models_uploaded=0,private_test_executions=0,
                production_owner_calls=0,scope='complete no-default root crate with new sufficient-head positive private entry; only the unchanged eight synthetic tests executed; private five-case lifecycle requires separate local admission')
    save(output/'RESULTS.json',result)
    # This is an explicit allowlist: never copy a fixture, workspace, state root or arbitrary log.
    save(package/'SYNTHETIC_RESULTS.json',result)
    shutil.copyfile(c['source_manifest_pin']['path'],package/'SOURCE_MANIFEST.json')
    save(package/'PACKAGE_FILES.json',dict(schema='hepta.canonical-owner-ci-package.v1',status=status,files=[pin(p) for p in sorted(package.iterdir()) if p.is_file()],private_data_allowed=False))
    raise SystemExit(0 if status=='PASS' else 1)


if __name__=='__main__':main()
