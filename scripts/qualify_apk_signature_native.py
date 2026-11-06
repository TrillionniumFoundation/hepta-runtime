#!/usr/bin/env python3
"""Qualify the native APK record verifier against REA 6.8.0 and Android apksigner.

Only owned public fixtures are read. This never installs an APK or executes its
payload. The optional existing Bouncy Castle JAR supplies standard JDK PSS aliases
for the unmodified Android verifier; it is not part of the runtime dependency.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import tarfile

from generate_apk_signature_fixtures import verify_command, content_digest


NODE_ORACLE = r'''
import {pathToFileURL} from 'node:url';
import {readFileSync} from 'node:fs';
const request=JSON.parse(readFileSync(0,'utf8'));
const module=await import(pathToFileURL(request.provider).href);
const provider=new module.ApkSignatureProvider();
const reports=[];
try {
  for(const entry of request.files) {
    const result=await provider.inspect({path:entry.path});
    if(result.ok!==true) throw new Error(entry.file+': '+JSON.stringify(result));
    reports.push({file:entry.file,report:result.value.result});
  }
} finally { await provider.close(); }
process.stdout.write(JSON.stringify(reports));
'''


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], capture_output=True, timeout=90, **kwargs)


def check(condition, label):
    if not condition:
        raise AssertionError(label)


def native(binary, data):
    started = time.monotonic()
    result = run([binary, 'rea-apk-signature-worker'], input=data, env={}, cwd='/')
    check(result.returncode == 0, result.stderr.decode(errors='replace'))
    check(len(result.stdout) <= 1024 * 1024 + 1, 'worker output cap')
    return json.loads(result.stdout), time.monotonic() - started


def compare(name, native_report, rea):
    """These field projections are a finite comparison, not an Evidence contract."""
    check(native_report['source']['sha256'] == rea['artifact']['sha256'], name + ': source digest')
    check(native_report['source']['byte_length'] == rea['artifact']['bytes'], name + ': source length')
    check(native_report['verification']['complete_android_verification'] is False, name + ': coverage')
    check(native_report['rea_evidence_compatible'] is False, name + ': independent envelope')
    check((native_report['verification']['v3_1'] == 'present_unverified') == rea['schemes']['v3.1']['present'], name + ': v3.1 presence')
    native_signers = native_report['signers']
    for scheme in ('v2', 'v3'):
        a = [s for s in native_signers if s['scheme'] == scheme]
        b = rea['schemes'][scheme]['signers']
        check(len(a) == len(b), name + ': ' + scheme + ' signer count')
        for left, right in zip(a, b):
            check(left['certificates'][0]['sha256'] == right['certificate']['sha256_fingerprint'], name + ': leaf certificate bytes')
            check(left['public_key_bytes'] == right['public_key_bytes'], name + ': SPKI bytes')
            check(left['uninterpreted_signed_data_bytes'] == right['uninterpreted_signed_data_bytes'], name + ': signed tail')
            check([int(a['id'], 16) for a in left['algorithms']] == [a['signature_algorithm_id'] for a in right['digests']], name + ': algorithm IDs')
            for n, r in zip(left['algorithms'], right['digests']):
                check(n['declared_digest'] == r['declared_digest_hex'], name + ': declared digest')
                check((n['content_digest_status'] == 'match') == r['matches_apk'], name + ': content digest')
            if scheme == 'v3':
                check(left['sdk_range'] == {'min':right['min_sdk'],'max':right['max_sdk']}, name + ': SDK range')
    return {'source_digest':True,'source_length':True,'scheme_signer_counts':True,
            'leaf_certificate_fingerprints':True,'public_key_lengths':True,'signed_tail_lengths':True,
            'algorithm_ids':True,'declared_and_computed_digest_agreement':True,'v3_sdk_ranges':True,
            'v3_1_presence':True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--rea-install', type=Path, required=True)
    parser.add_argument('--rea-tarball', type=Path, help='Frozen rea-agents 6.8.0 npm tarball; defaults to the sibling reference pack directory')
    parser.add_argument('--apksigner', type=Path, required=True)
    parser.add_argument('--bc-provider', type=Path)
    parser.add_argument('--fixtures', type=Path, default=Path('tests/fixtures/rea_apk_signature'))
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.scratch.mkdir(parents=True, exist_ok=True)
    fixture_files = sorted(args.fixtures.glob('*.apk'))
    check(len(fixture_files) == 20, 'expected 19 positive and one forged fixture')
    package = json.loads((args.rea_install / 'package.json').read_text())
    check(package['version'] == '6.8.0', 'frozen REA package version changed')
    tarball = args.rea_tarball or args.rea_install.parents[2] / 'pack' / 'rea-agents-6.8.0.tgz'
    archive_sha256 = hashlib.sha256(tarball.read_bytes()).hexdigest()
    check(archive_sha256 == '8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb', 'frozen REA tarball identity changed')
    package_files_checked = 0
    with tarfile.open(tarball, 'r:gz') as archive:
        for member in archive.getmembers():
            if member.isfile():
                check(member.name.startswith('package/') and '..' not in Path(member.name).parts, 'npm archive entry path')
                installed = args.rea_install / member.name.removeprefix('package/')
                check(installed.read_bytes() == archive.extractfile(member).read(), 'installed REA file differs from frozen npm package: ' + member.name)
                package_files_checked += 1
    request = {'provider':str((args.rea_install/'dist/apkSignature/ApkSignatureProvider.js').resolve()),
               'files':[{'file':p.name,'path':str(p.resolve())} for p in fixture_files]}
    producer = run(['node','--input-type=module','-e',NODE_ORACLE], input=json.dumps(request).encode())
    check(producer.returncode == 0, producer.stderr.decode(errors='replace'))
    rea_reports = {row['file']:row['report'] for row in json.loads(producer.stdout)}
    verifier = verify_command(args.apksigner, args.bc_provider, args.scratch)
    results = []
    for path in fixture_files:
        data = path.read_bytes()
        report, seconds = native(args.binary, data)
        agreement = compare(path.name, report, rea_reports[path.name])
        if report['signing_block']['present']:
            check(report['computed_content_digests']['chunked_sha256'] == content_digest(data,'sha256').hex(), path.name + ': independent SHA256')
            check(report['computed_content_digests']['chunked_sha512'] == content_digest(data,'sha512').hex(), path.name + ': independent SHA512')
        command = [*verifier,'verify','--verbose','--print-certs','--min-sdk-version','21' if path.name.startswith('v1-') else '24']
        if path.name == 'v1-only.apk':
            command += ['--max-sdk-version','23']
        android = run([*command,path])
        forged = path.name == 'forged-matching-digest.apk'
        check((android.returncode == 0) != forged, path.name + ': Android oracle verdict')
        status = report['verification']['v2_v3_records']
        expected = 'invalid' if forged else ('absent' if path.name == 'v1-only.apk' else ('partial' if path.name in ('custom-0202-p521.apk','custom-0103-rsa1024.apk','custom-0103-rsa34.apk','custom-0103-rsa34audit.apk') else 'verified'))
        check(status == expected, path.name + ': native record verdict')
        if forged:
            check(rea_reports[path.name]['schemes']['v2']['signers'][0]['digests'][0]['matches_apk'] is True, 'forged REA digest-only result')
            check(report['signers'][0]['algorithms'][0]['signature_status'] == 'invalid', 'forged signature rejection')
        results.append({'file':path.name,'sha256':hashlib.sha256(data).hexdigest(),
                        'byte_length':len(data),'native_record_status':status,
                        'native_runtime_seconds':round(seconds,3),'android_exit':android.returncode,
                        'android_stdout':android.stdout.decode(),'android_stderr':android.stderr.decode(),
                        'rea_field_comparison':agreement,'native_report':report})
        print('QUALIFIED',path.name,status,flush=True)
    malformed = [b'',b'not an apk',fixture_files[0].read_bytes()[:7],fixture_files[0].read_bytes()[:-1]]
    rejections = []
    for index, data in enumerate(malformed):
        result = run([args.binary,'rea-apk-signature-worker'],input=data,env={},cwd='/')
        check(result.returncode != 0, 'malformed worker input accepted')
        check(len(result.stdout) == 0, 'malformed input emitted a success report')
        check(len(result.stderr) < 65536, 'malformed diagnostics overflow')
        rejections.append({'case':index,'byte_length':len(data),'exit':result.returncode,'stderr':result.stderr.decode(errors='replace')})
    summary = {'format':'hepta.apk-native-qualification.v1','native_binary_sha256':hashlib.sha256(args.binary.read_bytes()).hexdigest(),
               'rea_package_version':package['version'],'rea_frozen_source_revision':'93b8b82db70279e40f484114cff9dc1958dc14ee',
               'rea_tarball_sha256':archive_sha256,'rea_package_files_checked':package_files_checked,
               'node_version':run(['node','--version']).stdout.decode().strip(),
               'rea_provider_sha256':hashlib.sha256(Path(request['provider']).read_bytes()).hexdigest(),
               'apksigner_version':run([args.apksigner,'version']).stdout.decode().strip(),
               'apksigner_jar_sha256':hashlib.sha256((args.apksigner.resolve().parent/'lib/apksigner.jar').read_bytes()).hexdigest(),
               'bc_provider_sha256':hashlib.sha256(args.bc_provider.read_bytes()).hexdigest() if args.bc_provider else None,
               'java_runtime':run(['java','-version']).stderr.decode().strip(),
               'native_source_sha256':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ('src/mcp/rea_apk_signature.rs','src/mcp/rea_apk_signature_parser.rs','src/mcp/rea_apk_signature_worker.rs','src/mcp/rea_apk_signature_tests.rs')},
               'positive_fixtures':19,'forged_matching_digest_fixture':1,'worker_malformed_rejections':rejections,
               'full_android_verification':False,'rea_evidence_compatibility':False,'results':results}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(summary,indent=2)+'\n')
    print('PASS: 20 three-way projections and four actual-worker malformed rejections')


if __name__ == '__main__':
    main()
