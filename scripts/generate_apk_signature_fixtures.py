#!/usr/bin/env python3
"""Generate bounded public APK fixtures using Android apksigner and OpenSSL.

Private test keys exist only in the explicitly selected scratch directory. This
script signs only its own copied fixture packages and never installs an APK.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zipfile


def verify_command(apksigner, provider, scratch):
    if provider is None:
        return [str(apksigner)]
    wrapper = scratch / 'ApkSignerWithBc.java'
    wrapper.write_text('import java.security.Security;\nimport org.bouncycastle.jce.provider.BouncyCastleProvider;\npublic class ApkSignerWithBc { public static void main(String[] args) throws Exception { Security.addProvider(new BouncyCastleProvider()); com.android.apksigner.ApkSignerTool.main(args); } }\n')
    jar = Path(apksigner).resolve().parent / 'lib' / 'apksigner.jar'
    classpath = str(jar) + ':' + str(provider)
    run(['javac', '-cp', classpath, wrapper])
    return ['java', '--class-path', classpath + ':' + str(scratch), 'ApkSignerWithBc']


def run(args, **kwargs):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, check=True, **kwargs)
    return result.stdout


def lp(data):
    return struct.pack('<I', len(data)) + data


def content_digest(data, algorithm):
    eocd = data.rindex(b'PK\x05\x06')
    central = struct.unpack_from('<I', data, eocd + 16)[0]
    start = central
    if data[central - 16:central] == b'APK Sig Block 42':
        start = central - struct.unpack_from('<Q', data, central - 24)[0] - 8
    end_record = bytearray(data[eocd:])
    struct.pack_into('<I', end_record, 16, start)
    chunks = []
    for section in (data[:start], data[central:eocd], end_record):
        for start in range(0, len(section), 1048576):
            chunk = section[start:start + 1048576]
            chunks.append(hashlib.new(algorithm, b'\xa5' + struct.pack('<I', len(chunk)) + chunk).digest())
    return hashlib.new(algorithm, b'\x5a' + struct.pack('<I', len(chunks)) + b''.join(chunks)).digest()


def custom_apk(unsigned, key, certificate, spki, algorithm, scratch):
    """Independent standards encoder; Android apksigner verifies every result."""
    digest_algorithm = 'sha512' if algorithm in (0x0102, 0x0104, 0x0202) else 'sha256'
    digest = content_digest(unsigned, digest_algorithm)
    digest_records = lp(struct.pack('<I', algorithm) + lp(digest))
    signed_data = lp(digest_records) + lp(lp(certificate)) + lp(b'')
    options = ['openssl', 'dgst', '-' + digest_algorithm, '-sign', key]
    if algorithm in (0x0101, 0x0102):
        options += ['-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:digest']
    signature = run(options, input=signed_data)
    signer = lp(signed_data) + lp(lp(struct.pack('<I', algorithm) + lp(signature))) + lp(spki)
    value = lp(lp(signer))
    pairs = struct.pack('<Q', len(value) + 4) + struct.pack('<I', 0x7109871a) + value
    size = struct.pack('<Q', len(pairs) + 24)
    block = size + pairs + size + b'APK Sig Block 42'
    eocd = unsigned.rindex(b'PK\x05\x06')
    central = struct.unpack_from('<I', unsigned, eocd + 16)[0]
    end = bytearray(unsigned[eocd:])
    struct.pack_into('<I', end, 16, central + len(block))
    return unsigned[:central] + block + unsigned[central:eocd] + end



def forge_matching_declaration(data):
    """An attacker updates the payload and signed-data digest declaration without resigning."""
    old_digest = content_digest(data, 'sha256')
    changed = bytearray(data)
    name, extra = struct.unpack_from('<HH', changed, 26)
    changed[30 + name + extra] ^= 1
    new_digest = content_digest(changed, 'sha256')
    end = changed.rindex(b'PK\x05\x06')
    central = struct.unpack_from('<I', changed, end + 16)[0]
    start = central - struct.unpack_from('<Q', changed, central - 24)[0] - 8
    at = changed.index(old_digest, start, central)
    assert changed.find(old_digest, at + 1, central) == -1
    changed[at:at + len(old_digest)] = new_digest
    return bytes(changed)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apksigner', required=True)
    parser.add_argument('--seed', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--bc-provider', type=Path, help='Existing Bouncy Castle JAR for JDK RSA/PSS aliases')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.scratch.mkdir(parents=True, exist_ok=False)
    keys = {}
    for name, algorithm in [('rsa', 'RSA'), ('rsa1024', 'RSA'), ('rsa34', 'RSA'), ('rsa33', 'RSA'), ('rsa34audit', 'RSA'), ('second', 'RSA'), ('p256', 'EC'), ('p384', 'EC'), ('p521', 'EC')]:
        pem = args.scratch / (name + '.pem')
        parameters = ['rsa_keygen_bits:' + ('1024' if name == 'rsa1024' else '2048')] if algorithm == 'RSA' else ['ec_paramgen_curve:' + {'p256':'P-256','p384':'P-384','p521':'P-521'}[name]]
        if name in ('rsa33', 'rsa34', 'rsa34audit'):
            parameters += ['rsa_keygen_pubexp:' + {'rsa33':'8589934591','rsa34':'8589934593','rsa34audit':'8589934609'}[name]]
        command = ['openssl','genpkey','-algorithm',algorithm,'-out',pem]
        for parameter in parameters:
            command += ['-pkeyopt', parameter]
        run(command)
        cert = args.scratch / (name + '-cert.pem')
        run(['openssl','req','-new','-x509','-key',pem,'-out',cert,'-subj','/CN=Hepta APK test '+name,'-days','3650','-set_serial','17'])
        pk8 = args.scratch / (name + '.pk8')
        run(['openssl','pkcs8','-topk8','-nocrypt','-in',pem,'-outform','DER','-out',pk8])
        certificate = run(['openssl','x509','-in',cert,'-outform','DER'])
        spki = run(['openssl','pkey','-in',pem,'-pubout','-outform','DER'])
        keys[name] = (pem, cert, pk8, certificate, spki)
    unsigned = args.seed.read_bytes()
    cases = []

    def sign(name, key='rsa', v1=False, v2=True, v3=True, min_sdk=24, source=args.seed):
        out = args.output / name
        run([args.apksigner,'sign','--key',keys[key][2],'--cert',keys[key][1],
             '--v1-signing-enabled',str(v1).lower(),'--v2-signing-enabled',str(v2).lower(),
             '--v3-signing-enabled',str(v3).lower(),'--v4-signing-enabled','false',
             '--min-sdk-version',str(min_sdk),'--out',out,source])
        cases.append((name,min_sdk))

    sign('rsa-v2.apk', v3=False)
    sign('rsa-v2-v3.apk')
    sign('ecdsa-v2-v3.apk', key='p256')
    sign('v1-only.apk', v1=True, v2=False, v3=False, min_sdk=21)
    sign('v1-v2-v3.apk', v1=True, min_sdk=21)
    boundary = args.scratch / 'unsigned-boundary.apk'
    with zipfile.ZipFile(args.seed) as source, zipfile.ZipFile(boundary, 'w', compression=zipfile.ZIP_STORED) as target:
        for member in source.infolist():
            target.writestr(member, source.read(member.filename))
        target.writestr('assets/boundary.bin', bytes(range(256)) * 8192 + b'section-boundary!')
        target.comment = b'Independent APK digest fixture with ZIP comment'
    sign('chunk-boundary.apk', v3=False, source=boundary)
    for algorithm, key in [(0x0101,'rsa'),(0x0102,'rsa'),(0x0103,'rsa'),(0x0103,'rsa1024'),(0x0103,'rsa34'),(0x0103,'rsa33'),(0x0103,'rsa34audit'),(0x0104,'rsa'),(0x0201,'p384'),(0x0202,'p521')]:
        pem, _, _, cert, spki = keys[key]
        name = f'custom-{algorithm:04x}-{key}.apk'
        (args.output / name).write_bytes(custom_apk(unsigned, pem, cert, spki, algorithm, args.scratch))
        cases.append((name,24))
    out = args.output / 'two-signers-v2.apk'
    run([args.apksigner,'sign','--key',keys['rsa'][2],'--cert',keys['rsa'][1],
         '--next-signer','--key',keys['second'][2],'--cert',keys['second'][1],
         '--v1-signing-enabled','false','--v2-signing-enabled','true','--v3-signing-enabled','false',
         '--v4-signing-enabled','false','--min-sdk-version','24','--out',out,args.seed])
    cases.append((out.name,24))
    lineage = args.scratch / 'lineage.bin'
    run([args.apksigner,'rotate','--out',lineage,'--old-signer','--key',keys['rsa'][2],'--cert',keys['rsa'][1],
         '--new-signer','--key',keys['second'][2],'--cert',keys['second'][1]])
    out = args.output / 'rotation-v31.apk'
    run([args.apksigner,'sign','--key',keys['rsa'][2],'--cert',keys['rsa'][1],
         '--next-signer','--key',keys['second'][2],'--cert',keys['second'][1],
         '--lineage',lineage,'--rotation-min-sdk-version','33',
         '--v1-signing-enabled','false','--v2-signing-enabled','true','--v3-signing-enabled','true',
         '--v4-signing-enabled','false','--min-sdk-version','24','--out',out,args.seed])
    cases.append((out.name,24))
    # Exercise the v3 proof-of-rotation attribute as well as a v3.1 declaration.
    out = args.output / 'rotation-v3.apk'
    run([args.apksigner,'sign','--key',keys['rsa'][2],'--cert',keys['rsa'][1],
         '--next-signer','--key',keys['second'][2],'--cert',keys['second'][1],
         '--lineage',lineage,'--rotation-min-sdk-version','28',
         '--v1-signing-enabled','false','--v2-signing-enabled','true','--v3-signing-enabled','true',
         '--v4-signing-enabled','false','--min-sdk-version','24','--out',out,args.seed])
    cases.append((out.name,24))
    reports = []
    verifier = verify_command(args.apksigner, args.bc_provider, args.scratch)
    for name, min_sdk in cases:
        apk = args.output / name
        command = [*verifier,'verify','--verbose','--print-certs','--min-sdk-version',str(min_sdk)]
        if name == 'v1-only.apk':
            command += ['--max-sdk-version','23']
        command += [apk]
        report = run(command).decode()
        reports.append({'file':name,'sha256':hashlib.sha256(apk.read_bytes()).hexdigest(),
                        'byte_length':apk.stat().st_size,
                        'independent_chunked_sha256':content_digest(apk.read_bytes(),'sha256').hex(),
                        'independent_chunked_sha512':content_digest(apk.read_bytes(),'sha512').hex(),
                        'apksigner_verify_exit':0,'apksigner_verify_stdout':report})
    forged = args.output / 'forged-matching-digest.apk'
    forged.write_bytes(forge_matching_declaration((args.output / 'custom-0103-rsa.apk').read_bytes()))
    negative = subprocess.run([*verifier,'verify','--verbose','--min-sdk-version','24',str(forged)], capture_output=True, text=True)
    assert negative.returncode != 0 and 'signature' in negative.stderr.lower(), negative
    negative_report = {'file':forged.name,'sha256':hashlib.sha256(forged.read_bytes()).hexdigest(),
                       'apksigner_verify_exit':negative.returncode,'apksigner_verify_stderr':negative.stderr,
                       'expected':'declared chunked digest matches; signature invalid'}
    provenance = {'format':'hepta.apk-signature-fixtures.v1','seed_sha256':hashlib.sha256(unsigned).hexdigest(),
                  'apksigner_version':run([args.apksigner,'version']).decode().strip(),
                  'openssl_version':run(['openssl','version']).decode().strip(),
                  'verification_provider':str(args.bc_provider) if args.bc_provider else 'JDK default',
                  'test_keys':'generated for these fixtures; private keys are excluded from the repository',
                  'fixtures':reports,'negative_fixtures':[negative_report]}
    (args.output / 'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    print(json.dumps({'generated':len(reports),'files':[row['file'] for row in reports]}))


if __name__ == '__main__':
    main()
