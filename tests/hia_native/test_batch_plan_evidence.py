"""Refuse incomplete batch captures and consistently rehashed wrong artifacts."""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
REFERENCE=Path(os.environ.get('HIA_REFERENCE_RUNTIME',ROOT))
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_batch_plan_build import inspect_bundle,read,sha
from hia_native_batch_plan_qualification import (inspect_native,exact_summary,source_composition,
    verify_stream,oracle_dependencies,SOURCE_FILES,REFERENCE_FILES,STREAMS)

def write(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def main(args):
    accepted=inspect_native(ROOT,REFERENCE,args.bundle,args.corpus,hepta=args.hepta)
    refused=[]
    def refuse(name,action):
        try:action()
        except (ValueError,AssertionError,KeyError,EOFError):refused.append(name)
        else:raise AssertionError('corrupt batch evidence was admitted: '+name)
    metadata=json.loads(read(args.corpus/'native-corpus.json'));summary=metadata['report']
    for key,value in [('status','FAIL'),('complete_domain',False),('reference_rows',3173),('control_rows',164),('seconds',float('nan'))]:
        bad=copy.deepcopy(summary);bad[key]=value
        refuse('summary.'+key,lambda bad=bad:exact_summary(bad))
    for domain in ['maximum_50_double_plain','maximum_50_double_stale','maximum_empty_lines','full_operation_count','child_contract_refusal']:
        bad=copy.deepcopy(summary);bad['domains'][domain]-=1
        refuse('omitted.'+domain,lambda bad=bad:exact_summary(bad))
    for field in summary['counts']:
        bad=copy.deepcopy(summary);bad['counts'][field]-=1
        refuse('native_calls.'+field,lambda bad=bad:exact_summary(bad))
    for kind in STREAMS:
        for field,value in [('raw_bytes',0),('raw_sha256','00'*32),('gzip_sha256','00'*32),('file','../outside')]:
            bad=copy.deepcopy(metadata);bad[kind][field]=value
            refuse('stream.'+kind+'.'+field,lambda kind=kind,bad=bad:verify_stream(args.corpus,kind,bad))
    # Copy only this profile's retained artifacts; the original stays read-only.
    bundle=json.loads(read(args.bundle));original_build=args.bundle.parents[2]
    with tempfile.TemporaryDirectory(prefix='hia-batch-evidence-') as temporary:
        base=Path(temporary);build=base/'build';own=base/'owner';reference=base/'reference'
        for name in SOURCE_FILES:
            p=own/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,p)
        for name in set(REFERENCE_FILES)|set(metadata['original_sources']):
            p=reference/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(REFERENCE/name,p)
        clone_bundle=build/args.bundle.relative_to(original_build)
        directories={original_build/row['manifest'] for row in bundle['wide_modules']}
        composition=original_build/bundle['composition']['manifest'];directories.add(composition)
        packed=json.loads(read(composition))
        for row in [packed['packer'],*packed['members']]:
            directories.add(original_build/'modules'/('composition-'+row['source_sha256'][:24])/'manifest.json')
        for manifest in directories:shutil.copytree(manifest.parent,build/manifest.parent.relative_to(original_build))
        (build/'bootstrap').mkdir(parents=True)
        for name in ['B3.image.bin','bootstrap.json']:shutil.copyfile(original_build/'bootstrap'/name,build/'bootstrap'/name)
        clone_bundle.parent.mkdir(parents=True);shutil.copyfile(args.bundle,clone_bundle)
        require_same=lambda:inspect_bundle(clone_bundle,source_root=own,reference_root=reference)
        require_same()
        def changed(name,files,change,action=require_same):
            prior={p:read(p) for p in files}
            try:change();refuse(name,action)
            finally:
                for p,raw in prior.items():p.write_bytes(raw)
        def alter_json(path,fn):
            value=json.loads(read(path));fn(value);write(path,value)
        for key,value in [('compiler_commit','0'*40),('buffer_profile','standard'),('production_activated',True)]:
            changed('bundle.'+key,[clone_bundle],lambda key=key,value=value:alter_json(clone_bundle,lambda v:v.__setitem__(key,value)))
        first=build/bundle['wide_modules'][0]['manifest'];first_meta=json.loads(read(first));image=first.parent/first_meta['image']
        def image_mutation():
            raw=bytearray(read(image));raw[-1]^=1;image.write_bytes(raw)
            alter_json(first,lambda v:v.__setitem__('image_sha256',sha(raw)))
            alter_json(clone_bundle,lambda v:v['wide_modules'][0].__setitem__('manifest_sha256',sha(read(first))))
        changed('consistently_rehashed_wrong_wide_image',[image,first,clone_bundle],image_mutation)
        def capacity_mutation():
            alter_json(first,lambda v:v.__setitem__('output_capacity',8<<20))
            alter_json(clone_bundle,lambda v:v['wide_modules'][0].__setitem__('manifest_sha256',sha(read(first))))
        changed('consistently_rehashed_wide_capacity',[first,clone_bundle],capacity_mutation)
        receipt=first.parent/'module.receipt.json';built=first.parent/'build.json'
        def receipt_mutation():
            alter_json(receipt,lambda v:v.__setitem__('source_unchanged',False))
            alter_json(built,lambda v:v.__setitem__('compile_receipt',json.loads(read(receipt))))
        changed('consistently_rehashed_compile_receipt',[receipt,built],receipt_mutation)
        cloned_composition=build/bundle['composition']['manifest'];elf=cloned_composition.parent/'native-local-read.elf'
        elf.chmod(0o600)  # Mutate only the private test copy; the built ELF stays sealed.
        for name,offset in [('adapter_code',180),('metadata_pointer',228),('metadata_reserved',8752+16),('table_permission',8752+64+48),('table_source_digest',8752+64+64),('embedded_image',8752+64+4*128)]:
            def mutate(offset=offset):
                raw=bytearray(read(elf));raw[offset]^=1;elf.write_bytes(raw)
                alter_json(cloned_composition,lambda v:(v.__setitem__('executable_sha256',sha(raw)),v['inspection'].__setitem__('sha256',sha(raw))))
                alter_json(clone_bundle,lambda v:v['composition'].__setitem__('manifest_sha256',sha(read(cloned_composition))))
            changed('consistently_rehashed_elf.'+name,[elf,cloned_composition,clone_bundle],mutate)
        proof=own/'native/batch_plan_composition.json'
        for name,mutate in [('import_relocation',lambda v:v['imports'][0]['function_relocation'].__setitem__('f2','f69')),
                            ('original_blob',lambda v:v['original_sources']['src/mcp/fs/text_editing.rs'].__setitem__('blob','0'*40)),
                            ('semantic_operation_limit',lambda v:v['original_semantic_limits'].__setitem__('operations',49)),
                            ('static_complete_domain',lambda v:v.__setitem__('static_adapter_complete_five_mib_domain',True))]:
            changed('composition.'+name,[proof],lambda mutate=mutate:alter_json(proof,mutate),lambda:source_composition(own,reference,args.hepta))
        # Neither this checkout name nor the explicit reference name is special.
        source_composition(own,reference,args.hepta)
        lock=own/'tests/hia_native/batch_plan_oracle/Cargo.lock'
        changed('oracle_dependency_checksum',[lock],lambda:lock.write_bytes(read(lock).replace(b'8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682',b'0'*64)),lambda:oracle_dependencies(own,reference))
        original_lock=reference/'Cargo.lock'
        changed('original_baseline_lock',[original_lock],lambda:original_lock.write_bytes(read(original_lock)+b'\n'),lambda:oracle_dependencies(own,reference))
    counts={'accepted_complete_captures':1,'accepted_copied_bundles':1,'accepted_arbitrary_checkout_sources':1,
      'refused_mutations':len(refused),'native_calls_added':0,'original_calls_added':0}
    result={'schema':'hepta.runtime.batch-plan-evidence-tests.v1','status':'PASS','counts':counts,
      'refusals':refused,'corpus_metadata_sha256':accepted['corpus_metadata_sha256'],
      'bundle_manifest_sha256':accepted['bundle_manifest_sha256'],
      'test_sha256':sha(read(Path(__file__))), 'qualification_sha256':sha(read(ROOT/'scripts/hia_native_batch_plan_qualification.py'))}
    if args.result:
        with args.result.open('x') as f:f.write(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,default=os.environ.get('HIA_BATCH_PLAN_BUNDLE'))
    parser.add_argument('--corpus',type=Path,default=os.environ.get('HIA_BATCH_PLAN_CORPUS_DIR'))
    parser.add_argument('--hepta',type=Path,default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--result',type=Path,default=os.environ.get('HIA_BATCH_PLAN_EVIDENCE_RESULT'))
    args=parser.parse_args()
    if not args.bundle or not args.corpus or not args.hepta:parser.error('bundle, fresh complete corpus and pinned compiler source are required')
    main(args)
