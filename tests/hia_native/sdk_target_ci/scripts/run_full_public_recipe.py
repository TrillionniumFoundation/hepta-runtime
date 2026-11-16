#!/usr/bin/env python3
"""Rebuild five original SDK fixtures, retained G1-G5, and the actual eight-tool graph.

Required execution host: authorized Linux x86-64 CI/build worker, pinned Hepta,
Rust 1.95.0 and a populated exact Cargo cache. No precompiled files are inputs.
"""
from pathlib import Path
import argparse, ast, hashlib, importlib.util, json, os, shutil, sys, time, traceback

sha=lambda b:hashlib.sha256(b).hexdigest()

def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def module_from(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def verify(source):
    manifest=json.loads((source/'source-manifest.json').read_bytes())
    assert manifest['schema']=='hepta.g5.public-source-rebuild-bundle.v1'
    for relative,row in manifest['files'].items():
        p=Path(relative);assert not p.is_absolute() and '..' not in p.parts
        path=source/p;assert path.is_file() and not path.is_symlink()
        raw=path.read_bytes();assert len(raw)==row['bytes'] and sha(raw)==row['sha256'],relative
        if path.suffix=='.py':ast.parse(raw,filename=relative)
    base=source/'base-source'
    closure=json.loads((base/'native/runtime_mcp_sources.json').read_bytes())
    for relative,row in closure['sources'].items():
        raw=(base/relative).read_bytes();assert row=={'bytes':len(raw),'sha256':sha(raw)},relative
    g5=source/'g5'
    for file in ['hia-modules.json','frontend-modules.json']:
        for name,row in json.loads((source/'source-pins'/file).read_bytes())['members'].items():
            assert sha((g5/row['source']).read_bytes())==row['source_sha256'],name
    cases=(g5/'cases/normal.jsonl').read_bytes()
    assert sha(cases)==json.loads((g5/'cases/manifest.json').read_bytes())['sha256']
    assert len(cases.splitlines())==654
    cm=json.loads((g5/'cases/context-manifest.json').read_bytes())
    assert sha((g5/'cases/context.bin').read_bytes())==cm['frames_sha256']
    assert sha((g5/'cases/context-types.jsonl').read_bytes())==cm['typed_values_sha256']
    assert len((g5/'cases/context.jsonl').read_bytes().splitlines())==104
    for filename in ['hia_native_build.py','hia_native_loader.py']:
        old=(base/'scripts'/filename).read_text();new=(g5/'scripts'/filename).read_text()
        addition='    "sdk-message-target.v1": (32 << 20, 64 << 20, 256 << 20),\n'
        assert new.count(addition)==1 and new.replace(addition,'',1)==old
    assert sha((source/'native/sdk_public_protocol.hepta').read_bytes())=='ec5ed4c001b7b9446bd700c230751557f2252edaf5009aefc90e6ee6a19ebd64'
    assert sha((g5/'target/Cargo.lock').read_bytes())=='1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631'
    dependencies=module_from('_sdk_ci_source_dependencies',source/'scripts/ci_source_dependencies.py')
    dependencies.verify(source)
    return manifest

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path)
    p.add_argument('--hepta',type=Path);p.add_argument('--rust-bin',type=Path)
    p.add_argument('--check-only',action='store_true');a=p.parse_args()
    source=a.source.resolve(strict=True);manifest=verify(source)
    if a.check_only:
        print(json.dumps({'status':'SOURCE_CHECK_PASS','files':len(manifest['files']),
            'g5_cases':654,'context_cases':104,'native_or_rust_executed':False,
            'actual_eight_tool_loop_qualified':False,
            'five_original_rust_source_closures_checked':True},sort_keys=True));return
    assert a.output is not None and a.hepta is not None and a.rust_bin is not None
    output=a.output.resolve();assert not output.exists() and not output.is_relative_to(source)
    output.mkdir(parents=True)
    for relative in manifest['files']:
        path=output/relative;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source/relative,path)
    shutil.copy2(source/'source-manifest.json',output/'source-manifest.json')
    (output/'evidence').mkdir(exist_ok=True)
    sys.path.insert(0,str(output/'scripts'))
    from exact_rust_build import Recorder,build_exact_oracle
    start=time.monotonic();report={'schema':'hepta.sdk-five-originals.public-source-rebuild.v3','status':'RUNNING',
        'source_manifest_sha256':sha((source/'source-manifest.json').read_bytes()),
        'existing_binary_inputs':False,'fresh_compiler_bootstrap_from_source':False,
        'fresh_cold_qualified':False,'historical_3_4_evidence_promoted':False,
        'target_canonical_v5_adopted':False,'target_connection_identity_integrated':False,
        'target_response_owner_integrated':False,'target_async_transport_integrated':False,
        'retained_g1_g2_g3_g4_domains_reexecuted':False,
        'full_sdk_qualified':False,'full_async_runtime_qualified':False,
        'full_136_route_qualified':False,'five_original_target_oracles_rebuilt':False,
        'native_task_registry_qualified':False,'native_future_cancellation_qualified':False,
        'production_activated':False,'old_path_removed':False,
        'actual_eight_tool_loop_qualified':False}
    def save():put(output/'evidence/recipe-summary.json',report)
    save()
    try:
        g5=output/'g5';(g5/'evidence').mkdir(exist_ok=True)
        g4=g5/'retained/g4';g3=g4/'transport-regression';g2=g3/'joined-g2'
        steps=Recorder(output,'evidence/recipe-processes')
        dependencies=json.loads((output/'ci/dependencies.json').read_bytes())
        frozen_generated={rel:(g3/rel).read_bytes() for rel in ['cases/normal.jsonl','cases/manifest.json']}
        steps.run('generate-normal-transport-inputs',[sys.executable,g3/'scripts/make_normal_cases.py'],cwd=g3)
        for rel,raw in frozen_generated.items():assert (g3/rel).read_bytes()==raw,rel
        generated_manifest=json.loads(frozen_generated['cases/manifest.json'])
        for rel,pin in generated_manifest['files'].items():
            raw=(g3/rel).read_bytes();assert len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],rel
        put(output/'evidence/generated-ordinary-inputs.json',{
            'status':'PASS','files':generated_manifest['files'],
            'generator_sha256':sha((g3/'scripts/make_normal_cases.py').read_bytes()),
            'generated_in_output_only':True,'frozen_manifest_sha256':sha(frozen_generated['cases/manifest.json'])})
        original_receipts=[]
        for spec in dependencies['rust_projects']:
            root=output/spec['root']
            binary,receipt,rec=build_exact_oracle(root,spec['project'],spec['binary'],a.rust_bin,
                evidence_prefix=spec['evidence_prefix'],target_relative=spec['target_directory'])
            raw=(root/spec['cases']).read_bytes()
            observed=rec.run('ordinary-oracle',[binary],stdin=raw,timeout=300)
            (root/spec['observations']).write_bytes(observed)
            receipt.update(actual_target_sdk_executed=True,cases_sha256=sha(raw),
                observations_sha256=sha(observed),source_rebuilt=True,
                current_original_target_commit=dependencies['original_target']['commit'],
                target_lock_sha256=dependencies['original_target']['cargo_lock_sha256'])
            if spec['id']=='connection':
                receipt['get_info_sha256']=sha((root/'oracle/generated_get_info.rs').read_bytes())
            put(root/spec['receipt'],receipt)
            if spec['id']=='connection':
                put(root/'evidence/oracle-observation.json',{
                    'schema':'hepta.g2.fresh-source-ci-observation.v1',
                    'oracle_build_sha256':sha((root/spec['receipt']).read_bytes()),
                    'binary_sha256':receipt['binary_sha256'],'cases_sha256':sha(raw),
                    'observations_sha256':sha(observed),'fresh_build_reused_unchanged':True,
                    'fresh_observation':True,'actual_target_sdk_executed':True,
                    'process_receipt':str((rec.directory/'processes.json').relative_to(root))})
            original_receipts.append({'id':spec['id'],'binary':spec['binary'],
                'receipt':str((root/spec['receipt']).relative_to(output)),
                'receipt_sha256':sha((root/spec['receipt']).read_bytes()),
                'binary_sha256':receipt['binary_sha256']})
        assert len(original_receipts)==5
        report.update(actual_target_oracles_rebuilt=5,five_original_target_oracles_rebuilt=True,
            original_oracles=original_receipts);save()
        sys.path.insert(0,str(g5/'scripts'))
        from hia_native_build import NativeBuild
        buildroot=output/'native-build';build=NativeBuild(a.hepta,buildroot);build.bootstrap()
        assert build.compiler_sha256=='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
        report['fresh_compiler_bootstrap_from_source']=True;save()
        historical=output/'historical-public-source';shutil.copytree(output/'base-source',historical)
        graph=output/'source';shutil.copytree(output/'base-source',graph)
        # The sole build/loader change declares the already-pinned SDK buffer
        # profile. It does not change any of the baseline 58 owner sources.
        for tree in [historical,graph]:
            binding=tree/'native/runtime_mcp_sources.json';doc=json.loads(binding.read_bytes())
            for file in ['hia_native_build.py','hia_native_loader.py']:
                rel='scripts/'+file;raw=(g5/rel).read_bytes();(tree/rel).write_bytes(raw)
                doc['sources'][rel]={'bytes':len(raw),'sha256':sha(raw)}
            put(binding,doc)
        baseline=module_from('_source_rebuild_public58',historical/'scripts/hia_native_runtime_mcp_build.py')
        assert len(baseline.MEMBERS)==58 and len(baseline.EXTRA)==33
        compiled={};baseline_manifests={};baseline_rows=[]
        def compile_one(name,path,profile):
            raw=path.read_bytes();key=sha(raw),profile
            if key not in compiled:
                compiled[key]=build.compile(name,path,standalone=None,buffer_profile=profile)
            return compiled[key]
        for name,owner,profile in baseline.MEMBERS:
            path=compile_one('base-'+name.replace('_','-'),historical/'native'/(owner+'.hepta'),profile)
            row,_=baseline.checked_member(build,historical,name,owner,profile,path)
            baseline_manifests[name]=path;baseline_rows.append(row)
        put(output/'evidence/fresh-baseline-58.json',baseline_rows)
        historical_pack=output/'build-historical';historical_pack.mkdir()
        shutil.copytree(buildroot/'bootstrap',historical_pack/'bootstrap')
        hist_manifest=baseline.build_runtime_mcp(a.hepta,historical_pack,name='historical-eight-public',
            source_root=historical,manifests=baseline_manifests)
        hist=json.loads(hist_manifest.read_bytes())
        expected_hist=json.loads((output/'historical-evidence/historical-eight-build.json').read_bytes())
        assert hist['elf_sha256']==expected_hist['elf_sha256'] and hist['physical_images']==58
        put(output/'evidence/historical-eight-build.json',{'status':'PASS',
            'manifest':str(hist_manifest.relative_to(output)),'manifest_sha256':sha(hist_manifest.read_bytes()),
            'elf':str((hist_manifest.parent/hist['elf']).relative_to(output)),
            'elf_sha256':hist['elf_sha256'],'physical_images':58,
            'all_owners_rebuilt_from_source':True,'target_3_9_body_qualified':False,
            'historical_3_4_evidence_promoted':False})
        # Regenerate and recompile all G5 components. Reuse here means only a
        # matching image freshly compiled above in this same invocation.
        rows={};front={}
        def g5_compile(name,pin):
            original=g5/pin['source'];assert sha(original.read_bytes())==pin['source_sha256']
            path=compile_one('g5-'+name.replace('_','-'),original,pin['buffer_profile'])
            actual=json.loads(path.read_bytes());assert actual['image_sha256']==pin['image_sha256'],name
            return {'path':os.path.relpath(path,g5),'sha256':sha(path.read_bytes()),
                'source':pin['source'],'source_sha256':actual['source_sha256'],
                'image_sha256':actual['image_sha256'],'buffer_profile':pin['buffer_profile']}
        pins=json.loads((output/'source-pins/hia-modules.json').read_bytes())['members']
        for name,pin in pins.items():rows[name]=g5_compile(name,pin)
        put(g5/'evidence/hia-modules.json',{'schema':'hepta.g5.source-rebuilt-modules.v1','members':rows,
            'existing_binary_inputs':False,'fresh_cold_qualified':False})
        steps.run('g5-catalog-request',[sys.executable,g5/'scripts/qualify_catalog_request.py','--run-name','normal-v2'])
        steps.run('author-eight-catalog',[sys.executable,g5/'scripts/author_public_catalog.py','--hepta',a.hepta])
        pins=json.loads((output/'source-pins/frontend-modules.json').read_bytes())['members']
        for name,pin in pins.items():front[name]=g5_compile(name,pin)
        put(g5/'evidence/frontend-modules.json',{'schema':'hepta.g5.source-rebuilt-frontend-modules.v1','members':front})
        steps.run('g5-frontend-context',[sys.executable,g5/'scripts/qualify_frontend.py','--run-name','source-frontend'])
        retained_module=module_from('_sdk_retained_contracts',output/'scripts/run_retained_contracts.py')
        retained_result=retained_module.run_retained(output,a.hepta,buildroot,compile_one,steps)
        assert retained_result['status']=='PASS'
        report.update(retained_g1_g2_g3_g4_domains_reexecuted=True,retained_counts=retained_result);save()
        steps.run('author-public-controller',[sys.executable,output/'scripts/author_public_protocol.py','--hepta',a.hepta])
        assert sha((output/'native/sdk_public_protocol.hepta').read_bytes())=='ec5ed4c001b7b9446bd700c230751557f2252edaf5009aefc90e6ee6a19ebd64'
        controller=compile_one('g5-public-protocol',output/'native/sdk_public_protocol.hepta','sdk-message-target.v1')
        cm=json.loads(controller.read_bytes());assert cm['image_sha256']=='d0ddbb7e5a65210bdfed365e57826b3d1e426d4c1c6b38ebc97f4e576799c231'
        put(output/'evidence/controller-module.json',{'path':str(controller.relative_to(output)),
            'sha256':sha(controller.read_bytes()),'source':'native/sdk_public_protocol.hepta',
            'source_sha256':cm['source_sha256'],'image_sha256':cm['image_sha256'],
            'buffer_profile':'sdk-message-target.v1'})
        steps.env['G5_REFERENCE_ROOT']=str(g5)
        steps.run('g5-native-controller',[sys.executable,output/'scripts/qualify_controller.py','--run-name','source-controller'])
        # Graph overlay uses saved HIA source. Assert equality to the components
        # that were just regenerated and compared against actual target SDK.
        for rel in ['native/runtime_mcp_catalog_target.hepta','native/sdk_request.hepta',
                    'native/sdk_frontend_bridge.hepta','baseline/sdk_message.hepta']:
            assert (output/rel).read_bytes()==(g5/rel).read_bytes()
        steps.run('prepare-public-graph',[sys.executable,output/'scripts/prepare_public_graph.py'])
        original=(graph/'scripts/hia_native_runtime_mcp_build.py').read_text()
        marker='or len(MEMBERS) != 58';assert original.count(marker)==1
        helper=graph/'scripts/hia_native_runtime_mcp_build62.py';helper.write_text(original.replace(marker,'or len(MEMBERS) != 62',1))
        assert sha(helper.read_bytes())=='32f3118dc39b00aa3ee07aace3ec6c7a1fc563db123b5fb46c9730dc4421371d'
        binding=graph/'native/runtime_mcp_sources.json';doc=json.loads(binding.read_bytes())
        doc['sources'][str(helper.relative_to(graph))]={'bytes':helper.stat().st_size,'sha256':sha(helper.read_bytes())};put(binding,doc)
        public=module_from('_source_rebuild_public62',helper)
        custom=[];selected={}
        for name,owner,profile in baseline.MEMBERS[:-5]:
            if name=='catalog':owner='runtime_mcp_catalog_target';path=(g5/front['public_catalog']['path']).resolve()
            elif name=='protocol':owner='sdk_public_protocol';profile='sdk-message-target.v1';path=controller
            else:path=baseline_manifests[name]
            custom.append((name,owner,profile));selected[name]=path
        for name,owner,profile,key in [('target_message','sdk_message_target','sdk-message-target.v1','message'),
                ('target_request','sdk_request_target','serde-json.v1','request'),
                ('target_bridge','sdk_frontend_bridge_target','sdk-message-target.v1','bridge')]:
            row=front[key] if key in front else rows[key]
            custom.append((name,owner,profile));selected[name]=(g5/row['path']).resolve()
        custom.append(('historical_protocol','runtime_mcp_protocol','history.v1'))
        selected['historical_protocol']=baseline_manifests['protocol']
        for name,owner,profile in baseline.MEMBERS[-5:]:
            custom.append((name,owner,profile));selected[name]=baseline_manifests[name]
        assert len(custom)==62
        public.MEMBERS=custom;public.EXTRA=list(public.EXTRA)+[None]*9+['target_message','target_request','target_bridge','historical_protocol']
        assert len(public.EXTRA)==46 and public.EXTRA[19]=='protocol'
        public_pack=output/'build-public';public_pack.mkdir()
        shutil.copytree(buildroot/'bootstrap',public_pack/'bootstrap')
        public_manifest=public.build_runtime_mcp(a.hepta,public_pack,name='public-eight-sdk',
            source_root=graph,manifests=selected)
        data=json.loads(public_manifest.read_bytes());assert data['physical_images']==62
        expected=json.loads((output/'historical-evidence/public-eight-build.json').read_bytes())
        assert data['elf_sha256']==expected['elf_sha256']
        put(output/'evidence/public-eight-build.json',{'status':'PASS',
            'manifest':str(public_manifest.relative_to(output)),'manifest_sha256':sha(public_manifest.read_bytes()),
            'elf':str((public_manifest.parent/data['elf']).relative_to(output)),
            'elf_sha256':data['elf_sha256'],'physical_images':62,
            'all_owners_rebuilt_from_source':True,'target_slots':{'message':42,'request':43,'bridge':44,'historical_protocol':45},
            'reserved_slots':list(range(33,42)),'target_connection_identity_integrated':False,
            'target_response_owner_integrated':False,'target_async_transport_integrated':False})
        steps.run('actual-public-eight-loop',[sys.executable,output/'scripts/qualify_public_loop_ordered.py',
            '--run-name','source-public-loop','--g5-reference',g5],timeout=600)
        loop=json.loads((output/'evidence/source-public-loop/summary.json').read_bytes())
        normal=json.loads((g5/'evidence/normal-v2/summary.json').read_bytes())
        frontend=json.loads((g5/'evidence/source-frontend/summary.json').read_bytes())
        controller_result=json.loads((output/'evidence/source-controller/summary.json').read_bytes())
        assert all(r['status']=='PASS' for r in [loop,normal,frontend,controller_result,retained_result])
        build._recheck()
        report.update(status='PASS',actual_eight_tool_loop_qualified=True,
            physical_images=62,compiled_source_profile_count=len(compiled),
            five_original_target_oracles_rebuilt=True,retained_g1_g2_g3_g4_domains_reexecuted=True,
            historical_native_elf_sha256=hist['elf_sha256'],public_elf_sha256=data['elf_sha256'],
            g5_counts=normal['counts'],frontend_counts=frontend['counts'],
            controller_counts=controller_result['counts'],actual_public_loop_counts=loop['counts'],
            all_original_tool_bodies_current_target_qualified=False,
            source_tree_unchanged=verify(source)==manifest)
    except BaseException:report.update(status='FAIL',failure=traceback.format_exc());raise
    finally:report['elapsed_seconds']=time.monotonic()-start;save()
    print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
