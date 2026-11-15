def ready_inputs(manifest, closure):
    """Unsealed future identities stop before the first create/rename/copy."""
    assert manifest['schema'] == 'hepta-d1-direct-qualification-input/v1'
    assert closure['schema'] == 'hepta-d1-r35-cache-owner-closure/v1'
    for value in (manifest, closure):
        assert value['sealed'] is True and value['required_missing_bindings'] == []
    assert HEX.fullmatch(manifest['owner_closure_input_sha256'])
    assert manifest['preparation_tool']['path'] == 'prepare_qualify.py'
    assert type(manifest['preparation_tool']['bytes']) is int and HEX.fullmatch(manifest['preparation_tool']['sha256'])
    postflight = closure['postflight']
    assert postflight['job_id'] == OWNER_POSTFLIGHT_JOB
    assert isinstance(postflight['read_pages'], list) and len(postflight['read_pages']) == 3
    assert isinstance(closure['inputs'], dict) and len(closure['inputs']) == 150
    for identity in [postflight['report'], postflight['native'], *postflight['read_pages'], *closure['inputs'].values()]:
        assert isinstance(identity, dict) and Path(identity['path']).is_absolute()
        assert type(identity['bytes']) is int and 0 <= identity['bytes'] <= 8 * 1024 * 1024
        assert HEX.fullmatch(identity['sha256'])
    # Future D1 results are not part of sealing preparation inputs.
    assert manifest['actual_d1_qualification'] is None and manifest['actual_d1_formatted_map'] is None
    assert manifest['actual_d1_test_counts'] is None and manifest['actual_d1_release_programs'] is None


def publication_provenance(manifest):
    identity = manifest['publication_provenance']
    assert identity == {'path': 'provenance/source-anchor-and-publication-parent.json', 'bytes': 2400,
                        'sha256': '99d1e7c4faef98fd680aa7136c3d73e163ca3f64e15f75a1704a6394c8c1fd34'}
    value = json.loads(read_bound(relative_identity(identity)))
    assert value['schema'] == 'hepta-d1-source-anchor-and-publication-parent/v1'
    assert value['source_construction_anchor'] == BASELINE_COMMIT
    assert value['actual_git_parent'] == value['published_candidate_parent_sha'] == manifest['published_candidate_parent']
    assert value['published_candidate_commit'] == manifest['published_candidate_commit']
    rows = value['compiler_input_root_bindings']
    assert [row['path'] for row in rows] == ['src', 'examples', 'Cargo.toml', 'Cargo.lock', 'rustfmt.toml']
    assert all(row['identical'] is True and row['source_anchor_sha'] == row['actual_git_parent_sha'] for row in rows)
    assert value['complete_baseline_compiler_input_map'] == {'files': 220, 'bytes': 24156,
        'sha256': 'c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd'}
    return relative_identity(identity)


def recheck_owner_inputs(closure):
    for identity in closure['inputs'].values():
        read_bound(identity)
    postflight = closure['postflight']
    for identity in (postflight['report'], postflight['native'], *postflight['read_pages']):
        read_bound(identity)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--owner-closure-sha256', required=True)
    args = parser.parse_args()
    assert not sys.flags.optimize, 'assertion guards require normal Python execution'
    destination = ROOT / 'preparation.json'
    assert Path(__file__).resolve() == ROOT / 'prepare_qualify.py'
    assert sys.platform == 'linux' and os.getuid() == 1000 and ROOT.resolve() == ROOT
    input_binding = input_identity(ROOT / 'qualification-input.json', args.input_sha256)
    closure_binding = input_identity(ROOT / 'cache-owner-closure-inputs.json', args.owner_closure_sha256)
    manifest = json.loads(read_bound(input_binding))
    closure = json.loads(read_bound(closure_binding))
    ready_inputs(manifest, closure)
    assert manifest['owner_closure_input_sha256'] == args.owner_closure_sha256
    read_bound(relative_identity(manifest['preparation_tool']))
    assert all(name not in os.environ for name in DIAGNOSTIC_ENV), 'diagnostic environment must be absent during original qualification'
    assert all(not os.path.lexists(ROOT / name) for name in
               ('preparation.json', 'preparation.json.next', 'source', 'qualification-01', 'target-build'))
    report = {'schema': 'hepta-x230-d1-preparation/v1', 'passed': False,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'automatic_retries': 0, 'production_services_modified': False,
              'source_baseline': BASELINE_COMMIT,
              'proposal': 'R24 plus opt-in bounded D1 phase-cost diagnostics; thirteen frozen paths, two additions',
              'diagnostic_name': 'D1', 'performance_acceptance_claim': False,
              'cache_deletions': 0, 'first_actual_d1_qualification_required': True,
              'qualification_started': False,
              'qualified_release_kind': 'phase-cost-diagnostics compiled by original all-features qualification; mode unset',
              'diagnostic_environment_absent': True, 'ordinary_supplemental_executed': False,
              'input_binding': input_binding, 'cache_owner_closure_input': closure_binding}
    # The original first-attempt exclusive claim remains outside try/finally.
    # A duplicate must not replace another invocation's preparation receipt.
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    try:
        candidate_input, patch_binding = frozen_candidate(manifest)
        report['publication_provenance'] = publication_provenance(manifest)
        report['frozen_candidate_input'] = relative_identity(manifest['candidate_input'])
        report['frozen_candidate_manifest'] = relative_identity(manifest['candidate_manifest'])
        report['candidate_patch'] = patch_binding
        report['source_materialization'] = 'accepted R24 source copy plus frozen recovery-02 D1 patch; R35 supplies only closed build cache'
        harness = {p.name: sha(p) for p in sorted((BASE / 'source/tools/x230/20261028').glob('*.py'))}
        assert len(harness) == 19 and harness == manifest['qualification_harness_sha256']
        baseline = source_map(BASE / 'source')
        qualified = json.loads(read_bound(manifest['baseline_qualification']))
        completed_qualification(qualified, BASE / 'source', harness)
        assert baseline == qualified['source_tested'] == candidate_input['baseline_compile_inputs']
        candidate_expected = candidate_input['candidate_compile_inputs']
        assert len(baseline) == 220 and len(candidate_expected) == 222
        assert set(candidate_expected) - set(baseline) == ADDED and not set(baseline) - set(candidate_expected)
        assert {name for name in candidate_expected if candidate_expected[name] != baseline.get(name)} == CHANGED
        report['baseline_qualification'] = manifest['baseline_qualification']
        report['qualification_harness_sha256'] = harness
        report['cache_owner_closure'] = cache_owner_closed(closure, harness)
        cache = CACHE_OWNER / 'target-build'
        assert cache.resolve() == cache and cache.is_dir()
        assert set(p.name for p in cache.iterdir()) == {'debug', 'release', '.rustc_info.json'}
        report['free_bytes_before'] = shutil.disk_usage(ROOT).free
        assert report['free_bytes_before'] >= 3 * 1024**3
        report['retained_programs'] = retained_programs(CACHE_OWNER)
        report['process_check'] = inspect_processes(cache)
        assert not report['process_check']['matched_processes'] and not report['process_check']['compiler_processes']
        report['cache_to_transfer'] = str(cache)
        save(destination, report)
        target = ROOT / 'target-build'
        assert not os.path.lexists(target)
        cache_identity = (cache.stat().st_dev, cache.stat().st_ino)
        cache.rename(target)
        assert (target.stat().st_dev, target.stat().st_ino) == cache_identity and not cache.exists()
        report['cache_transferred_by_rename'] = True
        report['new_full_cache_copy_bytes'] = 0
        for name, digest in report['retained_programs'].items():
            assert sha(Path(name)) == digest
        recheck_owner_inputs(closure)
        source = ROOT / 'source'
        shutil.copytree(BASE / 'source', source)
        assert source_map(source) == baseline
        assert {p.name: sha(p) for p in sorted((source / 'tools/x230/20261028').glob('*.py'))} == harness
        subprocess.run(['/usr/bin/git', 'apply', '--check', str(ROOT / 'candidate/candidate.patch')], cwd=source, check=True)
        subprocess.run(['/usr/bin/git', 'apply', str(ROOT / 'candidate/candidate.patch')], cwd=source, check=True)
        candidate = source_map(source)
        assert candidate == candidate_expected
        report['source_before_qualification'] = candidate
        assert all(name not in os.environ for name in DIAGNOSTIC_ENV)
        command = ['/usr/bin/python3', '-B', '-u', str(source / 'tools/x230/20261028/qualify.py'),
                   '--source', str(source), '--output', str(ROOT / 'qualification-01'),
                   '--target', str(target), '--cargo-home', str(CARGO_HOME), '--jobs', '2']
        report['qualification_command'] = command
        save(destination, report)
        report['qualification_started'] = True
        save(destination, report)
        result = subprocess.run(command, cwd=source)
        report['qualification_returncode'] = result.returncode
        report['source_after_qualification'] = source_map(source)
        if result.returncode == 0:
            actual = json.loads((ROOT / 'qualification-01/report.json').read_bytes())
            completed_qualification(actual, source, harness)
            assert actual['source_input'] == candidate_expected
            assert actual['source_tested'] == report['source_after_qualification']
            assert actual['source_tested'] == json.loads((ROOT / 'qualification-01/source-map.json').read_bytes())
            assert set(actual['source_tested']) == set(candidate_expected)
            assert {name for name in actual['source_tested'] if actual['source_tested'][name] != baseline.get(name)} == CHANGED
            assert actual['source_tested']['Cargo.toml'] == candidate_expected['Cargo.toml']
            actual_cargo = tomllib.loads((source / 'Cargo.toml').read_text())
            assert actual_cargo['features'] == {'phase-cost-diagnostics': []}
            report['qualification_report_sha256'] = sha(ROOT / 'qualification-01/report.json')
            report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save(destination, report)
        print(json.dumps({key: report.get(key) for key in
                          ('passed', 'error', 'qualification_returncode', 'free_bytes_before')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
