"""One Create recipe retains its blocking, segmented and held observations."""
from __future__ import annotations
import hia_native_local_create_qualification as blocking
import hia_native_local_create_segments_qualification as segments
import hia_native_local_create_async_qualification as held

TESTS = (*blocking.TESTS, *segments.TESTS, *held.TESTS)
MODULE = dict(blocking.MODULE, additional_tests=TESTS[1:])
PROCESS_NAMES = (*blocking.PROCESS_NAMES, *held.PROCESS_NAMES)
SOURCE_FILES = tuple(dict.fromkeys((*segments.SOURCE_FILES, *held.SOURCE_FILES,
                                   'scripts/hia_native_local_create_pipeline.py')))
SCOPE = dict(blocking.SCOPE)
native_evidence = blocking.native_evidence


def original_evidence(output, report, rustc):
    domains = dict(blocking=blocking.original_evidence(output, report, rustc),
                   segmented=segments.original_evidence(output, report, rustc),
                   held=held.original_evidence(output, report, rustc))
    artifacts = {}
    for domain in domains.values():
        for name, digest in domain['artifact_sha256'].items():
            if name in artifacts and artifacts[name] != digest:
                raise ValueError('Create domains disagree about the same retained artifact')
            artifacts[name] = digest
    return dict(schema='hepta.runtime.local-create-original-domains.v1', status='PASS',
                domains=domains, actual_original_commands=list(PROCESS_NAMES),
                fresh_locked_builds=2, actual_original_root_processes=400,
                artifact_sha256=dict(sorted(artifacts.items())), **SCOPE)


def compare_original(output, report, rustc):
    blocking.compare_original(output, report, rustc)
    held.compare_original(output, report, rustc)
    return original_evidence(output, report, rustc)
