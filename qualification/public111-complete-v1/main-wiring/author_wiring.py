"""Prepare a main-entry CI/documentation overlay without changing qualified graph bytes."""
from pathlib import Path
import hashlib,json,yaml

ROOT=Path(__file__).resolve().parent
COMMIT='d397daea2c098746b47e88efa0cb566c6ef71103'
PACKAGE='b33a9e1d8c206b9fd0b98f2a04d42b55e8b466ebe3f39675f22514573c596fcf'
def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':'100644'}
def save(path,text):
    dest=ROOT/'overlay'/path;dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open('x',encoding='utf-8') as f:f.write(text)
    return pin(dest.read_bytes())

def main():
    original=(ROOT/'qualified-workflow.yml.in').read_text()
    first=original[:original.index('permissions:\n')]
    head="""name: Current installed public111 default entry
on:
  workflow_dispatch:
  push:
    branches: ['codex/**', main]
    paths: ['native/**', 'scripts/**', 'authoring/**', 'runtime_support/**', 'tests/hia_native/**', '.github/workflows/hia-public-current.yml', '.github/workflows/hia-runtime-native.yml']
  pull_request:
    paths: ['native/**', 'scripts/**', 'authoring/**', 'runtime_support/**', 'tests/hia_native/**', '.github/workflows/hia-public-current.yml', '.github/workflows/hia-runtime-native.yml']
"""
    marker='      - name: Checkout the exact candidate default entry and complete source package\n'
    checkout="""      - name: Checkout immutable fully qualified public111 recipe
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          repository: TrillionniumFoundation/hepta-runtime
          path: qualification-source
          ref: d397daea2c098746b47e88efa0cb566c6ef71103
          sparse-checkout: tests/hia_native/public111_task_batch_ci
          persist-credentials: false
"""
    old_path='P111_PACKAGE=$GITHUB_WORKSPACE/runtime/tests/hia_native/public111_task_batch_ci'
    new_path='P111_PACKAGE=$GITHUB_WORKSPACE/qualification-source/tests/hia_native/public111_task_batch_ci'
    candidate_test='          test "$(git -C "$GITHUB_WORKSPACE/runtime" rev-parse HEAD)" = "$RUNTIME_SHA"\n'
    recipe_test='          test "$(git -C "$GITHUB_WORKSPACE/qualification-source" rev-parse HEAD)" = '+COMMIT+'\n'
    run='        run: |\n';export='          export GITHUB_SHA="$RUNTIME_SHA"\n'
    assert original.count(marker)==original.count(old_path)==original.count(candidate_test)==9
    assert original.count('@PACKAGE_SHA256@')==1
    workflow=head+original[len(first):]
    workflow=workflow.replace(marker,checkout+marker).replace(old_path,new_path)
    workflow=workflow.replace(candidate_test,candidate_test+recipe_test)
    workflow=workflow.replace(run,run+export).replace('@PACKAGE_SHA256@',PACKAGE)
    recovered=workflow.replace(head,first,1).replace(checkout,'').replace(new_path,old_path)
    recovered=recovered.replace(recipe_test,'').replace(export,'').replace(PACKAGE,'@PACKAGE_SHA256@')
    assert recovered==original,'complete nine-role workflow inverse differs'
    parsed=yaml.safe_load(workflow);old=yaml.safe_load(original)
    roles={'build','original','owner','batch-reference','profiles','authority','connection','native','batch'}
    assert set(parsed['jobs'])==set(old['jobs'])==roles
    for name,job in parsed['jobs'].items():
        assert job['timeout-minutes']==15
        assert job.get('needs')==old['jobs'][name].get('needs')
        assert sum(x.get('with',{}).get('path')=='qualification-source' for x in job['steps'])==1
        assert sum(x.get('with',{}).get('path')=='runtime' for x in job['steps'])==1
        assert all(x['run'].startswith(export.strip()+'\n') for x in job['steps'] if 'run' in x)
    assert '${{ runner.temp }}' not in str(parsed.get('env',{}))
    rows=[]
    def add(path,text):
        before=ROOT/'before'/path
        rows.append({'path':path,'before':pin(before.read_bytes()) if before.exists() else None,
                     'after':save(path,text)})
    add('.github/workflows/hia-public-current.yml',workflow)
    readme=(ROOT/'before/README.md').read_text();start=readme.index('## HIA native implementation');end=readme.index('\n## ',start+4)
    section="""## HIA native implementation

The [HIA native profile](native/README.md) provides executable `.hepta` owners
and Linux ELF transport packers. The resulting program runs without Python,
Rust, libc, or a dynamic loader. A pinned Hepta compiler and explicit Python
build and evidence readers produce and verify the executable.

The default native builder assembles **111 HIA components**: 103 directly linked
owners and an eight-component shared worker capability in 104 physical containers.
The installed catalog advertises nine tools: `host_list`, `effective_config`,
`execution_shadow_admit`, `view`, `workdir`, `directory_create`, `file_move`,
`directory_move` and `text_editor`. The graph also contains the actual Batch
and Bellman call paths; advertising them through a configuration-aware catalog
is a separately qualified successor. Component counts are not tool counts.

TextEditor uses shared Local Create/Replace/Delete/Undo owners. Current SDK
connection, metadata admission, get_info, typed text construction, serial
framing and shutdown are integrated. Configured calls enter the actual
SessionOwner binding owner. Its private stdio identity comes from OS entropy;
protocol peer information is not a caller credential. The request registry
and shared Bellman worker are integrated, while complete asynchronous
interleaving, cancellation and shutdown qualification remains open.

Build and launch the actual default entry with an explicit verified bootstrap:

```sh
python3 -I -B scripts/hia_native_runtime_mcp_build.py \\
  --hepta /absolute/path/to/pinned/Hepta \\
  --bootstrap /absolute/path/to/verified/bootstrap \\
  --output /absolute/path/to/new-public-build
/absolute/path/to/new-public-build/build/public-task-batch/runtime-mcp.elf
```

CI omits `--bootstrap` and freshly compiles all 111 components. The
[current public qualification](native/runtime_mcp_current_qualification.md)
binds the 390 exact source files, actual default builder, nine CI roles,
complete 1,394-record public wire domain, 1,777 private Batch cases and 28
Batch stdio requests, Authority domains, 54-session handshake, public90 and
transport24. Each CI role retains its 15-minute limit; public observer
processes retain 180 seconds and each exchange retains 60 seconds.

The dedicated [historical 58-image source profile](tests/hia_native/historical_public58/README.md)
preserves its original wide-input and SDK comparison evidence. Historical
91- and 102-component profiles also retain their original source identities.
The current default workflow uses the immutable qualified recipe and checks
the actual candidate checkout before building it; it does not substitute a
historical executable for the installed entry.

The production target has 136 registered tool handlers. The existing
production runtime still owns the remaining filesystem, process, host, SSH,
HTTP, document, REA and model-worker behavior. [The source coverage inventory](native/migration.json)
and [exact target snapshot](native/migration_target.json) retain these gaps.
Full SDK, full asynchronous runtime, full handler replacement, production
activation and removal of the old runtime remain unqualified.

The retained component registry and its eleven native partitions and eight
original comparison partitions remain separately qualified. Their counts
and passing results do not imply coverage of the current public graph.
"""
    add('README.md',readme[:start]+section+readme[end:])
    doc="""# Current default111 public qualification

This profile contains **111 HIA components in 104 physical containers**, not
111 tools. Its installed catalog still advertises nine tools. Batch and
Bellman have actual call paths and bounded comparison evidence; the later
configuration-aware catalog is outside this source freeze.

## Exact source and executable

| Identity | Pin |
|---|---|
| Production source commit | `fa2aed97cf22b720d85bd8d08b720aeadba3c4d6` |
| Complete qualification source | `d397daea2c098746b47e88efa0cb566c6ef71103` |
| Source binding, 390 files | `92456e41c9614005b96f3404b1a6dfbc65cc77f798ffd5b0024018ffad156e54` |
| Complete recipe PACKAGE SHA256 | `b33a9e1d8c206b9fd0b98f2a04d42b55e8b466ebe3f39675f22514573c596fcf` |
| Production ELF, 23,486,464 bytes | `a48bfdc90539794ba702c7082d740915ff5152d6d1b308bed9891a17fb6fc151` |
| Fixed FD3 observer ELF, 23,486,464 bytes | `db3d922727d2deac49b3d46fc476d92433c55a53eade086bfb15004025bca822` |
| Hepta compiler | `d3e2c90173cf733e42b299d0c4274df4b593a12f` |
| Current original target | `d3d75c30719db966b004756f610007a7c723729e` |

The public default is `scripts/hia_native_runtime_mcp_build.py`. It freshly
builds the worker and packed capability from `runtime_support/bellman_port`,
then the 103 direct owners. The qualified build compiled 111 HIA components
fresh with no reused bootstrap or direct member. The journal, trace and
private-instance entries reused only those exact same-CI members; the full
graph reader checked their mechanical differences and all packed bytes.

## Completed domains

[Fresh nine-role CI 43979626193](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43979626193)
completed all nine roles successfully, with a 15-minute limit for every role.

| Role | Retained domain |
|---|---|
| build | Actual default entry, 103 fresh direct plus eight fresh packed HIA owners; complete graph and physical controls |
| original | Fresh Rust 1.95.0 current SDK/Bellman public reference, all 1,394 records |
| native | Two real stdio processes, 1,394 records, 1,366 tool cases, 1,393 complete responses; full FD3 worker journal and reader controls |
| batch-reference | Fresh current original, all 1,777 private cases and 28 stdio requests |
| batch | Four private domains of 417, 417, 926 and 17 cases; both stdio domains, complete filesystem/state comparison and retained controls |
| owner | Complete 243-row current SessionOwner reference and 16 controls |
| authority | Two private processes, four sessions, 56 frames, 28 snapshots, retained current-original comparison |
| connection | All 54 handshake sessions / 324 responses, public90, transport24 and four codec-EOF observations |
| profiles | Complete current23 and historical7 public profiles |

The 1,394-record observer used the fixed FD3 entry. The two processes completed
in 134.871454651 and 135.154940671 seconds, within the original 180-second
process limit. The per-exchange limit stayed 60 seconds. Complete wire
comparison retains the one established elapsed-wall-time normalization;
other response bytes and all original inputs remain in the evidence.

The fresh reference preserves actual SDK `arguments` root-Map behavior,
including its distinction from nested Value decoding. It does not replace
public SDK rejection behavior with the older private Value reference.

## Complete independent readback

[Six-role independent readback 43981207344](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43981207344)
and [remaining three-role readback 43982826481](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43982826481)
both completed successfully. Each role recovered the complete original ZIP
and TAR, checked all source Git objects and member byte/mode inventories, and
ran the original full reader under eleven physical guard probes. Before and
after inventories were equal, with no HIA/Rust execution or reader writes.

Local byte-only verification additionally read all nine original archives:
2,629,421,961 ZIP bytes, 63,389 members and 12,383,573,483 logical bytes.
The 741,930,469-byte build ZIP exceeded the download connector's size limit.
[Byte-only export 43984231360](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43984231360)
split that existing ZIP into three verified ranges. Reassembly matched the
original full SHA256 before the complete TAR/member read. No semantic
execution was repeated to recover those bytes.

## Preserved failures and limits

The earlier 180-second failure remains a failure with its full retained prefix.
The narrow accessor optimization preserves checked byte-access ordering,
first-failure and partial-write behavior, and every parser/Value conversion.
Its exact inverse and symbolic proofs are retained alongside the new source.

Source preflight `f47c7f1ffb6cbb4fd8b4738649d3aacd6348dad5` remains failed:
a JavaScript number round trip changed six u64 literals in a composition
file. The successor restored the exact integer text, without changing HIA
or assembly for this repair. All four failed role archives were fully read;
their failure is not relabeled as a qualification pass.

Full asynchronous request interleaving, cancellation and concurrent identity,
full SDK behavior, all 136 handlers, configuration-aware catalog integration,
request audit, scope annotation, production activation and old-stack removal
remain false. SDK notification cancellation is not equivalent to dropping
the handler future. Peer metadata is not an identity credential. The serial
wire domain does not establish those remaining lifecycle properties.

Slots 47-52 remain Batch, 53 shutdown, 54 get_info, 55 connection, 56 authority,
57 Bellman port and 58 request registry. Slots 59-63 are reserved for the
separate extract_lines successor. The private pending ABI remains phase97,
64-byte HRCMFR02 kind4, record offset1280 and control offset1344.

## Main installation

The exact graph delta from base `0a8f9d6603abaf85f702ff2626dbe75f5d5f841c`
contains ten changed and 172 new files; 208 other bound files are unchanged.
Apply those explicit rows, rather than replacing the repository. Preserve
the disjoint `7afd543f` Cargo reader fixes and `08ce7b6f` outcome JSON
normalization fix, including the later combined reporting test file.

The main workflow keeps all nine original roles and command bodies. It
checks out the immutable recipe at `d397daea`, checks the actual candidate's
390 source bytes and executable modes, and invokes that candidate's default
builder. For pull requests the candidate and captured source identity use
the exact PR head, not the synthetic merge revision. This workflow overlay
is source-reviewed; installing it is a separate main-branch action.

Historical 58-, 91- and 102-component evidence retains its exact source
profile. The previous documentation is preserved at base commit `0a8f9d6`.
"""
    add('native/runtime_mcp_current_qualification.md',doc)
    proof={'schema':'hepta.public111.main-wiring-source-proof.v1','status':'SOURCE_STATIC_PASS',
           'qualified_recipe_commit':COMMIT,'qualified_workflow_git_blob':'861e7a2924ca767a39f2912d3862fe8972be9ad7',
           'roles':sorted(roles),'complete_workflow_inverse_equal':True,'all_inner_commands_and_dag_retained':True,
           'job_timeout_minutes':15,'actual_runtime_head_checked_in_each_role':True,
           'qualified_recipe_head_checked_in_each_role':True,'pull_request_capture_identity':'exact PR head',
           'graph_source_modified':False,'native_or_rust_executed':False,'new_workflow_executed':False,
           'rows':rows}
    (ROOT/'STATIC_PROOF.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    print(json.dumps(proof,sort_keys=True))

if __name__=='__main__':main()
