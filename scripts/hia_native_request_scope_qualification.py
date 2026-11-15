"""Admit executed scope/lease evidence without running replacement semantics.

The finite private fixture does not qualify public dispatch, arbitrary
concurrent execution, allocator growth or removal of the original runtime.
"""
from __future__ import annotations
import gzip
import hashlib
import io
import json
import math
from pathlib import Path
import re
import stat
import struct
import sys

from hia_native_build import HEPTA_COMMIT, json_bytes
from hia_native_entropy_qualification import inspect_elf
from hia_native_loader import NativeModule
from hia_native_request_scope_build import members, source_check
from hia_native_scope_qualification import embedded_images
from hia_native_view_cache_qualification import _compiled

FOLDER = 'request-scope'
BOUNDARY_FOLDER = 'request-scope-boundaries'
FIXTURE_KEY = 'request_scope_composition'
NATIVE_SUITE = 'test_request_scope_lifecycle.py'
BOUNDARY_SUITE = 'test_request_scope_boundaries.py'
EVIDENCE_SUITE = 'test_request_scope_evidence.py'
FIRST_ERROR = 0xffff0000
REFUSALS = (0xffffffff, 0xfffffffe, 0xfffffffd)

# Final executed source/corpus identities are installed only after the final
# complete run. Each full raw stream must still be read and checked below.
SOURCE_PINS = {'Cargo.lock': {'bytes': 90148, 'sha256': '7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43'},
 'native/composition_packer.hepta': {'bytes': 282552,
                                     'sha256': '4367179d1c4776853d5c9542db6582b24be2c59c76ac8d1c347d6373cb297d5a'},
 'native/request_cache_lease.hepta': {'bytes': 62428,
                                      'sha256': '27dc4812cb6c471bb38de777ab2329f89d1dc2664d9063ab6614b26a6ca8eec5'},
 'native/request_context.hepta': {'bytes': 43339,
                                  'sha256': '8078c5061920a2675094e51163a13ba811b9af52c96c46e70fd5850a715567a7'},
 'native/request_scope_lifecycle.hepta': {'bytes': 99427,
                                          'sha256': '9db58f6b764221c271fced0a3a25bd523815ce591fdc7c699fb1703194826d84'},
 'native/request_scope_lifecycle_abi.md': {'bytes': 9646,
                                           'sha256': 'c4b6d51721276c272c175525e81018995d2de00be29171cc50aa6e0e69d443c4'},
 'native/request_scope_lifecycle_composition.json': {'bytes': 3880,
                                                     'sha256': 'e70209afee9d347f1747f69dd1b3d891d4c77c357b4529d9b1670d6756a38aeb'},
 'native/text_budget.hepta': {'bytes': 47464,
                              'sha256': '89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9'},
 'native/view_cache.hepta': {'bytes': 64484,
                             'sha256': 'd363c2d3b06bf6d3de0ab20ad40ea3a090baf5d02fef9d280e54e6ef78c6cb01'},
 'scripts/hia_native_build.py': {'bytes': 16253,
                                 'sha256': '7b01d602d50835f2b73a2b7b39761c0cef08a372493985161d59184d52c0dcb2'},
 'scripts/hia_native_composition_build.py': {'bytes': 13830,
                                             'sha256': '7f640609c4a5de0599ccc1ed4132fd608c14dcf9eae9cc3f502526b745fe83d2'},
 'scripts/hia_native_loader.py': {'bytes': 12728,
                                  'sha256': '331b1fdc693df44847723f7171a1338918d1558f1cdc48f558cd29b32f2971e2'},
 'scripts/hia_native_request_scope_build.py': {'bytes': 4130,
                                               'sha256': '8c0975ec076b73ecaccb11179dbca019f77dd1a7ece8390dccfbc40cfc2e4a26'},
 'scripts/hia_native_scope_qualification.py': {'bytes': 29126,
                                               'sha256': '00f7ee12f66554a95847f53bc82c45a894168f33aec2c85aee2e9bd93fe5bd6f'},
 'src/mcp/fs/delta.rs': {'bytes': 9765,
                         'sha256': 'a21e86bc959ce79f35cb7695e908fa37d5fd5fb56e00673ecf4a8cd291c080e1'},
 'src/mcp/request_ctx.rs': {'bytes': 2860,
                            'sha256': '81ebf6e68bcf8c119c83274a090b5e4796d00b3ca6d889c92e9922be0612e943'},
 'src/mcp/server.rs': {'bytes': 178908,
                       'sha256': 'ea43d13d2e870188abc33afca771eb3f5ecacdf982a56467c7b7c2fa0fa81d0d'},
 'tests/hia_native/request_scope_fixture.hepta': {'bytes': 48097,
                                                  'sha256': '9ac408c47fc25504d9af276c3167889e79028fba127260df02f507a501338368'},
 'tests/hia_native/test_request_scope_boundaries.py': {'bytes': 11546,
                                                       'sha256': '4e1044ce4a4f0d4ff4cd137c8d2bfb4bb49925683d3767db7368f9894b32ca3b'},
 'tests/hia_native/test_request_scope_lifecycle.py': {'bytes': 24591,
                                                      'sha256': '9740f4682477f04e4453aeb78247209d38cee5bd5b3061fd969166cbf6c595aa'},
 'scripts/hia_native_entropy_qualification.py': {'bytes': 24405,
                                                 'sha256': '4eed770027867bfa983cab9d46f015cf576004eedd28a561d88062db9fe3f590'},
 'scripts/hia_native_view_cache_qualification.py': {'bytes': 17528,
                                                    'sha256': '1f96cd253842f634fb5854b66031921f689dfa72c0f84a6433e1be333d17ac9f'}}
RUN_PINS = {'await': {'requests': 19,
           'expected_refusals': 8,
           'streams_sha256': '431ffe7d7580f3488e3d4e112fca493c8ef14e611db38146e1fefeb07cc77a87'},
 'cancel': {'requests': 37,
            'expected_refusals': 14,
            'streams_sha256': 'be771a97c5299873bfa96016d3ad3eab1c862ca385ddc64b30a0b2151b0d8851'},
 'interleaved': {'requests': 15,
                 'expected_refusals': 0,
                 'streams_sha256': '61fe3c24b4c14689f0356d6f1adba50898e803b82426019726dce10790036d2b'},
 'leases': {'requests': 20,
            'expected_refusals': 3,
            'streams_sha256': '04fe05c66800439045240855ba95cb3fc4669ca6936373e2902a89a2dcaccf09'},
 'many-leases': {'requests': 8196,
                 'expected_refusals': 0,
                 'streams_sha256': 'cb143f43f6b921467d76e2b6aeedae0d7df154cba914e37af42d901a6e44c090'},
 'preexisting-context': {'requests': 14,
                         'expected_refusals': 1,
                         'streams_sha256': 'd65731cd449a51fbf7f41986779ec7ee9ec0d490975feeb805df95b3475b2e07'},
 'private-admission': {'requests': 25,
                       'expected_refusals': 1,
                       'streams_sha256': '04e9aa231f41e412bdb51aad04df8a58cb730adf87ee31111f7131e7bc5de679'},
 'process-0': {'requests': 6,
               'expected_refusals': 0,
               'streams_sha256': '6a25a1db5a2fb8e3d4337124b6755906b315fe1b255b33b52563274e140c7fc4'},
 'process-1': {'requests': 6,
               'expected_refusals': 0,
               'streams_sha256': '27af8b47a79f0e03119167723cfa6add1df3b8b4df2c89b0ae5099dda9455578'},
 'publisher-handoff': {'requests': 14,
                       'expected_refusals': 1,
                       'streams_sha256': 'd5a6760315712587129a3967db60721fb19f9d07665a342a797fb91bbd1b4206'},
 'refusals': {'requests': 19,
              'expected_refusals': 8,
              'streams_sha256': 'e140807d04faea6b2473e864d7cba2bff4c7ee154fbbb64001f81a853543622c'},
 'short-output': {'requests': 21,
                  'expected_refusals': 10,
                  'streams_sha256': 'aebcca75a29593a178ec67db2d41c81fa04cef3f6c955369b2d1d370561daa2c'},
 'unbound': {'requests': 22,
             'expected_refusals': 0,
             'streams_sha256': '812bcfb875ad547ca065132227677b5c5a704206cc4ede8ce61509265a31cc6c'}}
BOUNDARY_PINS = {'full-actual-arena': {'code': 4294967294,
                       'streams_sha256': '1626737c1f7c315badc668f7f1faf5b6315d2ff823cf95b7c095fa6499b022b2'},
 'count-beyond-actual-arena': {'code': 4294967293,
                               'streams_sha256': '04c8243a1d41a727d2d81c8b04723ae198d6ce9df8abf2cd404a7d2bd329f6a0'},
 'lease-counter-does-not-wrap': {'code': 4294967294,
                                 'streams_sha256': '8c417bc14577ceac41d64b83880d96fe7567123673b1fc53140210358fae489e'},
 'duplicate-private-record': {'code': 4294967293,
                              'streams_sha256': 'f46238ff25a0bbd829a70700dfead232cfc07a9016c24d85eca71359a8e6d066'},
 'bad-magic': {'code': 4294967293,
               'streams_sha256': 'aff014dde37d65f9e5a0f7c9450f50aada24c769d2e12591783955313d4f34a1'},
 'bad-version': {'code': 4294967293,
                 'streams_sha256': '8e3be507d42a0ed36c714611bd901a265b88a8c03355cd59c975be42bc2de337'},
 'zero-generation': {'code': 4294967293,
                     'streams_sha256': '007e54bd9c2071e37698c2cf1b058edc46ab248da6708c7f93dd44e1ca2188e6'},
 'opening-not-accessible': {'code': 4294967293,
                            'streams_sha256': '220ac14a8addcbbb25885a12cc68634c822207166c54c24cc77b9ee87efbfa64'},
 'zero-continuation': {'code': 4294967293,
                       'streams_sha256': '3e1b5574992b6b057f5c12b1e8074fcde79b47efd672686162108ef86d387c7f'},
 'absent-cache-epoch': {'code': 4294967293,
                        'streams_sha256': '03fe3ea088e897a3ca04818f820e785fd5c84b7be7465b8b09b7a67cb55b37e2'},
 'absent-live-lease': {'code': 4294967293,
                       'streams_sha256': '5d73960966c530597cf83a005787267495affb107ba3c1892025f135aba5fbec'},
 'scope-generation-does-not-wrap': {'code': 4294967293,
                                    'streams_sha256': 'cb1c459aa391097a6e1150f52eaaa6d8245de68a5140a0344ec015d18d01d5d9'},
 'continuation-does-not-wrap': {'code': 4294967293,
                                'streams_sha256': '18c17029ba7e879993d1fc6d911c54ebec403e127668b10ca8f435052cc6ca09'},
 'bridge-sequence-does-not-wrap': {'code': 4294967293,
                                   'streams_sha256': '1a29a707fed7f889fe51fb1de2ca1af7b9fddf9234fbea99ea3c65456524a3ef'},
 'cache-epoch-does-not-wrap': {'code': 4294967293,
                               'streams_sha256': '00e8c8dba965c6b6eb8f411fe79caabb0c506647eb2b3bcbb5e309f2c397ea45'},
 'ack-magic': {'code': 4294967293,
               'streams_sha256': '85dcacf19c16ad0dfcc93a10dd459af58284f368a2d24710848cf8ed8c165ede'},
 'ack-sequence': {'code': 4294967293,
                  'streams_sha256': '0cc3e75ad14a2d055b26ca86c1241073869bfcc7a1adf40e757906792c2b34b5'},
 'ack-target': {'code': 4294967293,
                'streams_sha256': 'e98d165863360d2769466f2ffe72a6b3058b538f2b21447b32cd10114c0cdae4'},
 'ack-input-region': {'code': 4294967293,
                      'streams_sha256': '4e9985da15a8d6ed51d5129ff81231bb9b786b1f1080b5e3a6f0a06442137f36'},
 'ack-input-offset': {'code': 4294967293,
                      'streams_sha256': 'e439fd6fde1704b1b9357c3cc103604972c8f0c91d4a8b38dd40a55f3afa7025'},
 'ack-input-length': {'code': 4294967293,
                      'streams_sha256': '041622e2a9efd151ce7d6c1536a68fcdcef5168783c4ed8315969357032a52cd'},
 'ack-output-region': {'code': 4294967293,
                       'streams_sha256': '773a0d8d0cb99ca881263311c226473ee011e4c86e5366fe9f60e00d2fbccc0c'},
 'ack-output-offset': {'code': 4294967293,
                       'streams_sha256': 'e7223ef721ecc4ab1b0ec2699dbca6ebea38ad28d01baafa7966cdd61e8c5f0b'},
 'ack-output-capacity': {'code': 4294967293,
                         'streams_sha256': '4dd50abdb3c45ccb5dbf4661688393afda0efb7d06bde03e3bfb5d8a2e533469'},
 'ack-reserved': {'code': 4294967293,
                  'streams_sha256': '2c86c9eb59430e8e7e31b59548314e09a3292a174ebae5d76b3ef16e7a169797'},
 'ack-completed-sequence': {'code': 4294967293,
                            'streams_sha256': '2c7853d93c9192fc43276c019af111feaeef7aae4b69dfa845fbbd6fbfaa91f1'},
 'ack-completed-flag': {'code': 4294967293,
                        'streams_sha256': '37b249e7d1c915136a2fd6e7d2f9054e681ca13364a13e0c6803c3ef154bdbdb'},
 'ack-status': {'code': 4294967293,
                'streams_sha256': '01a4adc78549c3da6ed41880bc8da2bcd33c5dd502d23fc2b1deb68f608b06cd'},
 'ack-status-with-success': {'code': 4294967293,
                             'streams_sha256': '5f1582bba68dee6dcce4e6029319a179554d50c941138c361351c0a64154d924'},
 'ack-dirty-upper-result': {'code': 4294967293,
                            'streams_sha256': 'e3e23e357ecd5dc7b8adf40f4797a106bcba79588a7ca5e3f42cc3f75d5746f4'},
 'ack-wrong-private-cache-association': {'code': 4294967293,
                                         'streams_sha256': 'c1756a54876eb390fba0a350feeb0bb3e395118dab36ac93fd41ed79f0fce18d'},
 'scope-workspace-short': {'code': 4294967294,
                           'streams_sha256': '606f8b1d737a6fbcd1dd83089567be2c2d51091d01064700fd3dbb5e756e562b'},
 'scope-output-short': {'code': 4294967294,
                        'streams_sha256': '9da0e37774fb1ddd742e58ba312b33b72f73f982993817aa226ba4b23b621eef'},
 'scope-truncated-header': {'code': 4294967295,
                            'streams_sha256': 'f6d4d2219835c2bfcf56fac26af13c5dc9b9f8f7450812418cdb765feb15fa0e'},
 'scope-trailing-byte': {'code': 4294967295,
                         'streams_sha256': 'aec7687140abedcaba84f6e6c848d4a77f6be17406096e077e19694db721a664'},
 'lease-workspace-short': {'code': 4294967294,
                           'streams_sha256': 'ebdaa3ae3f3c7a4e13ffcdae837a822b310a9bc61676bb529e20170dca93583c'},
 'lease-output-short': {'code': 4294967294,
                        'streams_sha256': '6faef5e14d3eab2ae810d9c21a41727a0f5f24558576a118421e7d91ec9cf7b2'},
 'lease-truncated-header': {'code': 4294967295,
                            'streams_sha256': '2edc9fd5af533921ba91d3fd939596484b41b19b714f30a5392170d35367ba57'},
 'lease-trailing-byte': {'code': 4294967295,
                         'streams_sha256': '9ec1275166b50f897cb61eb31858362d7239ba99e5001e99c525f009822ccdb5'},
 'push-window-overflow-8388577': {'code': 4294967294,
                                  'streams_sha256': '0418aa3d757755c0fc91c71bec3df6f075437762c08ec7551022493b5def4a60'},
 'push-window-overflow-16777216': {'code': 4294967294,
                                   'streams_sha256': '65847e04c81ee39099dc25afa67a16710c3a21a4ca3bb3bf27f9ba17f757aff7'}}
NATIVE_GROUPS = 12
BOUNDARY_GROUPS = 4
EVIDENCE_GROUPS = 6
EVIDENCE_CONTROLS = 42


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError('request-scope evidence: ' + message)


def exact(actual, expected, message):
    require(json_bytes(actual) == json_bytes(expected), message)


def decode(raw):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError('request-scope evidence: nonfinite JSON number ' + value)

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def owned(root, relative):
    require(type(relative) is str, 'non-string artifact path')
    name = Path(relative)
    require(bool(name.parts) and not name.is_absolute() and '..' not in name.parts
            and name.as_posix() == relative, 'artifact path escaped owner')
    path = root / name
    require(path.resolve() == path.absolute()
            and stat.S_ISREG(path.lstat().st_mode), 'artifact is not a regular owned file')
    return path


def source_identity(root):
    require(bool(SOURCE_PINS), 'final source pin set is absent')
    proof = source_check(root)
    result = {}
    for name, expected in SOURCE_PINS.items():
        raw = owned(root, name).read_bytes()
        exact({'bytes': len(raw), 'sha256': sha(raw)}, expected, 'source changed: ' + name)
        result[name] = sha(raw)
    for name in ('scripts/hia_native_request_scope_qualification.py',
                 'tests/hia_native/test_request_scope_evidence.py'):
        result[name] = sha(owned(root, name).read_bytes())
    for name in ('legacy_callers_replaced', 'production_dispatcher_installed',
                 'unbounded_cache_storage_closed', 'whole_runtime_replaced'):
        require(proof.get(name) is False, 'unqualified composition claim: ' + name)
    return result


def completed_suite(root, output, report, completed, name, groups):
    rows = [row for row in report['checks'] if row.get('name') == name]
    require(len(rows) == 1, 'exactly one actual suite receipt required: ' + name)
    row = rows[0]
    exact(row.get('command'), [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / name)],
          'suite command differs: ' + name)
    require(type(row.get('exit_code')) is int and row['exit_code'] == 0
            and row.get('timed_out') is False and not row.get('start_error')
            and type(row.get('timeout_seconds')) is int and row['timeout_seconds'] == 180
            and type(row.get('elapsed_seconds')) in (int, float)
            and math.isfinite(row['elapsed_seconds']) and 0 < row['elapsed_seconds'] < 180,
            'suite did not complete within its original limit: ' + name)
    raw_streams = {}
    for suffix in ('stdout', 'stderr'):
        raw = owned(output, name + '.' + suffix).read_bytes()
        exact({'bytes': row.get(suffix + '_bytes'), 'sha256': row.get(suffix + '_sha256')},
              {'bytes': len(raw), 'sha256': sha(raw)}, 'suite raw stream differs: ' + name)
        raw_streams[suffix] = raw
    summary = decode(raw_streams['stdout'])
    require(type(summary) is dict, 'suite summary is not one complete object')
    exact(summary, row.get('summary'), 'stored suite summary differs from stdout')
    observed_row, observed_summary = completed(output, report, name)
    exact(observed_row, row, 'completed callback selected a different process')
    exact(observed_summary, summary, 'completed callback selected a different summary')
    stderr = raw_streams['stderr'].decode('utf-8')
    require(len(re.findall(r'\.\.\. ok\n', stderr)) == groups
            and re.search(r'\nRan ' + str(groups) + r' tests in [0-9.]+s\n\nOK\n\Z', stderr),
            'suite groups were not all executed: ' + name)
    return row, summary


class Evidence:
    def __init__(self, output):
        self.output = output
        self.artifacts = {}

    def retain(self, relative):
        raw = owned(self.output, relative).read_bytes()
        self.artifacts[relative] = sha(raw)
        return raw

    def object(self, relative):
        value = decode(self.retain(relative))
        require(type(value) is dict, 'expected an evidence object: ' + relative)
        return value

    def stream(self, folder, metadata, pin):
        exact(sorted(metadata), sorted(('bytes', 'sha256', 'path', 'gzip_bytes', 'gzip_sha256')),
              'captured stream metadata fields differ')
        require(type(metadata['bytes']) is int and metadata['bytes'] >= 0
                and type(metadata['gzip_bytes']) is int and metadata['gzip_bytes'] > 0,
                'captured stream sizes are not integers')
        exact({key: metadata[key] for key in ('bytes', 'sha256')}, pin,
              'captured raw stream differs from the frozen domain')
        name = metadata['path']
        require(type(name) is str and Path(name).name == name, 'stream path is not a local basename')
        packed = self.retain(folder + '/' + name)
        exact({'bytes': len(packed), 'sha256': sha(packed)},
              {'bytes': metadata['gzip_bytes'], 'sha256': metadata['gzip_sha256']},
              'complete compressed capture differs')
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(packed)) as handle:
                raw = handle.read(pin['bytes'] + 1)
                require(len(raw) == pin['bytes'] and handle.read(1) == b'',
                        'complete uncompressed capture length differs')
        except (OSError, EOFError) as exc:
            raise ValueError('request-scope evidence: invalid gzip capture') from exc
        require(sha(raw) == pin['sha256'], 'complete uncompressed capture bytes differ')
        return raw

    def inventory(self, folder, expected):
        directory = self.output / folder
        require(directory.resolve() == directory.absolute() and directory.is_dir(),
                'corpus directory is not owned')
        paths = set()
        for path in directory.iterdir():
            require(stat.S_ISREG(path.lstat().st_mode), 'unexpected corpus directory or symlink')
            paths.add(path.name)
        exact(sorted(paths), sorted(expected), 'complete corpus inventory differs')


def build_evidence(root, output, report, evidence):
    require(report.get('compiler_commit') == HEPTA_COMMIT, 'compiler dependency commit differs')
    compiler = evidence.retain('build/bootstrap/B3.image.bin')
    require(sha(compiler) == report.get('compiler_image_sha256'), 'compiler executable changed')
    evidence.retain('build/bootstrap/bootstrap.json')
    owner = report[FIXTURE_KEY]
    require(owner.get('builder') == 'request_scope', 'unexpected native composition builder')
    relative = owner['manifest']
    raw = evidence.retain(relative)
    require(sha(raw) == owner.get('sha256'), 'native composition manifest changed')
    meta = decode(raw)
    require(meta.get('schema') == 'hepta.runtime.native-composition.v1'
            and meta.get('target') == 'linux-x86_64'
            and meta.get('compiler_commit') == HEPTA_COMMIT
            and meta.get('compiler_sha256') == sha(compiler)
            and meta.get('runtime_libc_required') is False
            and meta.get('runtime_python_required') is False
            and meta.get('whole_runtime_replaced') is False,
            'native composition compiler, target or runtime claims differ')
    specs = members(root)
    profile = [{'id': i, 'name': spec.name, 'flags': spec.flags, 'call_mask': spec.call_mask,
                'input_capacity': spec.input_capacity, 'output_capacity': spec.output_capacity,
                'workspace_capacity': spec.workspace_capacity,
                'source_sha256': sha(spec.source.read_bytes())} for i, spec in enumerate(specs)]
    exact(meta.get('profile'), profile, 'private image table privileges or capacities differ')
    require(len(meta.get('members', [])) == len(specs), 'native member inventory differs')
    parent = Path(relative).parent
    images = []
    frame = bytearray(b'HIABND01' + struct.pack('<3Q', len(specs), 0, 0))
    entries = [('packer', root / 'native/composition_packer.hepta', meta['packer'])]
    entries += [(f'module_{i:02d}', spec.source, row)
                for i, (spec, row) in enumerate(zip(specs, meta['members']))]
    for index, (stem, source_path, row) in enumerate(entries):
        require(row.get('manifest') == stem + '.json', 'member manifest name differs')
        child_relative = (parent / (stem + '.json')).as_posix()
        child_raw = evidence.retain(child_relative)
        require(sha(child_raw) == row.get('manifest_sha256'), 'member manifest hash differs')
        child = decode(child_raw)
        source = evidence.retain((parent / (stem + '.hepta')).as_posix())
        image = evidence.retain((parent / (stem + '.image.bin')).as_posix())
        require(source == source_path.read_bytes() and sha(source) == row.get('source_sha256')
                and sha(image) == row.get('image_sha256'), 'actual native member bytes differ')
        contract = {'schema': 'hepta.runtime.native-module.v1',
                    'abi': 'hepta.runtime.borrowed-bytes.linux-x86_64.v1', 'target': 'linux-x86_64',
                    'compiler_commit': HEPTA_COMMIT, 'compiler_sha256': sha(compiler),
                    'source': stem + '.hepta', 'image': stem + '.image.bin',
                    'source_sha256': sha(source), 'image_sha256': sha(image),
                    'input_capacity': 8 << 20, 'output_capacity': 8 << 20,
                    'workspace_capacity': 32 << 20, 'standalone': None}
        exact({key: child.get(key) for key in contract}, contract, 'native member contract differs')
        with NativeModule(owned(output, child_relative), manifest_sha256=sha(child_raw)):
            pass
        _compiled(output, output / 'build/modules' / ('composition-' + sha(source)[:24]),
                  source, image, compiler, evidence.artifacts)
        if index:
            images.append(image)
            p = profile[index - 1]
            frame.extend(struct.pack('<8Q', len(image), p['input_capacity'], p['output_capacity'],
                                     p['workspace_capacity'], p['flags'], p['call_mask'], 0, 0))
            frame.extend(bytes.fromhex(sha(source)) + bytes.fromhex(sha(image)) + image)
    require(meta.get('executable') == 'native-local-read.elf', 'native executable name differs')
    executable_relative = (parent / meta['executable']).as_posix()
    executable = evidence.retain(executable_relative)
    layout = embedded_images(executable, profile, images)
    key = sha(json_bytes({'compiler': sha(compiler), 'members': profile,
                         'packer': sha((root / 'native/composition_packer.hepta').read_bytes())}))
    require(meta.get('key') == key and meta.get('frame_sha256') == sha(frame)
            and type(meta.get('frame_bytes')) is int and meta['frame_bytes'] == len(frame)
            and meta.get('executable_sha256') == sha(executable), 'complete packed image identity differs')
    exact(meta.get('inspection'), inspect_elf(executable), 'actual ELF inspection differs')
    exact(meta.get('packing'), {'owner': 'HIA', 'input_unchanged': True,
          'buffer_canaries_unchanged': True, 'packer_image_sha256': meta['packer']['image_sha256']},
          'native packer completion differs')
    return {'manifest_sha256': sha(raw), 'executable_sha256': sha(executable),
            'profile': profile, 'embedded_images': layout}, owned(output, executable_relative)


def native_header(summary):
    require(bool(RUN_PINS), 'final native corpus pin set is absent')
    expected = {'schema': 'hepta.runtime.request-scope-lifecycle-native-corpus.v1',
                'status': 'PASS', 'groups': NATIVE_GROUPS,
                'native_elf_processes': len(RUN_PINS),
                'native_elf_requests': sum(row['requests'] for row in RUN_PINS.values()),
                'native_refusals': sum(row['expected_refusals'] for row in RUN_PINS.values()),
                'original_rust_processes': 0, 'production_dispatcher_installed': False,
                'legacy_callers_replaced': False, 'unbounded_cache_storage_closed': False}
    exact(sorted(summary), sorted(list(expected) + ['binding', 'runs']), 'native summary fields differ')
    exact({key: summary[key] for key in expected}, expected, 'native coverage or scope claim differs')
    exact(sorted(summary['runs']), sorted(RUN_PINS), 'actual ELF process inventory differs')


def native_run(name, record, executable, evidence):
    pin = RUN_PINS[name]
    exact(sorted(record), sorted(('command', 'timeout_seconds', 'elapsed_seconds', 'exit_code',
          'requests', 'expected_refusals', 'streams')), 'ELF process receipt fields differ')
    exact(record['command'], [str(executable), '--local-read-profile', '/request-scope-fixture'],
          'ELF process command differs')
    require(type(record['exit_code']) is int and record['exit_code'] == 0
            and type(record['timeout_seconds']) is int and record['timeout_seconds'] == 90
            and type(record['elapsed_seconds']) in (int, float)
            and math.isfinite(record['elapsed_seconds']) and 0 < record['elapsed_seconds'] < 90,
            'ELF process completion differs')
    exact({key: record[key] for key in ('requests', 'expected_refusals')},
          {key: pin[key] for key in ('requests', 'expected_refusals')}, 'ELF process accounting differs')
    exact(sorted(record['streams']), sorted(('input', 'stdout', 'stderr', 'expected', 'domains')),
          'ELF complete stream inventory differs')
    stream_pins = {kind: {key: metadata[key] for key in ('bytes', 'sha256')}
                   for kind, metadata in record['streams'].items()}
    require(sha(json_bytes(stream_pins)) == pin['streams_sha256'], 'frozen ELF raw domain differs')
    data = {}
    for kind, stream_pin in stream_pins.items():
        metadata = record['streams'][kind]
        require(metadata['path'] == name + '.' + kind + '.gz', 'ELF stream filename differs')
        data[kind] = evidence.stream(FOLDER, metadata, stream_pin)
    require(data['stderr'] == b'' and data['stdout'] == data['expected'],
            'actual complete ELF output differs from its expected domain')
    for kind in ('input', 'stdout'):
        require(data[kind].endswith(b'\n'), 'ELF capture lacks its final complete row')
    requests, responses = data['input'].splitlines(), data['stdout'].splitlines()
    domains = decode(data['domains'])
    require(type(domains) is list and len(requests) == len(responses) == len(domains) == pin['requests'],
            'ELF complete row counts differ')
    refused = 0
    for ordinal, (request, response, domain) in enumerate(zip(requests, responses, domains)):
        require(type(domain) is dict, 'ELF domain row is not an object')
        target, separator, encoded = request.partition(b':')
        require(separator == b':' and re.fullmatch(rb'[0-9]+(?:@[0-9a-f]{8})?', target),
                'ELF private fixture target framing differs')
        packet = bytes.fromhex(encoded.decode('ascii'))
        require(packet.hex().encode() == encoded, 'ELF request hex is not canonical')
        encoded_code, separator, encoded_body = response.partition(b':')
        require(separator == b':' and re.fullmatch(rb'[0-9a-f]{8}', encoded_code),
                'ELF response framing differs')
        code = int(encoded_code, 16)
        body = bytes.fromhex(encoded_body.decode('ascii'))
        require(body.hex().encode() == encoded_body, 'ELF response hex is not canonical')
        exact(sorted(domain), sorted(('ordinal', 'target', 'domain', 'input_bytes', 'input_sha256',
              'expected_code', 'expected_output_sha256')), 'ELF domain fields differ')
        require(type(domain['ordinal']) is int and domain['ordinal'] == ordinal
                and str(domain['target']).encode('ascii') == target
                and type(domain['domain']) is str and bool(domain['domain']),
                'ELF domain ordering or identity differs')
        exact({key: domain[key] for key in ('input_bytes', 'input_sha256', 'expected_code', 'expected_output_sha256')},
              {'input_bytes': len(packet), 'input_sha256': sha(packet), 'expected_code': code,
               'expected_output_sha256': sha(body)}, 'ELF complete row bytes differ')
        if code >= FIRST_ERROR:
            require(code in REFUSALS and not body, 'unrecognized native refusal')
            refused += 1
        else:
            require(code == len(body) and code >= 32
                    and body[:8] in (b'HRSCR001', b'HRCLR001', b'HRCXR001'),
                    'successful native result shape differs')
    require(refused == pin['expected_refusals'], 'actual native refusal count differs')
    return {metadata['path'] for metadata in record['streams'].values()}


def boundary_header(summary):
    require(bool(BOUNDARY_PINS), 'final boundary pin set is absent')
    expected = {'schema': 'hepta.runtime.request-scope-boundary-corpus.v1',
                'status': 'PASS', 'groups': BOUNDARY_GROUPS,
                'native_refusal_calls': len(BOUNDARY_PINS),
                'native_child_requests_issued_without_execution': 1,
                'executed_native_children': 0, 'original_operations': 0}
    exact(sorted(summary), sorted(list(expected) + ['records']), 'boundary summary fields differ')
    exact({key: summary[key] for key in expected}, expected, 'boundary execution domain differs')
    exact([row.get('label') for row in summary['records']], list(BOUNDARY_PINS),
          'boundary record inventory or ordering differs')


def boundary_row(ordinal, record, evidence):
    pin = BOUNDARY_PINS[record['label']]
    exact(sorted(record), sorted(('label', 'classification', 'actual_code', 'expected_code',
          'native_calls', 'executed_native_children', 'original_operations', 'streams',
          'input_beyond_standard_transport_profile')),
          'boundary row fields differ')
    exact({key: record[key] for key in ('classification', 'actual_code', 'expected_code',
          'native_calls', 'executed_native_children', 'original_operations',
          'input_beyond_standard_transport_profile')},
          {'classification': 'injected-private-state-native-refusal', 'actual_code': pin['code'],
           'expected_code': pin['code'], 'native_calls': 1, 'executed_native_children': 0,
           'original_operations': 0,
           'input_beyond_standard_transport_profile': record['streams']['input']['bytes'] > 8 << 20},
          'boundary refuses a different domain or result')
    exact(sorted(record['streams']), sorted(('input', 'workspace-before', 'workspace-after',
          'output-before', 'output-after')), 'boundary stream inventory differs')
    stream_pins = {kind: {key: metadata[key] for key in ('bytes', 'sha256')}
                   for kind, metadata in record['streams'].items()}
    require(sha(json_bytes(stream_pins)) == pin['streams_sha256'], 'frozen boundary raw domain differs')
    data = {}
    for kind, stream_pin in stream_pins.items():
        metadata = record['streams'][kind]
        require(metadata['path'] == f"{ordinal:03d}.{record['label']}.{kind}.gz",
                'boundary stream filename differs')
        data[kind] = evidence.stream(BOUNDARY_FOLDER, metadata, stream_pin)
    require(data['workspace-before'] == data['workspace-after']
            and data['output-before'] == data['output-after']
            and data['output-before'] == b'\xa5' * len(data['output-before']),
            'refused native call changed complete workspace or output')
    return {metadata['path'] for metadata in record['streams'].values()}


def native_evidence(root: Path, output: Path, report: dict, completed) -> dict:
    sources = source_identity(root)
    _, native = completed_suite(root, output, report, completed, NATIVE_SUITE, NATIVE_GROUPS)
    _, boundary = completed_suite(root, output, report, completed, BOUNDARY_SUITE, BOUNDARY_GROUPS)
    native_header(native)
    boundary_header(boundary)
    evidence = Evidence(output)
    exact(evidence.object(FOLDER + '/native-corpus.json'), native,
          'native corpus summary differs from actual process stdout')
    exact(evidence.object(BOUNDARY_FOLDER + '/native-boundary-corpus.json'), boundary,
          'boundary corpus summary differs from actual process stdout')
    binding, executable = build_evidence(root, output, report, evidence)
    exact(native['binding'], binding, 'actual executed private composition differs')
    native_files = {'native-corpus.json'}
    for name in sorted(RUN_PINS):
        native_files.update(native_run(name, native['runs'][name], executable, evidence))
    evidence.inventory(FOLDER, native_files)
    boundary_files = {'native-boundary-corpus.json'}
    for ordinal, row in enumerate(boundary['records']):
        boundary_files.update(boundary_row(ordinal, row, evidence))
    evidence.inventory(BOUNDARY_FOLDER, boundary_files)
    for name in (NATIVE_SUITE, BOUNDARY_SUITE):
        for suffix in ('stdout', 'stderr'):
            evidence.retain(name + '.' + suffix)
    exact(source_identity(root), sources, 'sources changed during complete evidence admission')
    counts = {'native_elf_processes': len(RUN_PINS),
              'native_elf_requests': sum(row['requests'] for row in RUN_PINS.values()),
              'native_elf_refusals': sum(row['expected_refusals'] for row in RUN_PINS.values()),
              'injected_private_state_refusals': len(BOUNDARY_PINS),
              'boundary_inputs_beyond_standard_profile': sum(row['input_beyond_standard_transport_profile']
                                                            for row in boundary['records']),
              'child_requests_issued_without_execution': 1,
              'boundary_executed_children': 0, 'original_processes': 0,
              'native_cases_added_by_validation': 0}
    return {'schema': 'hepta.runtime.request-scope-lifecycle-native-evidence.v1',
            'status': 'PASS', 'counts': counts, 'source_pins': sources,
            'compiler_commit': HEPTA_COMMIT, 'compiler_image_sha256': report['compiler_image_sha256'],
            'composition': binding, 'artifact_sha256': dict(sorted(evidence.artifacts.items())),
            'native_corpus_sha256': sha((output / FOLDER / 'native-corpus.json').read_bytes()),
            'boundary_corpus_sha256': sha((output / BOUNDARY_FOLDER / 'native-boundary-corpus.json').read_bytes()),
            'production_dispatcher_installed': False, 'legacy_callers_replaced': False,
            'unbounded_cache_storage_closed': False, 'whole_runtime_replaced': False}


def qualification_evidence(root: Path, output: Path, report: dict, completed) -> dict:
    native = native_evidence(root, output, report, completed)
    check, summary = completed_suite(root, output, report, completed, EVIDENCE_SUITE, EVIDENCE_GROUPS)
    expected = {'schema': 'hepta.runtime.request-scope-evidence-tests.v1', 'status': 'PASS',
                'groups': EVIDENCE_GROUPS, 'refusal_controls': EVIDENCE_CONTROLS,
                'failures': 0, 'errors': 0, 'skipped': 0, 'new_native_calls': 0,
                'new_original_processes': 0, 'production_dispatcher_installed': False,
                'legacy_callers_replaced': False, 'whole_runtime_replaced': False,
                'native_evidence_sha256': sha(json_bytes(native)),
                'reader_sha256': sha((root / 'scripts/hia_native_request_scope_qualification.py').read_bytes()),
                'test_sha256': sha((root / 'tests/hia_native' / EVIDENCE_SUITE).read_bytes())}
    exact(sorted(summary), sorted(list(expected) + ['controls']), 'evidence suite fields differ')
    exact({key: summary[key] for key in expected}, expected, 'evidence controls used a different native baseline')
    controls = summary['controls']
    require(type(controls) is list and len(controls) == EVIDENCE_CONTROLS
            and all(type(value) is str and bool(value) for value in controls)
            and controls == sorted(set(controls)), 'evidence refusal control inventory differs')
    for suffix in ('stdout', 'stderr'):
        relative = EVIDENCE_SUITE + '.' + suffix
        native['artifact_sha256'][relative] = sha(owned(output, relative).read_bytes())
    native['evidence_controls'] = {'groups': EVIDENCE_GROUPS, 'refusals': EVIDENCE_CONTROLS,
                                   'test_stdout_sha256': check['stdout_sha256'],
                                   'test_stderr_sha256': check['stderr_sha256'],
                                   'controls': controls}
    return native
