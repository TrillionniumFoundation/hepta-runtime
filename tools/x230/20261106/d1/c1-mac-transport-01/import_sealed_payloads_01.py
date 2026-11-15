"""Import only the 23 frozen files into the pre-created private Mac staging tree.

No package code is imported or executed. A failure leaves any created files in
place for inspection; this importer never removes, overwrites, or retries them.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01')
ARCHIVE_NAME = 'sealed-payloads-01.tar.gz'
IMPORTER_NAME = 'import_sealed_payloads_01.py'
ARCHIVE_BYTES = 174654
ARCHIVE_SHA256 = 'efe412bd28dd0e2fa6935f57a699e3742eb91c2d064bb1861f7c63a9282ac760'
EXPECTED = {
    "install_campaign.py": {
        "bytes": 12349,
        "sha256": "0045ac1a119727260a99f4aab98c554e033f3486d16ae45cca9464e0c811d40a"
    },
    "mac/d1_campaign.py": {
        "bytes": 51545,
        "sha256": "8b2a53ebc08627d46885c85ef7639abbe73d14b12a513e3b2f9b0fa528097977"
    },
    "mac/held_agent_campaign_02.py": {
        "bytes": 11374,
        "sha256": "715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65"
    },
    "operator-argv.json": {
        "bytes": 359,
        "sha256": "ea227201c9fba1fd8ea63f9cc29513f371731ed7df669cc36143e1ddd7fefb4e"
    },
    "seal-manifest.json": {
        "bytes": 328810,
        "sha256": "4f0b9447c24788c856c1bbb4664c3ab483e27803ff09c84e9192424f34f69f6b"
    },
    "x230/c1-campaign-inputs-01.json": {
        "bytes": 2503,
        "sha256": "1b99ae9549aa2306973281542c89dbcc8b25517181d79c7288e0d5d5998dbb03"
    },
    "x230/c1-prerequisites-01.json": {
        "bytes": 5063,
        "sha256": "9d5ca9b3d4e276d8f7b830cf028eac9eded76ab3b0f560758279451989c966cb"
    },
    "x230/c1-tools-01/compiler-monitor-policy-01.json": {
        "bytes": 1001,
        "sha256": "ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368"
    },
    "x230/c1-tools-01/compiler_monitor.py": {
        "bytes": 12510,
        "sha256": "afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf"
    },
    "x230/c1-tools-01/compiler_state.py": {
        "bytes": 6243,
        "sha256": "9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251"
    },
    "x230/c1-tools-01/d1_campaign.py": {
        "bytes": 51545,
        "sha256": "8b2a53ebc08627d46885c85ef7639abbe73d14b12a513e3b2f9b0fa528097977"
    },
    "x230/c1-tools-01/d1_prerequisites.py": {
        "bytes": 58168,
        "sha256": "623c8678fe2ed89dae7fb8cdf188e34e009e8d73fee10275f51b753fe3d41b98"
    },
    "x230/c1-tools-01/pre-execution-clarification-01.json": {
        "bytes": 3821,
        "sha256": "7848ccc640e8d44fd042632eda69a93d2b24e07cabb65e83aeef683faeeb8704"
    },
    "x230/c1-tools-01/reference/allocator_environment.py": {
        "bytes": 5879,
        "sha256": "f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525"
    },
    "x230/c1-tools-01/reference/allocator_environment_audit.py": {
        "bytes": 6709,
        "sha256": "4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727"
    },
    "x230/c1-tools-01/reference/analyze_native_observation.py": {
        "bytes": 8708,
        "sha256": "cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66"
    },
    "x230/c1-tools-01/reference/audit_native_evidence.py": {
        "bytes": 17065,
        "sha256": "b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28"
    },
    "x230/c1-tools-01/reference/observation_resources.py": {
        "bytes": 12382,
        "sha256": "f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894"
    },
    "x230/c1-tools-01/reference/run_native_observation.py": {
        "bytes": 3279,
        "sha256": "7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb"
    },
    "x230/c1-tools-01/reference/summarize_trace.py": {
        "bytes": 15057,
        "sha256": "f6e65c2e206d4aa90143a17893e5e57c158bca9f8eec5f74897b19c3596e32c5"
    },
    "x230/c1-tools-01/reference/x230_observation_benchmark.py": {
        "bytes": 37006,
        "sha256": "4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed"
    },
    "x230/c1-tools-01/run_c1_phase_cost.py": {
        "bytes": 34274,
        "sha256": "0902f5a9bf4c085172a61010deb54c74d7b89516fb9cfe1255722ad97b25dea9"
    },
    "x230/c1-tools-01/validate_compiler_monitor.py": {
        "bytes": 7055,
        "sha256": "d2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2"
    }
}
MAX_ARCHIVE = 1024 * 1024
MAX_FILE = 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024
MAX_TAR = MAX_TOTAL + 65536
DIRECTORIES = ('', 'x230', 'x230/c1-tools-01', 'x230/c1-tools-01/reference', 'mac')
DIRECTORY_CHILDREN = {
    '': {'x230', 'mac'}, 'x230': {'c1-tools-01'},
    'x230/c1-tools-01': {'reference'}, 'x230/c1-tools-01/reference': set(), 'mac': set(),
}
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def require(okay, reason):
    if not okay:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def directory_identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)


def read_regular(directory, name, cap):
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            'input is not a standalone regular file: ' + name)
    require(before.st_uid == os.geteuid() and not (before.st_mode & 0o022),
            'input owner or permissions differ: ' + name)
    require(0 <= before.st_size <= cap, 'input exceeds size bound: ' + name)
    fd = os.open(name, READ_FLAGS, dir_fd=directory)
    try:
        require(stamp(os.fstat(fd)) == stamp(before), 'input changed on open: ' + name)
        chunks = []
        size = 0
        while size <= cap:
            raw = os.read(fd, min(65536, cap + 1 - size))
            if not raw:
                break
            chunks.append(raw)
            size += len(raw)
        require(size == before.st_size and size <= cap, 'input length changed: ' + name)
        require(stamp(os.fstat(fd)) == stamp(before), 'input changed while read: ' + name)
        require(stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)) == stamp(before),
                'input path changed while read: ' + name)
        return b''.join(chunks)
    finally:
        os.close(fd)


def octal(raw):
    value = raw.rstrip(b'\0 ')
    require(bool(value) and all(48 <= x <= 55 for x in value), 'invalid USTAR number')
    return int(value, 8)


def parse_archive(raw):
    require(len(raw) == ARCHIVE_BYTES <= MAX_ARCHIVE and sha(raw) == ARCHIVE_SHA256,
            'archive identity differs')
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as stream:
        body = stream.read(MAX_TAR + 1)
    require(len(body) <= MAX_TAR and len(body) % 512 == 0, 'uncompressed tar exceeds bound')
    files = {}
    cursor = 0
    total = 0
    terminated = False
    while cursor + 512 <= len(body):
        header = body[cursor:cursor + 512]
        if header == bytes(512):
            require(len(body) - cursor >= 1024 and not any(body[cursor:]), 'invalid USTAR end')
            terminated = True
            break
        require(len(files) < 23, 'extra tar member')
        require(header[156:157] == b'0' and not any(header[157:257]),
                'nonregular or linked tar member')
        require(header[257:263] == b'ustar\0' and header[263:265] == b'00'
                and not any(header[345:512]), 'unsupported USTAR extension')
        checksum = sum(header[:148]) + 8 * 32 + sum(header[156:])
        require(octal(header[148:156]) == checksum, 'USTAR checksum differs')
        require(octal(header[100:108]) == 0o600 and octal(header[108:116]) == 0
                and octal(header[116:124]) == 0 and octal(header[136:148]) == 0,
                'USTAR fixed metadata differs')
        name_raw = header[:100].split(b'\0', 1)[0]
        require(not any(header[len(name_raw):100]), 'noncanonical tar member name')
        name = name_raw.decode('ascii')
        require(name and not name.startswith('/') and '\\' not in name
                and all(part not in ('', '.', '..') for part in name.split('/')),
                'unsafe tar member path')
        require(name in EXPECTED and name not in files, 'unexpected or duplicate tar member')
        size = octal(header[124:136])
        require(size == EXPECTED[name]['bytes'] and size <= MAX_FILE, 'tar member size differs')
        start = cursor + 512
        end = start + size
        next_header = start + ((size + 511) // 512) * 512
        require(next_header <= len(body), 'truncated tar member')
        raw_file = body[start:end]
        require(sha(raw_file) == EXPECTED[name]['sha256'], 'tar member SHA differs: ' + name)
        require(not any(body[end:next_header]), 'nonzero tar padding')
        total += size
        require(total <= MAX_TOTAL, 'payload total exceeds bound')
        files[name] = raw_file
        cursor = next_header
    require(terminated and set(files) == set(EXPECTED) and len(files) == 23,
            'tar member set or termination differs')
    require(total == 692705, 'frozen payload total differs')
    return files


def check_directories(checks):
    for parent, name, fd, identity in checks:
        require(directory_identity(os.fstat(fd)) == identity, 'directory descriptor changed')
        require(directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity,
                'directory path changed: ' + name)


def inventory(dirs, complete):
    allowed = {key: set(value) for key, value in DIRECTORY_CHILDREN.items()}
    allowed[''].update((ARCHIVE_NAME, IMPORTER_NAME))
    if complete:
        for name in EXPECTED:
            parent, _, leaf = name.rpartition('/')
            allowed[parent].add(leaf)
    for parent, fd in dirs.items():
        require(set(os.listdir(fd)) == allowed[parent],
                'staging contents differ or a payload already exists: ' + (parent or '.'))


def main():
    require(sys.platform == 'darwin' and os.geteuid() != 0, 'requires the non-root Mac owner')
    require(len(sys.argv) == 1 and Path(__file__).absolute() == ROOT / IMPORTER_NAME,
            'fixed importer path or arguments differ')
    require(isinstance(EXPECTED, dict) and len(EXPECTED) == 23, 'unsealed transport importer')
    os.umask(0o077)
    opened = []
    checks = []
    dirs = {}
    try:
        fd = os.open('/', DIR_FLAGS)
        opened.append(fd)
        # All ancestors are checked without following symlinks and remain open.
        for index, name in enumerate(ROOT.parts[1:]):
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode) and before.st_uid in (0, os.geteuid())
                    and not (before.st_mode & 0o022), 'unsafe staging ancestor: ' + name)
            if index == len(ROOT.parts) - 2:
                require(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o700,
                        'staging root is not private and owned')
            child = os.open(name, DIR_FLAGS, dir_fd=fd)
            opened.append(child)
            identity = directory_identity(before)
            require(directory_identity(os.fstat(child)) == identity, 'ancestor changed on open')
            checks.append((fd, name, child, identity))
            fd = child
        dirs[''] = fd
        for relative in DIRECTORIES[1:]:
            parent, _, name = relative.rpartition('/')
            before = os.stat(name, dir_fd=dirs[parent], follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode) and before.st_uid == os.geteuid()
                    and stat.S_IMODE(before.st_mode) == 0o700, 'unsafe private directory: ' + relative)
            child = os.open(name, DIR_FLAGS, dir_fd=dirs[parent])
            opened.append(child)
            identity = directory_identity(before)
            require(directory_identity(os.fstat(child)) == identity, 'private directory changed on open')
            checks.append((dirs[parent], name, child, identity))
            dirs[relative] = child
        check_directories(checks)
        inventory(dirs, False)
        archive = read_regular(dirs[''], ARCHIVE_NAME, MAX_ARCHIVE)
        importer = read_regular(dirs[''], IMPORTER_NAME, MAX_FILE)
        files = parse_archive(archive)
        # Every identity and every absent output is checked before the first write.
        check_directories(checks)
        inventory(dirs, False)
        for name, raw in sorted(files.items()):
            check_directories(checks)
            parent, _, leaf = name.rpartition('/')
            out = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=dirs[parent])
            try:
                offset = 0
                while offset < len(raw):
                    written = os.write(out, raw[offset:])
                    require(written > 0, 'short payload write')
                    offset += written
                os.fsync(out)
                current = os.fstat(out)
                require(stat.S_ISREG(current.st_mode) and current.st_nlink == 1
                        and current.st_uid == os.geteuid() and stat.S_IMODE(current.st_mode) == 0o600,
                        'created payload identity differs')
            finally:
                os.close(out)
            require(read_regular(dirs[parent], leaf, MAX_FILE) == raw, 'payload readback differs: ' + name)
            os.fsync(dirs[parent])
        check_directories(checks)
        inventory(dirs, True)
        for name, identity in EXPECTED.items():
            parent, _, leaf = name.rpartition('/')
            raw = read_regular(dirs[parent], leaf, MAX_FILE)
            require(len(raw) == identity['bytes'] and sha(raw) == identity['sha256'],
                    'final payload identity differs: ' + name)
        require(read_regular(dirs[''], ARCHIVE_NAME, MAX_ARCHIVE) == archive, 'archive changed')
        require(read_regular(dirs[''], IMPORTER_NAME, MAX_FILE) == importer, 'importer changed')
        for directory in dirs.values():
            os.fsync(directory)
        check_directories(checks)
        print(json.dumps({'schema': 'hepta-d1-c1-mac-transport-import/v1', 'imported': True,
                          'files': 23, 'payload_bytes': 692705, 'archive_sha256': ARCHIVE_SHA256,
                          'seal_manifest_sha256': EXPECTED['seal-manifest.json']['sha256'],
                          'target_code_executed': False, 'measurement_started': False}, sort_keys=True))
    finally:
        for fd in reversed(opened):
            os.close(fd)


if __name__ == '__main__':
    main()
