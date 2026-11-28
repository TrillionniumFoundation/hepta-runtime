"""Closed source, compiled artifact and retained reference locations for tests."""
from pathlib import Path
import fcntl,hashlib,json,os,tarfile
ROOT=Path(__file__).resolve().parents[2]
sha=lambda raw:hashlib.sha256(raw).hexdigest()
BUILD_PATH=Path(os.environ['HIA_CONFIG_BUILD']).resolve(strict=True)
BUILD=json.loads(BUILD_PATH.read_bytes())
OUTPUT=Path(os.environ['HIA_REGEX_OUTPUT_DIR']).resolve()
DATA=OUTPUT/'reference-data'


def module_manifest(name):
    item=BUILD['modules'][name];path=Path(item['path']).resolve(strict=True)
    if sha(path.read_bytes())!=item['sha256']:raise ValueError('regex module manifest changed')
    return path


def executable_manifest(profile):
    item=BUILD['executables']['regex_'+profile];path=Path(item['path']).resolve(strict=True)
    if sha(path.read_bytes())!=item['sha256']:raise ValueError('regex executable manifest changed')
    metadata=json.loads(path.read_bytes());elf=(path.parent/metadata['executable']).read_bytes()
    if sha(elf)!=metadata['executable_sha256']or len(elf)!=metadata['executable_bytes']:raise ValueError('regex actual executable changed')
    for member in metadata['members']:
        if sha((ROOT/member['source']).read_bytes())!=member['source_sha256']:raise ValueError('regex executable source changed')
        if sha(elf[member['offset']:member['offset']+member['image_bytes']])!=member['image_sha256']:raise ValueError('regex embedded image changed')
    return path


def executable(profile):
    path=executable_manifest(profile);return path.parent/json.loads(path.read_bytes())['executable']


def prepare_data():
    archive=ROOT/'tests/hia_native/regex_reference_cases.tar.xz';index_path=archive.with_suffix('').with_suffix('.json');index=json.loads(index_path.read_bytes())
    raw=archive.read_bytes()
    if len(raw)!=index['archive_bytes']or sha(raw)!=index['archive_sha256']:raise ValueError('regex reference archive changed')
    OUTPUT.mkdir(parents=True,exist_ok=True)
    if not DATA.exists():
        DATA.mkdir()
        with tarfile.open(archive,'r:xz')as reader:
            members=reader.getmembers()
            if {member.name for member in members}!=set(index['files'])or len(members)!=len(index['files']):raise ValueError('regex reference member set changed')
            for member in members:
                if not member.isfile()or member.name.startswith('/')or'..'in Path(member.name).parts:raise ValueError('invalid regex reference member')
                content=reader.extractfile(member).read();expected=index['files'][member.name]
                if len(content)!=expected['bytes']or sha(content)!=expected['sha256']:raise ValueError('regex reference content changed')
                path=DATA/member.name;path.parent.mkdir(parents=True,exist_ok=True)
                with path.open('xb')as target:target.write(content)
    actual={path.relative_to(DATA).as_posix()for path in DATA.rglob('*')if path.is_file()}
    if actual!=set(index['files']):raise ValueError('regex extracted reference member set changed')
    for name,expected in index['files'].items():
        raw=(DATA/name).read_bytes()
        if len(raw)!=expected['bytes']or sha(raw)!=expected['sha256']:raise ValueError('regex extracted reference content changed')


def data(name):return DATA/name
def artifact(name):return OUTPUT/name


OUTPUT.mkdir(parents=True,exist_ok=True)
with (OUTPUT/'reference-data.lock').open('a+b')as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    prepare_data()
