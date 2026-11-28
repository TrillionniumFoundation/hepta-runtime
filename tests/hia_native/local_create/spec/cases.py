"""Fixed ordinary Local Create fixtures, all confined to an owned directory."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import stat
import struct


def case(name, *, path=b'created.bin', content=b'hello\n', repeat=1, context=1,
         setup='none', poison=False, absolute=True, outcome='success', error_class=None):
    return dict(name=name, path_hex=path.hex(), body_hex=content.hex(), repeat=repeat,
        context=context, setup=setup, poison=poison, absolute=absolute,
        outcome=outcome, error_class=error_class)


CASES = [
    case('empty', content=b''),
    case('ascii'),
    case('unicode_content', content='é\r\n你好🙂\n'.encode()),
    case('nul_content', content=b'a\0b\r\nc'),
    case('single_crlf_normalization', content=b'a\r\r\nb\r\nc\r'),
    case('context_absent', content=b'a\r\nb', context=2),
    case('cache_poisoned', content=b'new\r\nbody', poison=True),
    case('context_absent_poisoned', context=2, poison=True),
    case('cache_limit_exact', content=b'x', repeat=1 << 20),
    case('cache_limit_plus_one', content=b'x', repeat=(1 << 20) + 1),
    case('normalized_cache_limit_exact', content=b'\r\n', repeat=1 << 20),
    case('normalized_cache_limit_plus_one', content=b'\r\n', repeat=(1 << 20) + 1),
    case('three_write_chunks', content=b'x', repeat=(4 << 20) + 37),
    case('nested_parent', path=b'one/two/three/created.bin'),
    case('relative_bare', absolute=False),
    case('relative_nested_parent', path=b'one/two/created.bin', absolute=False),
    case('relative_empty', path=b'', absolute=False, outcome='error', error_class='write'),
    case('relative_dot', path=b'.', absolute=False, outcome='error', error_class='exists'),
    case('trailing_separator', path=b'newdir/', outcome='error', error_class='write'),
    case('existing_file', setup='existing_file', outcome='error', error_class='exists'),
    case('existing_directory', setup='existing_directory', outcome='error', error_class='exists'),
    case('dangling_leaf_symlink', setup='dangling_leaf_symlink', outcome='error', error_class='write'),
    case('existing_leaf_symlink', setup='existing_leaf_symlink', outcome='error', error_class='exists'),
    case('parent_regular_file', path=b'parent/created.bin', setup='parent_regular_file', outcome='error', error_class='write'),
    case('parent_symlink', path=b'alias/created.bin', setup='parent_symlink'),
    case('dangling_parent_symlink', path=b'alias/created.bin', setup='dangling_parent_symlink', outcome='error', error_class='mkdir'),
    case('invalid_utf8_path', path=b'bad-\xff.bin', content=b'utf8-safe body\n'),
    case('nul_leaf_path', path=b'created.bin\0hidden', outcome='error', error_class='write'),
    case('nul_parent_path', path=b'bad\0parent/created.bin', outcome='error', error_class='mkdir'),
    case('backslash_colon_path', path=b'part\\name:1.bin'),
    case('dot_parent_alias', path=b'dir/../created.bin', setup='dot_parent_alias'),
    case('readonly_parent', path=b'protected/created.bin', setup='readonly_parent', outcome='error', error_class='write'),
    case('readonly_missing_parent', path=b'protected/new/created.bin', setup='readonly_parent', outcome='error', error_class='mkdir'),
    case('filename_255', path=b'x' * 255),
    case('filename_256', path=b'x' * 256, outcome='error', error_class='write'),
    case('partial_directory_creation', path=b'newone/' + b'x' * 256 + b'/created.bin', outcome='error', error_class='mkdir'),
    case('leaf_symlink_loop', setup='leaf_symlink_loop', outcome='error', error_class='write'),
    case('parent_symlink_loop', path=b'loop/created.bin', setup='parent_symlink_loop', outcome='error', error_class='mkdir'),
]


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def framed(raw):
    return struct.pack('<Q', len(raw)) + raw


def cache_frame(operation, key=b'', content=b''):
    return struct.pack('<8s5Q', b'HVCACH01', operation, 0, len(key), len(content), 0) + key + content


def setup(spec, work):
    work = Path(work)
    work.mkdir(exist_ok=False)
    path = bytes.fromhex(spec['path_hex'])
    kind = spec['setup']
    if kind == 'existing_file':
        (work / os.fsdecode(path)).write_bytes(b'original file must remain\n')
    elif kind == 'existing_directory':
        (work / os.fsdecode(path)).mkdir()
    elif kind == 'dangling_leaf_symlink':
        os.symlink('absent-target', work / os.fsdecode(path))
    elif kind == 'existing_leaf_symlink':
        (work / 'existing-target').write_bytes(b'original symlink target\n')
        os.symlink('existing-target', work / os.fsdecode(path))
    elif kind == 'parent_regular_file':
        (work / 'parent').write_bytes(b'parent is a regular file\n')
    elif kind == 'parent_symlink':
        (work / 'real').mkdir()
        os.symlink('real', work / 'alias')
    elif kind == 'dangling_parent_symlink':
        os.symlink('absent-parent', work / 'alias')
    elif kind == 'dot_parent_alias':
        (work / 'dir').mkdir()
    elif kind == 'readonly_parent':
        (work / 'protected').mkdir(mode=0o500)
    elif kind == 'leaf_symlink_loop':
        os.symlink(os.fsdecode(path), work / os.fsdecode(path))
    elif kind == 'parent_symlink_loop':
        os.symlink('loop', work / 'loop')
    else:
        assert kind == 'none'
    return request(spec, work)


def request(spec, work):
    work = Path(work).resolve(strict=True)
    suffix = bytes.fromhex(spec['path_hex'])
    path = os.fsencode(work) + b'/' + suffix if spec['absolute'] else suffix
    content = bytes.fromhex(spec['body_hex']) * spec['repeat']
    content.decode('utf-8')
    raw_key = path.decode('utf-8', 'replace').encode()
    if b'\0' in path:
        canonical_key = b'no-success-nul-key'
    else:
        full = path if spec['absolute'] else os.fsencode(work) + b'/' + path
        canonical_key = os.path.realpath(full).decode('utf-8', 'replace').encode()
    seeds = {b'unrelated\0key': b'untouched\r\ntext', b'present-empty': b'',
             raw_key: b'stale raw-path entry', canonical_key: b'stale canonical entry'}
    frames = [cache_frame(0)]
    frames.extend(cache_frame(2, key, value) for key, value in sorted(seeds.items()))
    if spec['poison']:
        frames.append(cache_frame(9))
    create_index = len(frames)
    frames.append(struct.pack('<8s7Q', b'HLCSPQ01', 1, spec['context'], len(path), len(content), 1, 0, 0) + path + content)
    inspection_keys = sorted(seeds)
    frames.extend(cache_frame(1, key) for key in inspection_keys)
    return dict(wire=b''.join(framed(frame) for frame in frames), frames=frames,
        create_index=create_index, inspection_keys=inspection_keys, path=path, content=content,
        canonical_key=canonical_key, seeds=seeds)


def snapshot(work):
    """No symlink traversal: retain all regular-file bytes and all object names."""
    root = os.fsencode(Path(work))
    rows, contents = [], {}

    def walk(folder, prefix):
        for entry in sorted(os.scandir(folder), key=lambda x: x.name):
            relative = prefix + entry.name
            metadata = entry.stat(follow_symlinks=False)
            row = dict(path_hex=relative.hex(), mode=stat.S_IMODE(metadata.st_mode))
            if stat.S_ISREG(metadata.st_mode):
                raw = Path(os.fsdecode(entry.path)).read_bytes()
                row.update(kind='file', content=pin(raw))
                contents[relative.hex()] = raw
            elif stat.S_ISDIR(metadata.st_mode):
                row['kind'] = 'directory'
            elif stat.S_ISLNK(metadata.st_mode):
                row.update(kind='symlink', target_hex=os.readlink(entry.path).hex())
            else:
                raise AssertionError('unexpected fixture object type')
            rows.append(row)
            if row['kind'] == 'directory':
                walk(entry.path, relative + b'/')
    walk(root, b'')
    return rows, contents


def retire(work):
    for current, directories, _ in os.walk(work, followlinks=False):
        os.chmod(current, 0o700)
        for name in directories:
            child = Path(current) / name
            if not child.is_symlink():
                os.chmod(child, 0o700)
    shutil.rmtree(work)


if __name__ == '__main__':
    print(json.dumps(dict(schema='hepta.runtime.local-create-spec-ordinary-cases.v1', cases=CASES,
        qualifier_deadline_seconds=180, process_deadline_seconds=60,
        public_handler_qualified=False, whole_runtime_replaced=False), sort_keys=True, indent=2))
