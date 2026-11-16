"""Fresh original build/replay custody. This module never runs Rust on import."""
from pathlib import Path
import hashlib
import io
import json
import os
import signal
import subprocess
import tarfile
import time
import tomllib

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+"\n")


def environment(inherited, rust_bin=None, target=None):
    env = dict(inherited)
    removed = []
    forbidden = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
                 "RUSTC", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP",
                 "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_INCREMENTAL", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}
    for name in list(env):
        if name in forbidden or (name.startswith("CARGO_") and any(part in name for part in ("RUSTFLAGS", "RUSTC", "RUSTDOC", "PROFILE_", "LINKER"))):
            removed.append(name); env.pop(name)
    env.update(PYTHONDONTWRITEBYTECODE="1")
    if rust_bin is not None:
        rust_bin = Path(rust_bin).resolve(strict=True)
        env.update(PATH=str(rust_bin)+os.pathsep+env.get("PATH", ""), RUSTC=str(rust_bin/"rustc"),
            RUSTDOC=str(rust_bin/"rustdoc"), RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="",
            CARGO_BUILD_RUSTC=str(rust_bin/"rustc"), CARGO_BUILD_RUSTC_WRAPPER="", CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER="",
            CARGO_ENCODED_RUSTFLAGS="", CARGO_ENCODED_RUSTDOCFLAGS="", CARGO_BUILD_RUSTFLAGS="",
            CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu")
        if target is not None:
            env["CARGO_TARGET_DIR"] = str(Path(target).absolute())
    controlled = {"RUSTC", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC",
                  "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_ENCODED_RUSTFLAGS",
                  "CARGO_ENCODED_RUSTDOCFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"}
    binding = {name: env[name] for name in sorted(controlled) if name in env}
    return env, dict(removed_keys=sorted(removed), explicit_reference_environment=binding,
        cargo_encoded_rustflags_override=env.get("CARGO_ENCODED_RUSTFLAGS"),
        inherited_environment_values_not_logged=True)


class Recorder:
    def __init__(self, root, directory, env=None):
        self.root = Path(root).resolve(strict=True)
        self.directory = Path(directory).absolute()
        self.directory.mkdir(parents=True, exist_ok=False)
        self.env = dict(os.environ) if env is None else dict(env)
        self.records = []

    def run(self, name, argv, *, cwd=None, stdin=None, timeout=180):
        assert name.replace("-", "").isalnum() and name not in {r["name"] for r in self.records}
        argv = [str(x) for x in argv]
        cwd = self.root if cwd is None else Path(cwd).resolve(strict=True)
        started = time.monotonic()
        process = None
        out, error, code, timed_out, completed = b"", b"", None, False, False
        exception = None
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=self.env, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            pgid = os.getpgid(process.pid)
            out, error = process.communicate(input=stdin, timeout=timeout)
            code = process.returncode
            completed = True
        except subprocess.TimeoutExpired as failure:
            timed_out = True
            exception = failure
        except BaseException as failure:
            exception = failure
        finally:
            # Reaping is independent of all evidence writes, including ENOSPC.
            if process is not None and not completed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                finally:
                    out, error = process.communicate()
                    code = process.returncode
            if process is not None:
                process.wait()
            row = dict(name=name, argv=argv, cwd=str(cwd), pid=process.pid if process else None,
                parent_pid=os.getpid(), pgid=pgid if process is not None and "pgid" in locals() else None,
                exit_code=code, timed_out=timed_out, completed=completed, timeout_seconds=timeout,
                elapsed_seconds=time.monotonic()-started,
                stdin=None if stdin is None else dict(file=name+".stdin", bytes=len(stdin), sha256=SHA(stdin)),
                stdout=dict(file=name+".stdout", bytes=len(out), sha256=SHA(out)),
                stderr=dict(file=name+".stderr", bytes=len(error), sha256=SHA(error)))
            for suffix, raw in (("stdout",out),("stderr",error)):
                (self.directory/(name+"."+suffix)).write_bytes(raw)
            if stdin is not None:
                (self.directory/(name+".stdin")).write_bytes(stdin)
            self.records.append(row)
            put(self.directory/"processes.json",self.records)
        if exception is not None:
            raise exception
        if code != 0:
            raise RuntimeError("recorded command failed: "+name)
        return out, row


def build_reference(source_root, target_root, output, rust_bin):
    """Call only from the explicit original phase on CI or authorized ai395."""
    if os.environ.get("GITHUB_ACTIONS") != "true" and os.environ.get("HIA_AUTHORIZED_REFERENCE_HOST") != "ai395":
        raise RuntimeError("fresh Rust reference requires CI or the explicitly authorized ai395 host")
    source_root = Path(source_root).resolve(strict=True)
    target_root = Path(target_root).resolve(strict=True)
    output = Path(output).absolute()
    output.mkdir(parents=True,exist_ok=False)
    rust_bin = Path(rust_bin).resolve(strict=True)
    project = output/"reference-project"; project.mkdir()
    reference = source_root/"reference"
    from extract_reference import TARGET_COMMIT, TARGET_SHA, LOCK_SHA, extract, CARGO
    original=(target_root/"src/mcp/runtime/caller_scope.rs").read_bytes()
    lock=(target_root/"Cargo.lock").read_bytes()
    assert SHA(original)==TARGET_SHA and SHA(lock)==LOCK_SHA
    generated,extracted=extract(original)
    assert generated==(reference/"main.rs").read_bytes() and CARGO==(reference/"Cargo.toml").read_bytes()
    for name in ("Cargo.toml","Cargo.lock","src/mcp/runtime/caller_scope.rs"):
        assert (target_root/name).read_bytes()==(reference/"target"/name).read_bytes()
    for name,raw in (("main.rs",generated),("Cargo.toml",CARGO),("Cargo.lock",lock)):
        (project/name).write_bytes(raw)
    target=output/"cargo-target"
    assert not target.exists()
    env,binding=environment(os.environ,rust_bin,target)
    rec=Recorder(source_root,output/"processes",env)
    head,_=rec.run("reference-target-head",["git","-C",target_root,"rev-parse","HEAD"],timeout=30)
    assert head.strip().decode()==TARGET_COMMIT
    version,_=rec.run("reference-rustc-version",[rust_bin/"rustc","--version","--verbose"],timeout=60)
    assert version.decode().splitlines()[0].startswith("rustc 1.95.0 ")
    cargo_version,_=rec.run("reference-cargo-version",[rust_bin/"cargo","--version","--verbose"],timeout=60)
    assert cargo_version.decode().splitlines()[0].startswith("cargo 1.95.0 ")
    metadata,_=rec.run("reference-metadata",[rust_bin/"cargo","metadata","--offline","--format-version","1"],cwd=project,timeout=180)
    metadata=json.loads(metadata)
    derived=(project/"Cargo.lock").read_bytes()
    originals={(p["name"],p["version"],p.get("source")):p.get("checksum") for p in tomllib.loads(lock.decode())["package"] if p.get("source")}
    retained=[]
    for package in tomllib.loads(derived.decode())["package"]:
        if not package.get("source"):
            assert package["name"]=="scope-annotation-original"
            continue
        key=(package["name"],package["version"],package["source"])
        assert originals.get(key)==package["checksum"],key
        retained.append({k:package[k]for k in ("name","version","source","checksum")})
    registry=[];sdk_verified=False
    archives=output/"registry";archives.mkdir()
    for package in metadata["packages"]:
        if not package.get("source"):
            continue
        key=(package["name"],package["version"],package["source"])
        expected=originals[key]
        crate=Path(package["manifest_path"]).parent
        archive_path=crate.parent.parent.parent/"cache"/crate.parent.name/(crate.name+".crate")
        raw=archive_path.read_bytes()
        assert SHA(raw)==expected
        archive_name=crate.name+".crate"
        assert Path(archive_name).name==archive_name and archive_name not in (".","..")
        (archives/archive_name).write_bytes(raw)
        files={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz")as archive:
            for member in archive.getmembers():
                parts=Path(member.name).parts
                assert parts and parts[0]==crate.name and ".."not in parts and not Path(member.name).is_absolute()
                if member.isdir():continue
                assert member.isfile()
                name=str(Path(*parts[1:]));content=archive.extractfile(member).read()
                assert (crate/name).read_bytes()==content
                files[name]=SHA(content)
        if package["name"]=="rmcp":
            assert package["version"]=="3.9.0"
            for name in ("src/model.rs","src/model/content.rs"):
                assert (crate/name).read_bytes()==(reference/"sdk"/name).read_bytes()
            sdk_verified=True
        registry.append(dict(name=package["name"],version=package["version"],source=package["source"],
            checksum=expected,archive_sha256=SHA(raw),archive_file="registry/"+archive_name,
            source_files=files,files_verified=len(files)))
    assert sdk_verified and not target.exists()
    subset=dict(schema="hepta.scope-annotation.target-lock-subset.v1",target_lock_sha256=SHA(lock),fixture_lock_sha256=SHA(derived),
        retained_registry_packages=retained,registry_source_verification=registry,all_retained_exactly_match_target=True,
        actual_sdk_constructor_dependencies_match=True,offline_resolution=True)
    put(output/"lock-subset.json",subset)
    put(output/"reference-environment.json",binding)
    rec.run("reference-build",[rust_bin/"cargo","build","--locked","--offline","--target","x86_64-unknown-linux-gnu",
        "--bin","scope-annotation-original"],cwd=project,timeout=900)
    assert (project/"Cargo.lock").read_bytes()==derived
    binary=target/"x86_64-unknown-linux-gnu/debug/scope-annotation-original"
    retained_binary=output/"scope-annotation-original"
    retained_binary.write_bytes(binary.read_bytes());retained_binary.chmod(0o700)
    receipt=dict(schema="hepta.scope-annotation.actual-original-build.v1",target_commit=TARGET_COMMIT,target_sha256=TARGET_SHA,
        target_lock_sha256=SHA(lock),fixture_lock_sha256=SHA(derived),source_sha256=SHA(generated),
        cargo_sha256=SHA(CARGO),binary_file=retained_binary.name,binary_sha256=SHA(retained_binary.read_bytes()),
        binary_bytes=retained_binary.stat().st_size,rust_version=version.decode(),cargo_version=cargo_version.decode(),
        rustc_sha256=SHA((rust_bin/"rustc").read_bytes()),cargo_binary_sha256=SHA((rust_bin/"cargo").read_bytes()),
        profile="exact target [profile.dev]",extracted=extracted,environment=binding,
        actual_target_sdk_built=True,actual_target_sdk_executed=False,fresh_target_dir=True,
        process_count=len(rec.records),production_activated=False,whole_runtime_replaced=False)
    put(output/"build.json",receipt)
    return retained_binary,receipt,rec
