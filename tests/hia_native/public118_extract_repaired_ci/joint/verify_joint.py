"""Reopen both complete fresh profiles and join only byte-identical 102-owner products."""
from pathlib import Path
import argparse
import copy
import hashlib
import importlib.util
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from check_package import check, pin

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, separators=(",", ":"))).encode()
BINDING = "41a42a6247d8b4bf0ccee11e743bad28285273637b9f824fcbf2f0bf9bad0726"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def doc(path):
    def pairs(rows):
        result = {}
        for key, value in rows:
            assert key not in result
            result[key] = value
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def product(root, manifest_path):
    root = Path(root)
    path = root / manifest_path
    manifest = doc(path)
    assert manifest["schema"] == "hepta.runtime.authority-batch-union-build.v1"
    assert manifest["status"] == "PASS" and manifest["physical_images"] == 102
    assert len(manifest["members"]) == 102
    assert manifest["source_binding"]["manifest_sha256"] == BINDING
    binary = path.parent / manifest["elf"]
    actual = pin(binary)
    assert actual["bytes"] == manifest["elf_bytes"] and actual["sha256"] == manifest["elf_sha256"]
    rows = [{key: row[key] for key in ("name", "source", "source_sha256", "image_sha256", "image_bytes", "buffer_profile")}
        for row in manifest["members"]]
    return dict(source_binding_sha256=BINDING, physical_images=102,
        private=manifest["private_instance_fixture"], members=rows,
        fresh_member_count=sum(row["fresh_compile"] is True for row in manifest["members"]),
        elf={key: actual[key] for key in ("bytes", "sha256")}, elf_path=str(binary),
        manifest=pin(path), extra_table=manifest["extra_table"],
        packed_offsets=manifest["pack"]["image_offsets"], physical_order=manifest["physical_image_members"])


def join_products(authority, batch):
    assert set(authority) == set(batch) == {"public", "private"}
    for kind in ("public", "private"):
        left, right = authority[kind], batch[kind]
        assert left["source_binding_sha256"] == right["source_binding_sha256"] == BINDING
        assert type(left["physical_images"]) is type(right["physical_images"]) is int
        assert left["physical_images"] == right["physical_images"] == 102
        assert left["private"] is right["private"] is (kind == "private")
        assert left["fresh_member_count"] == right["fresh_member_count"] == (102 if kind == "public" else 0)
        assert len(left["members"]) == len(right["members"]) == 102
        assert len({row["name"] for row in left["members"]}) == 102
        for key in ("members", "elf", "extra_table", "packed_offsets", "physical_order"):
            assert left[key] == right[key], (kind, key)
        assert len(left["extra_table"]) == 57 and left["extra_table"][47:53] == [
            "batch_gateway", "batch_params", "batch_call", "batch_adapter", "batch_input", None]
    assert authority["public"]["members"] == authority["private"]["members"]
    return dict(physical_images=102, independent_fresh_public_compiles=204,
        reverified_private_members=204, same_complete_public_executable=True,
        same_complete_private_executable=True, graph_binding_sha256=BINDING,
        public_elf=authority["public"]["elf"], private_elf=authority["private"]["elf"],
        corresponding_members_byte_identical=True)


def join_controls(authority, batch):
    changes = (
        ("graph-binding", lambda x: x["public"].update(source_binding_sha256="0" * 64)),
        ("physical-count", lambda x: x["public"].update(physical_images=101)),
        ("missing-member", lambda x: x["public"]["members"].pop()),
        ("duplicate-member", lambda x: x["public"]["members"].__setitem__(1, copy.deepcopy(x["public"]["members"][0]))),
        ("source-identity", lambda x: x["public"]["members"][0].update(source_sha256="0" * 64)),
        ("image-identity", lambda x: x["public"]["members"][0].update(image_sha256="0" * 64)),
        ("reused-public", lambda x: x["public"].update(fresh_member_count=101)),
        ("fresh-private", lambda x: x["private"].update(fresh_member_count=1)),
        ("extra-slot", lambda x: x["public"]["extra_table"].__setitem__(47, None)),
        ("public-bytes", lambda x: x["public"]["elf"].update(sha256="0" * 64)),
        ("private-bytes", lambda x: x["private"]["elf"].update(bytes=x["private"]["elf"]["bytes"] + 1)),
        ("packed-layout", lambda x: x["public"]["packed_offsets"].__setitem__(0, x["public"]["packed_offsets"][0] + 16)),
    )
    accepted = join_products(authority, batch)
    rejected = []
    for label, change in changes:
        value = copy.deepcopy(batch)
        change(value)
        try:
            join_products(authority, value)
        except (AssertionError, ValueError, KeyError):
            rejected.append(label)
        else:
            raise AssertionError("joint product mutation was admitted: " + label)
    assert join_products(authority, batch) == accepted
    return dict(admissions=2, refusals=len(rejected), rejected=rejected,
        complete_component_readers_ran_before_controls=True, native_or_rust_executions=0)


def preload_input_definitions(source, batch, batch_run=None):
    """Derive all fixed inputs before the guard; never perform fixture actions."""
    capture = batch.read_public.capture
    original = capture.case_rows
    retained = {}
    shapes = []
    for domain, count in batch.DOMAINS.items():
        if batch_run is None:
            fixture = source / "readonly-input-definition" / domain
        else:
            native = doc(batch_run / "public" / domain / "native/result.json")
            reference = doc(batch_run / "public" / domain / "original/result.json")
            assert type(native["fixture"]) is str and native["fixture"] == reference["fixture"]
            fixture = Path(native["fixture"])
            assert fixture.is_absolute()
        rows = original(domain, fixture)
        assert len(rows) == count
        key = (domain, fixture)
        assert key not in retained
        retained[key] = rows
        shapes.append(dict(domain=domain, fixture=str(fixture), rows=count))
    def input_rows(domain, fixture):
        key = (domain, Path(fixture))
        assert key in retained, "unadmitted complete input shape"
        # Each reader gets independent dictionaries, exactly as regeneration
        # would return. The original corpus functions and bytes stay unchanged.
        return copy.deepcopy(retained[key])
    capture.case_rows = input_rows
    batch._joint_input_shapes = shapes


def prepare(source, batch_run=None):
    source = Path(source)
    sys.path.insert(0, str(source / "authority-runner"))
    authority = load("_joint102_authority_reader", source / "authority-runner/verify_complete.py")
    prepared = authority.preload(source / "authority")
    # Authority retains its own check_source module. The Batch recipe uses its
    # distinct source_check and receipt_support names from its admitted folder.
    sys.path.insert(0, str(source / "batch"))
    batch = load("_joint102_batch_recipe", source / "batch/run_recipe.py")
    batch.read_builds.load_builder(source / "batch/native-source")
    # This module is imported by the complete Batch reader. Admit its exact
    # definitions before the guard; do not allow a later implicit pyc probe.
    controls = importlib.import_module("check_evidence")
    assert Path(controls.__file__).resolve(strict=True) == (source / "batch/check_evidence.py").resolve(strict=True)
    preload_input_definitions(source, batch, batch_run)
    entry = load("_joint102_entry_reader", source / "entry102.py")
    return authority, batch, entry, prepared["guard"]


def check_imports(source, prepared):
    """Retain all 11 guard refusals while checking repeat imports and exact authors."""
    batch = prepared[1]
    def operation():
        for _ in range(2):
            builder = batch.read_builds.load_builder(source / "batch/native-source")
            assert len(builder.MEMBERS) == 102
            assert builder.source_check(source / "batch/native-source")["manifest_sha256"] == BINDING
        reference = source / "batch/original-reference"
        author = batch.read_builds.source_module("batch_public_original_author",
            reference / "authoring/author_public_reference.py")
        generated, proof = author.compose(reference / "baseline", reference / "core")
        assert proof == doc(reference / "project/SOURCE.json")
        for name, raw in generated.items():
            assert (reference / "project" / name).read_bytes() == raw
        assert Path(importlib.import_module("check_evidence").__file__).resolve(strict=True) == (
            source / "batch/check_evidence.py").resolve(strict=True)
        counts = {}
        for shape in batch._joint_input_shapes:
            domain, fixture = shape["domain"], Path(shape["fixture"])
            rows = batch.read_public.capture.case_rows(domain, fixture)
            again = batch.read_public.capture.case_rows(domain, fixture)
            assert rows == again and rows is not again and len(rows) == shape["rows"] == batch.DOMAINS[domain]
            saved_name = rows[0]["name"]
            rows[0]["name"] = "independent-reader-copy-control"
            assert again[0]["name"] == saved_name
            assert batch.read_public.capture.case_rows(domain, fixture)[0]["name"] == saved_name
            counts[domain] = len(again)
        assert counts == batch.DOMAINS and sum(counts.values()) == 1777
        return dict(repeated_builder_imports=2, physical_members=102,
            exact_original_source_files=len(generated), actual_builder_executions=0,
            input_definitions=counts, independent_input_copies=True,
            native_or_rust_executions=0)
    report = prepared[3].guarded(operation, roots=[source], foreign_path="/dev/null")
    assert len(report["probes"]) == 11 and report["before"] == report["after"]
    return dict(status="EXACT_JOINT_READER_IMPORTS_PASS", evidence=report["evidence"],
        readonly=dict(probes=report["probes"], files=len(report["before"]),
            complete_before_after_equal=True, native_or_rust_executions=0))


def source_copies(source, authority_archive, batch_run):
    profile = doc(source / "joint-source.json")
    assert pin(authority_archive / "joint-source/joint-source.json") == pin(source / "joint-source.json")
    assert check(authority_archive / "joint-source") == check(source)
    copies = ((authority_archive / "recipe-source", "authority/"),
        (authority_archive / "runner-source", "authority-runner/"),
        (batch_run / "source", "batch/"))
    counts = {}
    for folder, prefix in copies:
        expected = {name.removeprefix(prefix): row for name, row in profile["files"].items()
            if name.startswith(prefix)}
        actual = {}
        for path in folder.rglob("*"):
            assert not path.is_symlink()
            if path.is_dir():
                continue
            name = path.relative_to(folder).as_posix()
            assert name in expected
            actual[name] = pin(path)
        assert actual == expected
        counts[prefix.removesuffix("/")] = len(actual)
    return counts


def verify(source, authority_archive, batch_run, prepared):
    source = Path(source); authority_archive = Path(authority_archive); batch_run = Path(batch_run)
    source_closure = check(source)
    retained_sources = source_copies(source, authority_archive, batch_run)
    authority_reader, batch_reader, entry_reader, _ = prepared
    auth_run = authority_archive / "run"
    authority = authority_reader.verify(source / "authority", auth_run, require_fresh=True, require_recipe_pass=True)
    batch = batch_reader.verify(batch_run)
    entry = entry_reader.verify(source / "installed", source / "authority", auth_run, auth_run / "main-default-entry")
    assert authority["status"] == "READONLY_PUBLIC102_AUTHORITY259_HANDSHAKE324_PUBLIC90_TRANSPORT24_PASS"
    assert authority["current_owner_v4"]["evidence"]["original"]["rows"] == 243
    assert authority["current_public_owner"]["rows"] == 16
    assert batch["status"] == "PASS" and batch["fresh_original_build"] is True
    assert batch["actual_private_rows_per_provider"] == 1777 and batch["actual_stdio_exchanges_per_provider"] == 28
    assert batch["actual_runtime_root_processes"] == 12
    assert entry["status"] == "ACTUAL_ISOLATED_DEFAULT_ENTRY_EQUALS_QUALIFIED_PUBLIC102"
    aproducts = {"public": product(auth_run, "public/build/public-authority-batch/manifest.json"),
        "private": product(auth_run, "private/build/authority-private/manifest.json")}
    bproducts = {"public": product(batch_run, "native/public-build/public102/manifest.json"),
        "private": product(batch_run, "native/private-build/private102/manifest.json")}
    joined = join_products(aproducts, bproducts)
    for kind in ("public", "private"):
        assert Path(aproducts[kind]["elf_path"]).read_bytes() == Path(bproducts[kind]["elf_path"]).read_bytes()
    # The Batch compiler reader also checks stdout/receipt/build identity and
    # every unused output byte for the separately compiled Authority lane.
    public_manifest = doc(auth_run / "public/build/public-authority-batch/manifest.json")
    module_map = doc(auth_run / "module-map.json")["modules"]
    for member in public_manifest["members"]:
        relative = Path(module_map[member["manifest"]])
        assert not relative.is_absolute() and ".." not in relative.parts
        batch_reader.read_builds.compiler((auth_run / relative).parent,
            (source / "authority/source" / member["source"]).read_bytes())
    controls = join_controls(aproducts, bproducts)
    return dict(schema="hepta.runtime.authority102-complete-joint-readonly.v1",
        status="READONLY_AUTHORITY102_AND_COMPLETE_BATCH_PASS", source=source_closure,
        exact_retained_source_copies=retained_sources,
        preloaded_input_shapes=batch_reader._joint_input_shapes,
        complete_inputs_rechecked_against_actual_capture_under_guard=True,
        authority_evidence_sha256=SHA(ENCODE(authority)), batch_evidence_sha256=SHA(ENCODE(batch)),
        entry_evidence_sha256=SHA(ENCODE(entry)), products=joined, join_controls=controls,
        authority_domains=dict(original_owner=243, current_public_owner=16, handshake_sessions=54,
            handshake_responses=324, public_responses=90, transport_cases=24, codec_eof_reference_cases=4,
            current_profile_native_groups=23, historical_profile_groups=7),
        batch_domains=dict(private_rows_per_provider=1777, stdio_rows_per_provider=28,
            typed_legacy=417, typed_modern=417, filesystem=926, session=17,
            evidence_refusals=21, evidence_admissions=2),
        both_profiles_fresh_original_build=True, independent_fresh_graphs=True,
        complete_component_readers_reread=True, reader_process_launches=0,
        joint_ordinary_profiles_qualified=True, shared_main_modified=False,
        catalog_batch_advertised=False, advertised_catalog_tools=9,
        full_sdk_qualified=False, full_async_cancellation_qualified=False,
        remote_batch_qualified=False, production_activated=False, whole_runtime_replaced=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    for name in ("authority", "batch"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--imports-only", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    assert pin(source / "joint-source.json")["sha256"] == args.expected_source_sha256
    check(source)
    if args.imports_only:
        assert args.authority is None and args.batch is None
        prepared = prepare(source)
        print(json.dumps(check_imports(source, prepared), sort_keys=True))
    else:
        assert args.authority is not None and args.batch is not None
        authority = args.authority.resolve(strict=True)
        batch = args.batch.resolve(strict=True)
        prepared = prepare(source, batch_run=batch)
        guarded = prepared[3].guarded(lambda: verify(source, authority, batch, prepared),
            roots=[source, authority, batch], foreign_path="/dev/null")
        assert len(guarded["probes"]) == 11 and guarded["before"] == guarded["after"]
        print(json.dumps(dict(status=guarded["evidence"]["status"], evidence=guarded["evidence"],
            readonly=dict(probes=guarded["probes"], files=len(guarded["before"]),
                complete_before_after_equal=True, native_or_rust_executions=0)), sort_keys=True))
