"""Compose exact Authority91 and qualified Batch94 sources without editing either input."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys

sys.dont_write_bytecode = True
BASE_COMMIT = "2f3909ad0bca5689fb4ae8a055212c7157bd4257"
BASE_BINDING = "f4d8d1d4410ee7299c6265f6ac0e0994bd8ba324d615b13771281d716e6e5db2"
BATCH_BINDING = None  # Filled from the frozen v7 profile by an exact argument.
BATCH_PROFILE = "a0c4d534489f6481c0b16ac736e8b64664fb33979168554c90eb7508afc895c9"
BATCH_COMMIT = "a3778ecb4fb5b5e8700e7cd213de2203e340aacc"
BATCH_MEMBERS = [
    ("batch_body", "batch_write", "batch-write.v1"),
    ("batch_lock", "file_lock_service", "batch-plan.v1"),
    ("batch_plan", "batch_plan", "batch-plan.v1"),
    ("batch_verify", "line_verify", "batch-plan.v1"),
    ("batch_apply", "batch_apply", "batch-plan.v1"),
    ("batch_render", "batch_render", "batch-write.v1"),
    ("batch_input", "batch_plan_input", "history.v1"),
    ("batch_params", "batch_params", "history.v1"),
    ("batch_gateway", "batch_gateway", "history.v1"),
    ("batch_call", "batch_call", "history.v1"),
    ("batch_adapter", "batch_body_adapter", "history.v1"),
]
EDITS = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw),
        "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def exact(text, before, after, label):
    if text.count(before) != 1:
        raise ValueError("expected exactly one frozen edit anchor: " + label)
    EDITS.append({"label": label, "before_sha256": sha(before.encode()),
        "after_sha256": sha(after.encode()), "before": before, "after": after})
    return text.replace(before, after)


def assignment(text, name):
    rows = [n for n in ast.parse(text).body if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    assert len(rows) == 1
    return rows[0], ast.literal_eval(rows[0].value)


def replace_assignment(text, name, value):
    node, _ = assignment(text, name)
    return exact(text, ast.get_source_segment(text, node), name + " = " + repr(value), "assignment:" + name)


def merge_builder(base):
    text = base
    _, boundaries = assignment(text, "BOUNDARIES")
    for name in ["scripts/runtime_batch_body_bridge.S", "scripts/runtime_batch_cache_bridge.S",
                 "scripts/runtime_batch_install.S", "scripts/local_batch_body_callable.S"]:
        assert name not in boundaries
    text = replace_assignment(text, "BOUNDARIES", ["scripts/runtime_batch_body_bridge.S",
        "scripts/runtime_batch_cache_bridge.S", "scripts/runtime_batch_install.S",
        "scripts/local_batch_body_callable.S", *boundaries])
    _, members = assignment(text, "MEMBERS")
    assert len(members) == 91 and list(members)[-5:][0][0] == "rf_owner"
    assert not set(x[0] for x in members) & set(x[0] for x in BATCH_MEMBERS)
    text = replace_assignment(text, "MEMBERS", [*members[:-5], *BATCH_MEMBERS, *members[-5:]])
    _, extra = assignment(text, "EXTRA")
    assert len(extra) == 57 and extra[47:53] == [None] * 6
    extra[47:53] = ["batch_gateway", "batch_params", "batch_call", "batch_adapter", "batch_input", None]
    text = replace_assignment(text, "EXTRA", extra)
    text = exact(text, "len(MEMBERS) != 91", "len(MEMBERS) != 102", "102 unique physical owners")
    needle = "authority_images=[images[n] for n in ('authority','authority_record','authority_kdf','rf_sha','authority_aead','authority_nonce','authority_scope','authority_entropy','authority_loader')])"
    text = exact(text, needle, needle[:-1] + ",\n                                    batch_images=[images[n] for n in ('batch_body','batch_lock','key','tb_history','tb_atomic','cache','lc_read','tb_lock','tb_edit','batch_plan','endpoint','batch_verify','batch_apply','batch_render')])", "pack both capability tables")
    text = exact(text, "'schema': 'hepta.runtime.public-nine-build.v1'", "'schema': 'hepta.runtime.authority-batch-union-build.v1'", "union manifest schema")
    anchor = "              'authority_slot': 56, 'authority_context_offset': 432,\n"
    text = exact(text, anchor, anchor + "              'batch_private_slots': [47,48,49,50,51,52],\n              'batch_public_route_registered': True, 'batch_public_route_qualified': False,\n              'batch_gateway_caller_qualified': False, 'batch_callable_scope_borrow_maximum': 1048672,\n              'advertised_catalog_tools': 9, 'candidate_extra_registered_tools': ['batch_edit'],\n", "union qualification remains pending")
    text = exact(text, "'target_text_constructor_source_sha256': '3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d'", "'target_text_constructor_source_sha256': '785315acd60821313e4683df67e0b83c59c572d798ad3849efaa3108a9e36d58'", "final shared constructor pin")
    ast.parse(text)
    return text


def merge_packer(base):
    text = exact(base, "*,create_images,body_images,authority_images):", "*,create_images,body_images,authority_images,batch_images):", "packer keeps both image-table ABIs")
    anchor = "    for slot,image in enumerate(authority_images):patches.append((1,256+symbols['runtime_authority_images']+slot*8,indices[image]))\n"
    text = exact(text, anchor, anchor + "    if len(batch_images)!=14:raise ValueError('private Batch table differs')\n    for slot,image in enumerate(batch_images):patches.append((1,256+symbols['runtime_batch_body_images']+slot*8,indices[image]))\n", "packer patches actual Batch images")
    ast.parse(text)
    return text


def merge_default(base):
    text = exact(base, "91-image", "102-image", "default graph description")
    text = exact(text, "hepta.runtime.public91-authority.build.v1", "hepta.runtime.public102-authority-batch.build.v1", "default graph schema")
    text = exact(text, "assert len(MEMBERS)==91 and len(EXTRA)==57", "assert len(MEMBERS)==102 and len(EXTRA)==57", "default exact counts")
    text = exact(text, "assert EXTRA[47:53]==[None]*6 and EXTRA[53:]==", "assert EXTRA[47:53]==['batch_gateway','batch_params','batch_call','batch_adapter','batch_input',None] and EXTRA[53:]==", "default Batch table")
    text = exact(text, 'name="public-authority"', 'name="public-authority-batch"', "default output name")
    text = exact(text, 'len(md["members"])==91', 'len(md["members"])==102', "default actual manifest count")
    text = exact(text, "assert fresh==91-len(reuse)", "assert fresh==102-len(reuse)", "default exact compile accounting")
    text = exact(text, 'physical_images=91,manifest=str(manifest)', 'physical_images=102,manifest=str(manifest)', "default reported count")
    ast.parse(text)
    return text


def section(text, start, end):
    assert text.count(start) == text.count(end) == 1
    return text[text.index(start):text.index(end)]


def merge_engine(base, batch):
    text = exact(base,
        '57 rows at engine+8192; slots47-52 are reserved for Batch.',
        '57 rows at engine+8192; slots47-52 bind Batch while56 remains Authority.',
        'keep engine dimensions and bind only reserved slots')
    text = exact(text, 'runtime_grow_destroy_fs_admitted:\n',
        'runtime_grow_destroy_fs_admitted:\n    cmp qword ptr [r15 + 416], 0\n    jne runtime_grow_destroy_invalid\n',
        'refuse engine destruction while Batch retains its context')
    text = exact(text, '    cmp ebp, 56\n    je runtime_grow_authority_dispatch\n',
        '    cmp ebp, 52\n    je runtime_grow_batch_body_dispatch\n    cmp ebp, 56\n    je runtime_grow_authority_dispatch\n',
        'keep Authority dispatch and add Batch capability')
    installed = section(batch, '    cmp ebp, 49\n    jne runtime_grow_batch_installed\n', '    cmp ebp, 11\n    jne runtime_grow_enter_native\n')
    text = exact(text, 'runtime_grow_text_installed:\n', 'runtime_grow_text_installed:\n' + installed,
        'install caller borrowed context exactly once')
    text = exact(text, 'runtime_grow_classify_result:\n',
        'runtime_grow_classify_result:\n    cmp ebp, 47\n    je runtime_grow_text_gateway_result\n    cmp ebp, 49\n    je runtime_grow_text_gateway_result\n    cmp ebp, 50\n    je runtime_grow_batch_adapter_result\n',
        'Batch gateway caller and adapter result paths')
    text = exact(text, '    cmp ebp, 38\n    je runtime_grow_text_params_result\n',
        '    cmp ebp, 48\n    je runtime_grow_batch_params_result\n    cmp ebp, 51\n    je runtime_grow_batch_input_result\n    cmp ebp, 38\n    je runtime_grow_text_params_result\n',
        'Batch params and Planner input result paths')
    adapter = section(batch, '/* The Batch adapter returns the complete HBBSPR01 extent,', 'runtime_grow_filesystem_params_result:\n')
    text = exact(text, 'runtime_grow_filesystem_params_result:\n', adapter + 'runtime_grow_filesystem_params_result:\n',
        'complete Batch adapter extent validation')
    params = section(batch, 'runtime_grow_batch_params_result:\n', 'runtime_grow_text_params_result:\n')
    text = exact(text, 'runtime_grow_text_params_result:\n', params + 'runtime_grow_text_params_result:\n',
        'typed Batch header has its own exact magic')
    anchor = '    mov rdx, 0x3230525250455448 /* HTEPRR02 */\n    cmp [r13], rdx\n    jne runtime_grow_bad\n'
    text = exact(text, anchor, anchor + 'runtime_grow_typed_params_fields:\n', 'share unchanged complete typed extent checks')
    input_result = section(batch, 'runtime_grow_batch_input_result:\n', 'runtime_grow_params_result:\n')
    text = exact(text, 'runtime_grow_params_result:\n', input_result + 'runtime_grow_params_result:\n',
        'exact Planner input status and growth ABI')
    text = exact(text, 'runtime_grow_authority_dispatch:\n',
        'runtime_grow_batch_body_dispatch:\n    call runtime_batch_body_owned\n    jmp runtime_grow_done\n\nruntime_grow_authority_dispatch:\n',
        'distinct mechanical Body and Authority callbacks')
    parents = '    cmp edi, 47\n    je runtime_grow_target_batch_gateway\n    cmp edi, 49\n    je runtime_grow_target_batch_caller\n    cmp edi, 50\n    je runtime_grow_target_batch_body\n'
    text = exact(text, 'runtime_grow_target:\n', 'runtime_grow_target:\n' + parents, 'fixed owned Batch parents')
    targets = section(batch, 'runtime_grow_target_batch_gateway:\n', 'runtime_grow_target_local_body:\n')
    text = exact(text, 'runtime_grow_target_local_body:\n', targets + 'runtime_grow_target_local_body:\n',
        'bounded child selectors for all three Batch controllers')
    text = exact(text, 'runtime_grow_target_frontend:\n    cmp rsi, 12\n',
        'runtime_grow_target_frontend:\n    cmp rsi, 13\n', 'retain Authority child12 and append child13')
    text = exact(text,
        '    .zero 128 /* 41 empty; SDK42-45, constructor46, Batch47-52, shutdown53, get_info54, connection55, authority56. */',
        '    .zero 48 /* 41..46: no controller action. */\n    .ascii "HBAWGA01" /* 47 */\n    .quad 0 /* 48 typed params */\n    .ascii "HBECCA01" /* 49 caller */\n    .ascii "HBBACA01" /* 50 adapter */\n    .zero 48 /* 51..56: no controller action; Authority is a capability. */',
        'exact action-table extent remains57 words')
    text = exact(text, '    .byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37, 46, 54, 56\n',
        '    .byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37, 46, 54, 56, 47\n',
        'all old frontend child targets preserved')
    suffix = batch[batch.index('\nruntime_grow_batch_gateway_targets:'):]
    assert suffix.endswith('    .byte 51, 52\n') and 'runtime_authority' not in suffix
    return text + suffix


def merge_fixture(base):
    text = exact(base,
        '    cmp qword ptr [r12 + 80], 41\n    ja fs_fixture_failure\nfs_fixture_authority_selector:\n',
        '    cmp qword ptr [r12 + 80], 47\n    jb fs_fixture_retained_selector\n    cmp qword ptr [r12 + 80], 52\n    jbe fs_fixture_authority_selector\nfs_fixture_retained_selector:\n    cmp qword ptr [r12 + 80], 41\n    ja fs_fixture_failure\nfs_fixture_authority_selector:\n',
        'add only47..52 without weakening old reserved-selector rejection')
    return exact(text, 'fs_fixture_finish_session:\n    mov r15, [r12 + r13 * 8]\n',
        'fs_fixture_finish_session:\n    mov r15, [r12 + r13 * 8]\n    call runtime_batch_body_release\n    test rax, rax\n    jnz fs_fixture_failure\n',
        'release each session Batch context before shared hub teardown')


def merge_transport(base):
    anchor = '    call runtime_text_body_release\n    test rax, rax\n    jnz public_span_fail\n'
    return exact(base, anchor, '    call runtime_batch_body_release\n    test rax, rax\n    jnz public_span_fail\n' + anchor,
        'real EOF releases Batch after target shutdown and before Text hub destruction')


def create(repo, batch_root, rebind, hepta, output):
    assert not output.exists()

    def git_file(name, required=True):
        result = subprocess.run(["git", "show", BASE_COMMIT + ":" + name], cwd=repo,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            if required:
                raise ValueError("missing exact baseline file: " + name)
            return None
        return result.stdout

    profile_raw = (batch_root / "source-profile.json").read_bytes()
    assert sha(profile_raw) == BATCH_PROFILE
    profile = json.loads(profile_raw)
    for name, expected in profile["files"].items():
        path = batch_root / name
        assert path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1
        data = path.read_bytes()
        assert {"bytes": len(data), "sha256": sha(data)} == expected, name
    batch = batch_root / "native-source"
    base_raw = git_file("native/runtime_mcp_sources.json")
    assert sha(base_raw) == BASE_BINDING
    base = json.loads(base_raw)
    batch_raw = (batch / "native/runtime_mcp_sources.json").read_bytes()
    selected = json.loads(batch_raw)
    originals = {}
    for name, expected in base["sources"].items():
        data = git_file(name)
        assert {"bytes": len(data), "sha256": sha(data)} == expected, name
        originals[name] = data
    files = dict(originals)
    generated = {"native/runtime_mcp.hepta", "native/runtime_mcp_composition.json",
        "native/runtime_mcp_batch_composition.json"}
    merged = {"scripts/public_nine_build.py", "scripts/hia_native_runtime_mcp_build.py",
        "scripts/text_editor_create_private_pack.py", "scripts/runtime_mcp_extra_engine.S",
        "scripts/runtime_mcp_filesystem_fixture.S", "scripts/runtime_mcp_filesystem_front_fixture.S",
        "scripts/runtime_mcp_transport.S"}
    for name, expected in selected["sources"].items():
        data = (batch / name).read_bytes()
        assert {"bytes": len(data), "sha256": sha(data)} == expected, name
        if name not in generated | merged:
            files[name] = data
    output.mkdir(parents=True)
    baseline = output / "frontend-baseline"
    for name in ("native/runtime_mcp.hepta", "native/runtime_mcp_composition.json"):
        p = baseline / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(originals[name])
    author_path = batch_root / "authoring/author_frontend_dynamic.py"
    spec = importlib.util.spec_from_file_location("authority102_frontend_author", author_path)
    author = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(author)
    front, front_proof = author.compose(baseline, hepta, sha(originals["native/runtime_mcp.hepta"]))
    assert set(front) == generated and front_proof["baseline_functions"] == 70
    assert front_proof["functions"] == 73 and front_proof["fixed_child"] == 13
    files.update(front)
    functions = {
        "scripts/public_nine_build.py": merge_builder,
        "scripts/hia_native_runtime_mcp_build.py": merge_default,
        "scripts/text_editor_create_private_pack.py": merge_packer,
        "scripts/runtime_mcp_filesystem_fixture.S": merge_fixture,
        "scripts/runtime_mcp_transport.S": merge_transport,
    }
    for name, function in functions.items():
        files[name] = function(originals[name].decode()).encode()
    files["scripts/runtime_mcp_extra_engine.S"] = merge_engine(
        originals["scripts/runtime_mcp_extra_engine.S"].decode(),
        (batch / "scripts/runtime_mcp_extra_engine.S").read_text()).encode()
    assert files["scripts/runtime_mcp_filesystem_front_fixture.S"] == originals["scripts/runtime_mcp_filesystem_front_fixture.S"]
    binding = copy.deepcopy(base)
    for name in ("sdk_internal_projection_growth", "sdk_request_internal_capacity", "bounded_access_performance"):
        binding[name] = copy.deepcopy(selected[name])
    extension = copy.deepcopy(selected["rebuilt_batch_extension"])
    extension.update(base_members=91, physical_members=102,
        base_binding={"bytes": len(base_raw), "sha256": sha(base_raw)},
        frontend_composition=sha(front["native/runtime_mcp_batch_composition.json"]))
    binding["rebuilt_batch_extension"] = extension
    binding["authority_batch_union"] = {
        "schema": "hepta.runtime.authority-batch-union-source.v1",
        "authority_commit": BASE_COMMIT, "authority_binding": BASE_BINDING,
        "batch_commit": BATCH_COMMIT, "batch_binding": sha(batch_raw),
        "batch_profile": BATCH_PROFILE, "author_sha256": sha(Path(__file__).read_bytes()),
        "baseline_members": 91, "batch_members_added": 11, "expected_physical_members": 102,
        "retained_frontend_child12": 56, "added_frontend_child13": 47,
        "engine_bytes": 16384, "descriptor_offset": 8192,
        "batch_context_offset": 416, "batch_install_offset": 424,
        "authority_context_offset": 432, "authority_callback_offset": 488,
        "scope_cache_input_window_closed": False, "full_async_cancellation_qualified": False,
        "fresh_joint_graph_qualified": False, "whole_runtime_replaced": False,
    }
    binding["sources"] = {name: {"bytes": len(data), "sha256": sha(data)} for name, data in sorted(files.items())}
    assert len(files) == 217
    files["native/runtime_mcp_sources.json"] = encoded(binding)
    originals["native/runtime_mcp_sources.json"] = base_raw
    source = output / "source"
    for name, data in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    # The main seven-owner qualification remains a separate exact source overlay.
    rebind_manifest_raw = (rebind / "MANIFEST.json").read_bytes()
    assert sha(rebind_manifest_raw) == "b6465050171ac01a12793aa6b6fb3c45b515faa7683e8e8147b234553e6b80bf"
    rebind_manifest = json.loads(rebind_manifest_raw)
    registry = {}
    for row in rebind_manifest["files"]:
        name = row["path"]
        before, after = git_file(name), (rebind / name).read_bytes()
        assert pin(before) == row["before"] and pin(after) == row["after"]
        registry[name] = after
        originals[name] = before
        p = output / "main-registry-overlay" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(after)
    installation, unchanged = [], []
    all_files = {**files, **registry}
    for name, data in sorted(all_files.items()):
        old = originals.get(name)
        if old is None:
            old = git_file(name, required=False)
        if old == data:
            unchanged.append({"path": name, **pin(data)})
            continue
        row = {"path": name, "action": "create" if old is None else "replace",
            "after": pin(data), "before": None if old is None else pin(old),
            "source": str((output / "main-registry-overlay" if name in registry else source) / name)}
        if old is not None:
            rollback = output / "rollback" / name
            rollback.parent.mkdir(parents=True, exist_ok=True)
            rollback.write_bytes(old)
            row["rollback"] = {"action": "restore_exact_preimage", "path": str(rollback), **pin(old)}
        else:
            row["rollback"] = {"action": "remove_only_if_current_after_pin_matches"}
        installation.append(row)
    # Replay the rollback in memory, checking every postimage first.
    restored = dict(all_files)
    for row in reversed(installation):
        name = row["path"]
        assert pin(restored[name]) == row["after"]
        if row["before"] is None:
            del restored[name]
        else:
            restored[name] = (output / "rollback" / name).read_bytes()
            assert pin(restored[name]) == row["before"]
    expected = {name: git_file(name) for name in restored}
    assert restored == expected
    manifest = {
        "schema": "hepta.runtime.authority-batch-install-and-rollback.v1",
        "status": "SOURCE_COMPOSED_NATIVE_NOT_RUN", "base_commit": BASE_COMMIT,
        "batch_commit": BATCH_COMMIT, "source": str(source),
        "source_binding": pin(files["native/runtime_mcp_sources.json"]),
        "source_file_count_including_binding": len(files), "registry_overlay_files": len(registry),
        "install": installation, "unchanged": unchanged, "rollback_exactly_restores_base": True,
        "retained_authority_only_sources": sorted(set(base["sources"]) - set(selected["sources"])),
        "frontend_proof": front_proof, "mechanical_and_build_edits": EDITS,
        "author": pin(Path(__file__).read_bytes()), "native_or_original_executions": 0,
        "expected_physical_images": 102, "actual_physical_images": None,
        "catalog_tool_count_retained": 9, "catalog_batch_advertised": False,
        "joint_graph_qualified": False, "full_async_cancellation_qualified": False,
        "whole_runtime_replaced": False,
    }
    (output / "INSTALL.json").write_bytes(encoded(manifest))
    print(json.dumps({"status": manifest["status"], "source": str(source),
        "source_files": len(files), "install_actions": len(installation),
        "unchanged_files": len(unchanged), "registry_overlay_files": len(registry),
        "binding": manifest["source_binding"], "rollback_exact": True}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "batch", "rebind", "hepta", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    create(args.repo.resolve(strict=True), args.batch.resolve(strict=True), args.rebind.resolve(strict=True),
        args.hepta.resolve(strict=True), args.output.absolute())
