"""Exact admitted source closure, with real copies and no recursive read fallback."""
from pathlib import Path
from receipt_support import ROOT, PIN, regular, read_json, require


def check(root=ROOT):
    root = Path(root)
    profile = read_json(root / "source-profile.json")
    require(profile["schema"] == "hepta.runtime.rebuilt-batch-private-source.v1"
        and profile["target_commit"] == "d3d75c30719db966b004756f610007a7c723729e"
        and profile["new_version_not_lost_private91"] is True
        and profile["lost_private91_evidence_reused"] is False, "source profile")
    files = profile["files"]
    require(type(files) is dict and files and "source-profile.json" not in files, "source file closure")
    for name, expected in files.items():
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts and str(path) == name,
                "source file path")
        require(PIN(regular(root / name)) == expected, "admitted source differs: " + name)
    require(set(profile["scope"]) == {"private_local_body", "current_typed_projection", "public_batch_qualified",
        "gateway_caller_qualified", "full_async_cancellation_qualified", "remote_sftp_qualified", "whole_runtime_replaced"}
        and profile["scope"]["private_local_body"] is True and profile["scope"]["current_typed_projection"] is True
        and all(value is False for key, value in profile["scope"].items() if key not in
                ("private_local_body", "current_typed_projection")), "private source qualification boundary")
    return profile


def snapshot(source, destination):
    source, destination = Path(source), Path(destination)
    profile = check(source)
    destination.mkdir(parents=True, exist_ok=False)
    for name in ["source-profile.json", *profile["files"]]:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(regular(source / name))
    require(check(destination) == profile, "independent source snapshot changed")
    return profile
