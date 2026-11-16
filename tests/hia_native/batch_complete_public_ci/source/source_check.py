"""Exact portable input closure, copied without aliases or fallback discovery."""
from pathlib import Path, PurePosixPath
from receipt_support import ROOT, PIN, regular, read_json, require

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
SCOPE = {"ordinary_public_batch_fixture": True, "complete_current_sdk_router": False,
    "catalog_batch_advertised": False, "full_async_cancellation_qualified": False,
    "remote_sftp_qualified": False, "whole_runtime_replaced": False}


def check(root=ROOT):
    root = Path(root)
    profile = read_json(root / "source-profile.json")
    require(profile["schema"] == "hepta.runtime.batch-public-complete-source.v1"
        and profile["target_commit"] == TARGET and profile["scope"] == SCOPE
        and profile["new_version_not_lost_private91"] is True
        and profile["lost_private91_evidence_reused"] is False, "portable source profile")
    files = profile["files"]
    require(type(files) is dict and files and "source-profile.json" not in files, "exact portable source set")
    for name, expected in files.items():
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts and str(relative) == name,
            "portable source path")
        require(PIN(regular(root / name)) == expected, "portable source bytes changed: " + name)
    require(profile["private_domains"] == {"typed-legacy": 417, "typed-modern": 417,
        "filesystem": 926, "session": 17} and profile["stdio_domains"] == {"legacy": 15, "modern": 13}
        and profile["per_exchange_deadline_seconds"] == 60 and profile["outer_lane_deadline_seconds"] == 180,
        "complete fixed input/deadline declaration")
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
    require(check(destination) == profile, "independent portable source copy changed")
    return profile
