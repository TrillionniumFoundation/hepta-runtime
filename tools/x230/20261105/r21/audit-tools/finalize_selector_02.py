#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Close the R21 evidence catalog for a rejected candidate without changing src."""
import argparse
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import tarfile


def load(path):
    return json.loads(Path(path).read_bytes())


def identity(path):
    raw = Path(path).read_bytes()
    return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob_sha1": hashlib.sha1(("blob " + str(len(raw)) + "\0").encode() + raw).hexdigest()}


def write_new(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, sort_keys=True, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final-entries", required=True)
    parser.add_argument("--review-inventory", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    here = Path(__file__).absolute().parent
    draft = load(here / "publication-selector-draft-02.json")
    index = load(here / "evidence-identities-draft-02.json")
    final = load(args.final_entries)
    rows = copy.deepcopy(draft["available_files"])
    for name in ("supplemental-static-inputs-01.json", "supplemental-static-inputs-02.json"):
        rows.extend(load(here / name))
    rows.extend(final)
    assert len({r["id"] for r in rows}) == len(rows)
    assert len({r["repo_path"] for r in rows}) == len(rows)
    by_id = {r["id"]: r for r in rows}
    for old in draft["pending_required"]:
        assert old["id"] in by_id and old["repo_path"] == by_id[old["id"]]["repo_path"]
    for row in rows:
        path = PurePosixPath(row["repo_path"])
        assert not path.is_absolute() and ".." not in path.parts
        assert path.parts[0] in {"docs", "tools"}, "Rejected candidate must not change compiled source"
        assert identity(row["source"]) == row["identity"]
        row["status"] = "closed_verified_file"
        if row["id"] == "r21_source_binder":
            row["role"] = "independent_source_binder_tool"
            row["actual_result_artifact_id"] = "r21_qualified_source_binding"
    orchestration = load(by_id["r21_final_orchestration"]["source"])
    assert orchestration["evidence_closed"] is True
    assert orchestration["candidate_adopted"] is False
    assert orchestration["native_regression_screen_passed"] is False
    assert all(v is True for v in orchestration["evidence_checks"].values())
    review_bytes = Path(args.review_inventory).read_bytes()
    review = json.loads(review_bytes)
    assert review["writers_stopped"] is True
    review_members = {r["archive_member"]: r for r in review["files"]}
    assert len(review_members) == len(review["files"])
    for original in draft["local_review_bundle_inputs"]:
        assert review_members[original["archive_member"]] == original
    with tarfile.open(by_id["r21_local_review_archive"]["source"], "r:gz") as archive:
        manifest_member = archive.getmember("_local-review-manifest.json")
        assert manifest_member.isfile()
        packed_review = json.loads(archive.extractfile(manifest_member).read())
    assert packed_review["inventory_sha256"] == hashlib.sha256(review_bytes).hexdigest()
    assert packed_review["writers_stopped"] is True
    assert all(packed_review[k] == review[k] for k in ("files", "scope", "exclusions"))
    known = {r["repo_path"] for r in rows} | {
        "tools/x230/20261105/r21/evidence-identities.json",
        "tools/x230/20261105/r21/publication-selector.json",
        "docs/X230_OPTIMIZATION_20261104_R19.md",
        "docs/X230_OPTIMIZATION_20261104_R16_R18.md",
        "src/mcp/runtime/jobs.rs"}
    links = []
    for name in ("r21_final_report", "r21_final_readme"):
        row = by_id[name]
        text = Path(row["source"]).read_text()
        assert "R21_PENDING" not in text and "待填" not in text
        for target in re.findall(r"\]\(([^)]+)\)", text):
            if target.startswith(("https://", "http://", "#")):
                continue
            target = target.split("#", 1)[0]
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(row["repo_path"]), target))
            assert resolved in known, (row["repo_path"], target, resolved)
            links.append({"from": row["repo_path"], "target": target, "resolved": resolved})
    decision = {"candidate_adopted": False, "native_regression_screen_passed": False,
                "source_changes_published": False,
                "reason": "C1 throughput and p95, plus C8 p95, failed the unchanged finite-run gates.",
                "retained_source_commit": "acdd07363cbff335e50c2944e02143d44ab03d6b",
                "expected_published_src_tree": "3aa8c9aadbf42b6a0ebdac3954bd1e64b4055e20",
                "qualified_rejected_candidate_src_tree": "5f814d4faa80b87cfb3a34ca38275664444c0883",
                "final_publication_commit": None,
                "publication_identity_scope": "Catalog closed before creating its commit; actual commit/ref is verified separately after publication."}
    index.update(closed=True, status="closed_evidence_candidate_rejected", adoption_assessed=True,
                 candidate_adopted=False, revision="final-01", pending_required_artifacts=[],
                 available_artifacts=rows, final_decision=decision,
                 scope="Complete selected source, raw archives and offline evidence for a qualified but rejected R21 candidate; accepted R19 compiled source is preserved.")
    index["source_chain"][-1]["role"] = "R21_STATUS_CANCEL_qualified_rejected_by_native_regression_screen"
    index["final_campaign"] = orchestration["campaign"]
    index["r21_qualification"] = orchestration["qualification"]
    output = Path(args.out_dir).absolute()
    output.mkdir(exist_ok=False)
    identity_path = output / "evidence-identities.json"
    write_new(identity_path, index)
    selector = copy.deepcopy(draft)
    archive_rows = [r for r in rows if r["repo_path"].endswith(".tar.gz")]
    assert len(archive_rows) == 9
    original_archive_rows = [r for r in archive_rows if r["id"] != "r21_local_review_archive"]
    assert len(original_archive_rows) == 8
    selector.update(revision="final-01", closed=True, publish_ready=True, pending_required=[],
                    original_archive_count=len(original_archive_rows), packaged_archive_count=len(archive_rows),
                    original_archive_classes=["qualification", "coldprocess", "cancelprocess", "rejected_hash", "campaign", "holder"],
                    generated_archive_classes=["local_review"],
                    archive_count_scope={"R20_original":5, "R21_original":3, "R21_generated_local_review":1},
                    supersedes_retained_draft={"source":str(here / "publication-selector-draft-02.json"), "identity":identity(here / "publication-selector-draft-02.json")},
                    available_files=rows, local_review_bundle_inputs=review["files"],
                    final_decision=decision,
                    closure_requirements=["All required artifacts exist and match their identities.",
                        "Qualification, raw replays and owned cleanup are bound by orchestration.",
                        "Native performance rejection is preserved without retries or source promotion.",
                        "Report and README relative links close against selected or pinned baseline paths.",
                        "No compiled-source entry is included in this publication."],
                    identity_document={"repo_path": "tools/x230/20261105/r21/evidence-identities.json",
                        "source": str(identity_path), "identity": identity(identity_path), "status": "closed"})
    write_new(output / "publication-selector.json", selector)
    write_new(output / "doc-link-closure-01.json", {"passed": True, "links": links,
              "report_identity": by_id["r21_final_report"]["identity"],
              "readme_identity": by_id["r21_final_readme"]["identity"],
              "compiled_source_entries": 0, "selected_files": len(rows)})
    print(json.dumps({"closed": True, "files": len(rows), "candidate_adopted": False,
                      "identity_document": identity(identity_path), "output": str(output)}))


if __name__ == "__main__":
    main()
