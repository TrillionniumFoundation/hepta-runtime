"""Fixed complete capture comparison commands; no execution on import."""
from pathlib import Path
GROUPS=("ordinary","lru","wide-128","wide-258")
def commands(meta):
    root=Path(meta["source_root"]);out=Path(meta["output_root"])
    fresh=Path(meta["fresh_root"]);prior=Path(meta["prior_root"]);py=meta["python"]
    rows=[dict(name="build-read",cwd=str(root),timeout=180,argv=[py,"-I","-B",str(root/"read_build_cli.py"),"--retained",str(fresh)])]
    for group in GROUPS:
        rows.append(dict(name="compare-"+group,cwd=str(root),timeout=60,argv=[py,"-I","-B",str(root/"compare_captured.py"),
            "--phase","run","--prior",str(prior/"complete"),"--build",str(fresh/"complete/run/build"),
            "--output",str(out/"groups"/group),"--group",group]))
    rows.append(dict(name="reader-controls",cwd=str(root),timeout=180,argv=[py,"-I","-B",str(root/"comparison_controls.py"),
        "--phase","create","--workspace",meta["workspace_root"]]))
    rows.append(dict(name="complete-read",cwd=str(root),timeout=180,argv=[py,"-I","-B",str(root/"read_comparison.py"),
        "--workspace",meta["workspace_root"]]))
    return rows
