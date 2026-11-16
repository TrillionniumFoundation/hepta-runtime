"""Invert only declared graph-layout checks; retained case data stays exact."""
from pathlib import Path
import argparse,json
def verify(package):
    package=Path(package).resolve(strict=True)
    rows=json.loads((package/"ci/authority/ADAPTERS.json").read_bytes())
    result={}
    prefix='sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "joint/authority/drivers"))\n'
    for path,row in rows.items():
        after=(package/path).read_text();original=(package/"joint"/row["original_path"]).read_text()
        restored=after
        if row["explicit_original_helper_search_path"]:
            assert restored.count(prefix)==1
            restored=restored.replace(prefix,"",1)
        for change in reversed(row["changes"]):
            assert restored.count(change["after"])==change["count"],path
            restored=restored.replace(change["after"],change["before"])
        assert restored==original,path
        result[path]={"complete_inverse_bytes_equal":True,"original_case_data_changed":False}
    return {"status":"ORIGINAL_DOMAIN_AND_GRAPH_LAYOUT_ADAPTERS_PASS","files":result,
        "native_or_rust_executed":False}
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--package",type=Path,required=True)
    print(json.dumps(verify(p.parse_args().package),sort_keys=True))
