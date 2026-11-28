"""Exercise the actual unchanged Local body admission and materialized-source verifier."""
from pathlib import Path
import argparse, importlib.util, json, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import read_only_guard as guard

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--mode",choices=("old","new","workflow-mutant","fixture-mutant"),required=True)
    a=parser.parse_args()
    root=a.source.resolve(strict=True)
    sys.path.insert(0,str(root/"scripts"))
    sys.path.insert(0,str(root/"tests/hia_native/local_text_body"))
    import portable_support
    module_path=root/"tests/hia_native/historical_public58/materialize.py"
    spec=importlib.util.spec_from_file_location("frozen_materializer",module_path)
    materializer=importlib.util.module_from_spec(spec);spec.loader.exec_module(materializer)
    binding=json.loads((HERE/"BINDING.json").read_bytes())
    workflow=binding["workflow"]
    def operation():
        if a.mode.endswith("-mutant"):
            try:
                materializer.check(root)
            except AssertionError as error:
                assert str(error)==workflow,(a.mode,str(error))
                return dict(status="EXPECTED_SOURCE_REFUSAL",mode=a.mode,reason=str(error))
            raise AssertionError("mutated source admitted")
        checked=materializer.verify_materialized(root)
        try:
            source=portable_support.source_evidence(root)
        except ValueError as error:
            assert a.mode=="old"
            assert str(error)=="body source identity differs: "+workflow
            return dict(status="EXPECTED_OLD_REFUSAL",reason=str(error),materialized=checked)
        assert a.mode=="new"
        expected=binding["body_source_manifest"]["files"]
        assert {name:source["files"][name] for name in expected}==expected
        assert len(expected)==67 and len(source["files"])==68
        return dict(status="BODY_SOURCE_ADMITTED",body_files=67,including_manifest=68,
                    materialized=checked,scope=source["scope"])
    proof=guard.guarded(operation,roots=[HERE,root],foreign_path=Path("/etc/passwd"))
    print(json.dumps(proof,sort_keys=True,indent=2,allow_nan=False))
if __name__=="__main__":main()
