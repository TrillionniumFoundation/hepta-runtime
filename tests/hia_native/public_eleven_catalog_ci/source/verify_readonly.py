"""Run the complete verifier under the fixed Python read-only regression guard."""
import argparse
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import verify_recipe
import read_only_guard

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--foreign-path',type=Path,required=True)
    a=p.parse_args();output=a.output.resolve(strict=True);foreign=a.foreign_path.absolute()
    assert foreign.is_file() and not foreign.is_relative_to(output) and not foreign.is_relative_to(ROOT)
    # Load the fixed original reader's Python dependencies before the guard;
    # the actual verification still reads its owned sources and every record.
    assert verify_recipe.ORIGINAL_READER is not None
    result=read_only_guard.guarded(lambda:verify_recipe.verify(output),roots=[ROOT,output],foreign_path=foreign)
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
