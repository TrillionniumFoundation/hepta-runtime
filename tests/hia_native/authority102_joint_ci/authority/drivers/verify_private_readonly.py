"""Run the complete private state reader inside the retained actual guard."""
from pathlib import Path
import argparse
import json
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from read_only_guard import guarded
from verify_private_binding import verify,module_path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','manifest','capture'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--module-map',type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True);manifest=a.manifest.resolve(strict=True);capture=a.capture.resolve(strict=True)
    mapping=a.module_map.resolve(strict=True) if a.module_map else None
    md=json.loads(manifest.read_bytes())
    roots={source,capture,manifest.parent,Path(__file__).resolve().parent}
    roots.update(module_path(row['manifest'],mapping).resolve(strict=True).parent for row in md['members'])
    if mapping is not None:roots.add(mapping.parent)
    roots=sorted(roots,key=str)
    result=guarded(lambda:verify(source,manifest,capture,mapping),roots=roots,foreign_path='/dev/null')
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
