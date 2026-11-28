"""Bounded custody for artifact download and the independent inert archive read."""
from pathlib import Path
import argparse
import json
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import archive_reader
from process import Recorder


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=['fetch','read'])
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--source-manifest-sha256',required=True)
    args=parser.parse_args()
    assert archive_reader.identity()==args.source_manifest_sha256
    work=args.work.absolute()
    recorder=Recorder(ROOT,work/(args.stage+'-processes'))
    argv=[sys.executable,'-I','-B',ROOT/'archive_reader.py',args.stage,'--artifact-root',work/'archive',
          '--source-manifest-sha256',args.source_manifest_sha256]
    try:
        raw,row=recorder.run(args.stage,argv,timeout=60 if args.stage=="fetch" else 180)
        result=json.loads(raw)
        if args.stage=='read':
            assert result['before']==result['after'] and len(result['probes'])==12
            assert result['native_or_rust_executions']==result['reader_writes']==0
            result=dict(status='PASS',evidence=result['evidence'],archive_guard_probes=12)
        result=dict(result,process=row,source_manifest_sha256=args.source_manifest_sha256)
        (work/(args.stage.upper()+'.json')).write_bytes(archive_reader.encoded(result))
        print(archive_reader.encoded(result).decode(),end='')
    except BaseException:
        print((recorder.directory/(args.stage+'.stderr')).read_text(),file=sys.stderr)
        raise


if __name__=='__main__':
    main()
