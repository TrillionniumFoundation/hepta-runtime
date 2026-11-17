from pathlib import Path
import json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import callable_common
print(json.dumps(callable_common.syntax(Path(__file__).resolve().parent),sort_keys=True))
