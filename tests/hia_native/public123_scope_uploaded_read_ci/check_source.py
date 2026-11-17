from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from callable_common import syntax
import json
print(json.dumps(syntax(Path(__file__).resolve().parent),sort_keys=True))
