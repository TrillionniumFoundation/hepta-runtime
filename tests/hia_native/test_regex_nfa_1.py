"""One fixed half of the complete original NFA domain; no budget changes."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import artifact
from regex_nfa_cases import main
if __name__=='__main__':
    sys.argv=[__file__,'--shards','2','--shard','1','--output',str(artifact('nfa-1'))]
    main()
