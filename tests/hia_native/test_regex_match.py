"""Every original Boolean-match corpus case, executed by native HIA."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_match_cases import main
if __name__=='__main__':main()
