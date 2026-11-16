"""Post-original physical registry evidence refusals; zero new SDK execution."""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent/'request_registry_sdk'))
from controls import run
if __name__=='__main__':run('original')
