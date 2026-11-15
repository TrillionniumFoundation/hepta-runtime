"""Run the frozen complete native mechanical domains, with actual receipts."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from hia_native_text_publication_pipeline import run_native
if __name__ == '__main__':
    run_native()
