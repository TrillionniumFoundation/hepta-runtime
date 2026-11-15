"""Run all 124 normal/private cases and 20 real external-writer races."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from hia_native_text_publication_pipeline import run_corpus
if __name__ == '__main__':
    run_corpus()
