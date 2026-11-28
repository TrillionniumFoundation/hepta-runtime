"""Read every captured byte and reject altered typed-parameter evidence."""
from pathlib import Path
import os
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_text_editor_params_qualification import evidence_controls
evidence_controls(ROOT, Path(os.environ['HIA_TEXT_EDITOR_PARAMS_QUALIFICATION_OUTPUT']))
