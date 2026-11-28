"""Run the complete typed Text Editor and borrowed-buffer domain."""
from pathlib import Path
import importlib.util
import os
import sys

sys.dont_write_bytecode = True
path = Path(__file__).resolve().parent / 'text_editor_params/native_capture.py'
spec = importlib.util.spec_from_file_location('text_editor_native_capture', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.run(os.environ['HIA_TEXT_EDITOR_PARAMS_QUALIFICATION_OUTPUT'])
