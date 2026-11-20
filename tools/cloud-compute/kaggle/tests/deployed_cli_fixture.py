import hashlib,importlib.util
from pathlib import Path
path=Path(__file__).resolve().parent/'fixtures/deployed_hepta_kaggle.py'
assert hashlib.sha256(path.read_bytes()).hexdigest()=='5cbc8455d4482f3d6223cb51f981c302780779f4a1f51325076dea4583a2f864'
spec=importlib.util.spec_from_file_location('frozen_deployed_cli',path)
deployed_cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(deployed_cli)
