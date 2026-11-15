import os, sys, subprocess, tempfile
from pathlib import Path

# Exact safe_env body from hepta-runtime PR #34 at 3bb28e5 for bounded reproduction.
def prior_safe_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_') and k not in (
        'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS', 'RUSTDOCFLAGS',
        'CARGO_ENCODED_RUSTFLAGS', 'CARGO_TARGET_DIR', 'RUSTUP_TOOLCHAIN',
        'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_TARGET',
    )}
    env['GIT_NO_REPLACE_OBJECTS']='1'
    env['PYTHONDONTWRITEBYTECODE']='1'
    env['RUSTUP_TOOLCHAIN']='1.95.0'
    env['CARGO_INCREMENTAL']='0'
    return env

with tempfile.TemporaryDirectory(prefix='hepta-runtime-inherited-env-') as td:
    root=Path(td)
    marker=root/'marker.txt'
    (root/'unittest').mkdir()
    (root/'unittest'/'__init__.py').write_text('')
    (root/'unittest'/'__main__.py').write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("mock-unittest-executed")\nprint("Ran 9999 tests in 0.001s\\nOK")\n')
    prior=os.environ.get('PYTHONPATH')
    try:
        os.environ['PYTHONPATH']=td
        forwarded=prior_safe_env()
        assert forwarded['PYTHONPATH']==td
        child=subprocess.run([sys.executable,'-m','unittest','discover','-s','scripts'],env=forwarded,
                             capture_output=True,text=True,check=True)
        assert marker.read_text()=='mock-unittest-executed'
        print('REPRODUCED: original #34 safe_env forwards PYTHONPATH; untrusted unittest test runner executed despite claimed pinned source')
        print('original output:',child.stdout.strip())
    finally:
        if prior is None: os.environ.pop('PYTHONPATH',None)
        else: os.environ['PYTHONPATH']=prior
