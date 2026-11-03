import os
import unittest
from unittest.mock import patch

class QualificationError(Exception):
    pass

_ALLOWED_EXECUTION_ENV = frozenset((
    "RUST_BACKTRACE", "RUST_LOG", "CARGO_TERM_COLOR", "PYTHONDONTWRITEBYTECODE",
    "PYTHONUNBUFFERED", "PYTHON_VERSION",
))
_BLOCKED_EXECUTION_ENV_EXACT = frozenset((
    "CC", "CXX", "LD", "AR", "RANLIB", "STRIP", "OBJCOPY", "OBJDUMP",
    "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "MAKEFLAGS",
    "CMAKE_PREFIX_PATH", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "LIBRARY_PATH",
    "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "NODE_OPTIONS",
))
_BLOCKED_EXECUTION_ENV_PREFIXES = (
    "GIT_", "RUST", "CARGO_", "LD_",
    "DYLD_", "PYTHON", "PKG_CONFIG_", "CMAKE_", "OPENSSL_",
    "LIBCLANG_", "BINDGEN_", "CC_", "CXX_",
)

def blocked_execution_env_names(environ=None):
    env=os.environ if environ is None else environ
    return sorted(name for name in env if name not in _ALLOWED_EXECUTION_ENV and
                  (name in _BLOCKED_EXECUTION_ENV_EXACT or
                   name.startswith(_BLOCKED_EXECUTION_ENV_PREFIXES)))

def safe_env():
    blocked=blocked_execution_env_names()
    if blocked:
        raise QualificationError("unreviewed execution environment keys: " + ", ".join(blocked))
    env={k:v for k,v in os.environ.items() if not k.startswith("GIT_") and k not in (
        "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR", "RUSTUP_TOOLCHAIN",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_TARGET",
    )}
    env["GIT_NO_REPLACE_OBJECTS"]="1"
    env["PYTHONDONTWRITEBYTECODE"]="1"
    env["RUSTUP_TOOLCHAIN"]="1.95.0"
    env["CARGO_INCREMENTAL"]="0"
    return env

class EnvReferenceTests(unittest.TestCase):
    def test_bad_keys_never_forwarded(self):
        for key in ("PYTHONPATH", "LD_PRELOAD", "RUSTC", "RUSTFLAGS", "RUSTUP_TOOLCHAIN",
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", "CARGO_HOME",
                    "GIT_CONFIG_COUNT", "BASH_ENV", "ENV", "CC", "OPENSSL_DIR",
                    "DYLD_INSERT_LIBRARIES", "PKG_CONFIG_PATH", "NODE_OPTIONS"):
            with self.subTest(key=key), patch.dict(os.environ,{key:"fixture"},clear=True):
                with self.assertRaisesRegex(QualificationError, key):
                    safe_env()
    def test_no_values_in_error(self):
        with patch.dict(os.environ,{"PYTHONPATH":"secret-case-value"},clear=True):
            with self.assertRaises(QualificationError) as c:
                safe_env()
            self.assertNotIn("secret-case-value",str(c.exception))
    def test_allowed_diagnostics_preserved(self):
        with patch.dict(os.environ,{"PATH":"/usr/bin", "RUST_BACKTRACE":"1",
                    "RUST_LOG":"trace","CARGO_TERM_COLOR":"never"},clear=True):
            env=safe_env()
            self.assertEqual(env["RUST_BACKTRACE"],"1")
            self.assertEqual(env["RUST_LOG"],"trace")
            self.assertEqual(env["CARGO_TERM_COLOR"],"never")
            self.assertEqual(env["RUSTUP_TOOLCHAIN"],"1.95.0")
    def test_bounded_key_detection(self):
        keys=blocked_execution_env_names({"CARGO_TARGET_FAKE_LINKER":"x","PYTHONPATH":"x",
                    "RUST_BACKTRACE":"1", "GIT_CONFIG_COUNT":"1"})
        self.assertEqual(keys,["CARGO_TARGET_FAKE_LINKER","GIT_CONFIG_COUNT","PYTHONPATH"])
if __name__=='__main__': unittest.main(verbosity=2)
