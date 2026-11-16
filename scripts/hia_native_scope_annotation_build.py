"""Fresh pinned HIA build for the private current-target scope annotation owner."""
from pathlib import Path
import hashlib
import contextlib
import importlib.util
import io
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
GENERATION = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
MODULES = {
    "text_result_constructor": (
        "3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d",
        "beaec81c8006ab98e31e0ab72d01311a0cd51ee4ead074bbd5b7742679e033cf"),
    "scope_annotation": (
        "4478ee39e09a2638c2da5a2e806df1a5bc47e0fb18c88f65e6f70d8615528b33",
        "a4ef44f2b8787c2e1d451f299546ee0ef92ed3cb757d5b94fc03fdc02aab5046"),
    "serde_json": (
        "ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18",
        "d57ad9ee16270929bbaac78219c7ac54e3ad2ab64de2e6a4fe3f29236706f22c"),
    "serde_error": (
        "14eea1ebc4bd12cb10e961d61bea58dded9befb15a3c67191fe6301577bc00e9",
        "1ccbbb66c5a1946c87295ce2bd89c17e9592730885123c903a3f1a0fcea6918f"),
    "typed_result_json": (
        "a9dfe2fec3f35b2ef2bcfaec56229007c75301cccb06a96a36691dc361aa0bec",
        "fdf581b95d1dfd7d73004807bbc43a797a5353555326ff809c4acd02b6207f68"),
}
PROFILES = {name: ("history.v1" if name == "text_result_constructor" else "serde-json.v1") for name in MODULES}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {"bytes": len(raw), "sha256": SHA(raw)}


def source_evidence(root=ROOT):
    root = Path(root).resolve(strict=True)
    result = {}
    for name, (expected, _) in MODULES.items():
        relative = "native/" + name + ".hepta"
        path = root / relative
        if path.resolve(strict=True) != path or not path.is_file():
            raise ValueError("source must be an ordinary owned file: " + relative)
        raw = path.read_bytes()
        if SHA(raw) != expected:
            raise ValueError("source changed: " + relative)
        result[relative] = pin(raw)
    return {"schema": "hepta.runtime.scope-annotation-source-files.v1", "files": result}


def verify_build(manifest, *, source_root=ROOT):
    manifest = Path(manifest).resolve(strict=True)
    document = json.loads(manifest.read_bytes())
    if document.get("schema") != "hepta.runtime.scope-annotation-build.v1":
        raise ValueError("annotation build schema differs")
    if document.get("sources") != source_evidence(source_root):
        raise ValueError("annotation build source closure differs")
    if document.get("compiler_commit") != COMPILER or document.get("compiler_image_sha256") != GENERATION:
        raise ValueError("annotation build compiler differs")
    if set(document.get("modules", {})) != set(MODULES):
        raise ValueError("annotation build module set differs")
    expected_reproduction = {"authoring/native/"+name+suffix for name in ("scope_annotation", "text_result_constructor")
                            for suffix in (".hepta", ".composition.json")}
    if set(document.get("source_reproduction", {})) != expected_reproduction:
        raise ValueError("actual source reproduction closure differs")
    for relative, expected in document["source_reproduction"].items():
        path = manifest.parent/relative
        if path.resolve(strict=True) != path:
            raise ValueError("source reproduction path crosses symbolic link")
        raw = path.read_bytes()
        if pin(raw) != expected or raw != (Path(source_root)/relative.removeprefix("authoring/")).read_bytes():
            raise ValueError("actual reproduced source/composition differs")
    for name, row in document["modules"].items():
        relative = Path(row["manifest"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("module path escapes annotation build")
        path = manifest.parent / relative
        if path.resolve(strict=True) != path:
            raise ValueError("module path contains a symbolic link")
        raw = path.read_bytes()
        if SHA(raw) != row["manifest_sha256"]:
            raise ValueError("module manifest changed")
        metadata = json.loads(raw)
        source, image = MODULES[name]
        profile = PROFILES[name]
        capacities = (128<<20,128<<20,256<<20) if profile == "history.v1" else (16<<20,64<<20,256<<20)
        if (metadata.get("schema"), metadata.get("target"), metadata.get("standalone"), metadata.get("buffer_profile"),
                metadata.get("input_capacity"), metadata.get("output_capacity"), metadata.get("workspace_capacity")) != (
                "hepta.runtime.native-module.v1", "linux-x86_64", None, profile, *capacities):
            raise ValueError("module ABI/capacity profile differs")
        if (metadata.get("source_sha256"), metadata.get("image_sha256")) != (source, image):
            raise ValueError("module source/image identity differs")
        if metadata.get("compiler_commit") != COMPILER or metadata.get("compiler_sha256") != GENERATION:
            raise ValueError("module compiler differs")
        for field, expected in (("source", source), ("image", image)):
            member = Path(metadata[field])
            if len(member.parts) != 1 or member.is_absolute():
                raise ValueError("module member is not a plain basename")
            actual = path.parent / member
            if actual.resolve(strict=True) != actual or SHA(actual.read_bytes()) != expected:
                raise ValueError("module member changed")
    return document


def reproduce_sources(hepta, folder, root):
    """Rerun source-bound authors; both imported AST closures must reproduce."""
    directory = folder/"authoring"
    directory.mkdir()
    for name in ("native/serde_json.hepta", "native/typed_result_json.hepta", "scripts/text_result_constructor.pseudo"):
        target = directory/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root/name, target)
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    scope = load("scope_annotation_author", root/"tests/hia_native/scope_annotation/author.py")
    constructor = load("scope_annotation_constructor_author", root/"scripts/author_text_result_constructor.py")
    with contextlib.redirect_stdout(io.StringIO()):
        scope.generate(Path(hepta).resolve(strict=True), root,
            root/"tests/hia_native/scope_annotation/reference/target",
            root/"tests/hia_native/scope_annotation/source.py.txt", directory/"native/scope_annotation.hepta")
        constructor.generate(Path(hepta).resolve(strict=True), directory)
    files = {}
    for name in ("scope_annotation", "text_result_constructor"):
        for suffix in (".hepta", ".composition.json"):
            relative = "native/"+name+suffix
            raw = (directory/relative).read_bytes()
            if raw != (root/relative).read_bytes():
                raise ValueError("source author/import closure did not reproduce: "+relative)
            files["authoring/"+relative] = pin(raw)
    return files


def build_scope_annotation(hepta, build_root, *, source_root=ROOT, bootstrap=None):
    root = Path(source_root).resolve(strict=True)
    folder = Path(build_root).absolute()
    folder.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(root / "scripts"))
    from hia_native_build import NativeBuild
    sources = source_evidence(root)
    if bootstrap is not None:
        original = Path(bootstrap).resolve(strict=True)
        destination = folder / "bootstrap"
        destination.mkdir()
        for name in ("B1.image.bin", "B2.image.bin", "B3.image.bin", "bootstrap.json"):
            src = original / name
            if src.resolve(strict=True) != src or not src.is_file():
                raise ValueError("bootstrap member is not an ordinary file")
            shutil.copyfile(src, destination/name)
    reproduction = reproduce_sources(hepta, folder, root)
    build = NativeBuild(hepta, folder)
    modules = {}
    for name, (source, image) in MODULES.items():
        path = build.compile(name, root / "native" / (name + ".hepta"), standalone=None, buffer_profile=PROFILES[name])
        metadata = json.loads(path.read_bytes())
        if (metadata["source_sha256"], metadata["image_sha256"]) != (source, image):
            raise ValueError("actual HIA source/image changed during fresh build")
        modules[name] = {"manifest": str(path.relative_to(folder)), "manifest_sha256": SHA(path.read_bytes()),
                         "source_sha256": source, "image_sha256": image}
    if source_evidence(root) != sources or build.compiler_sha256 != GENERATION:
        raise ValueError("build source/compiler closure changed")
    document = dict(schema="hepta.runtime.scope-annotation-build.v1", compiler_commit=COMPILER,
        compiler_image_sha256=GENERATION, sources=sources, modules=modules, source_reproduction=reproduction,
        cold_qualification=False, original_annotate_qualified=False, public_handler_qualified=False,
        production_activated=False, whole_runtime_replaced=False)
    manifest = folder / "scope-annotation-build.json"
    manifest.write_text(json.dumps(document, sort_keys=True, indent=2)+"\n")
    verify_build(manifest, source_root=root)
    return manifest
