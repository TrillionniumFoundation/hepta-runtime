"""Content-addressed artifacts and explicit input/output path authority."""
import hashlib
import os
from pathlib import Path
import tempfile

from .errors import canonical, checksum, digest, loads, need


def file_sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class PathPolicy:
    def __init__(self, input_roots, output_root):
        need(isinstance(input_roots, list), "INVALID_PATH", "input_roots must be a list")
        self.inputs = []
        for root in input_roots:
            p = Path(root)
            need(p.is_absolute() and p.is_dir(), "INVALID_PATH", "Input root must be an absolute existing directory")
            self.inputs.append(p.resolve())
        output = Path(output_root)
        need(output.is_absolute() and not output.is_symlink(), "INVALID_PATH", "output_root must be an absolute non-symlink directory")
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.output = output.resolve()

    def read(self, path, directory=False):
        p = Path(path)
        need(p.is_absolute(), "INVALID_PATH", "Input paths must be absolute")
        p = p.resolve(strict=True)
        need(any(p == root or p.is_relative_to(root) for root in self.inputs + [self.output]),
             "PATH_DENIED", "Input is outside declared roots", path=str(p))
        need(p.is_dir() if directory else p.is_file(), "INVALID_PATH", "Input has wrong file type", path=str(p))
        return p

    def bound(self, path, expected, max_bytes=None):
        p = self.read(path)
        checksum(expected)
        if max_bytes is not None:
            need(p.stat().st_size <= max_bytes, "ARTIFACT_LIMIT", "Input exceeds byte limit")
        need(file_sha256(p) == expected, "IDENTITY_MISMATCH", "Input SHA256 differs", path=str(p))
        return p


def atomic_create(path, data):
    """A crash never publishes a partial JSON file; existing evidence is immutable."""
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(name, path)
        except FileExistsError:
            need(not path.is_symlink() and path.read_bytes() == data,
                 "IDENTITY_MISMATCH", "Immutable record already differs", path=str(path))
        fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


class ArtifactStore:
    def __init__(self, root, max_artifact_bytes=268435456, max_total_bytes=1073741824):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_artifact_bytes, self.max_total_bytes = max_artifact_bytes, max_total_bytes
        self.total_bytes = sum(p.stat().st_size for p in self.root.iterdir() if p.is_file())

    def _commit(self, temporary, extension, kind, metadata):
        size = temporary.stat().st_size
        need(size <= self.max_artifact_bytes, "ARTIFACT_LIMIT", "Artifact exceeds per-object budget", bytes=size)
        content_hash = file_sha256(temporary)
        destination = self.root / (content_hash + extension)
        body = {"sha256": content_hash, "kind": kind, "path": str(destination),
                "byte_length": size, "metadata": metadata}
        artifact_id = digest(body)
        description = {"artifact_id": artifact_id, **body}
        descriptor = self.root / (artifact_id + ".ref.json")
        encoded = canonical(description) + b"\n"
        extra = (0 if destination.exists() else size) + (0 if descriptor.exists() else len(encoded))
        need(self.total_bytes + extra <= self.max_total_bytes, "ARTIFACT_LIMIT", "Session artifact budget exceeded")
        if destination.exists():
            need(not destination.is_symlink() and file_sha256(destination) == content_hash,
                 "IDENTITY_MISMATCH", "Stored artifact changed")
        else:
            os.link(temporary, destination)
        atomic_create(descriptor, encoded)
        self.total_bytes += extra
        return description

    def put_json(self, value, kind="evidence"):
        data = canonical(value) + b"\n"
        need(len(data) <= self.max_artifact_bytes, "ARTIFACT_LIMIT", "JSON artifact too large")
        fd, name = tempfile.mkstemp(prefix=".pending-", dir=self.root)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            return self._commit(temporary, ".json", kind, {})
        finally:
            temporary.unlink(missing_ok=True)

    def put_tensors(self, tensors, kind="tensors", metadata=None):
        import torch
        from safetensors.torch import save_file
        need(bool(tensors), "INVALID_ARGUMENT", "Empty tensor collection")
        estimate = sum(t.numel() * t.element_size() for t in tensors.values())
        need(estimate <= self.max_artifact_bytes, "ARTIFACT_LIMIT", "Tensor payload exceeds budget", bytes=estimate)
        prepared, inventory = {}, []
        for name, tensor in tensors.items():
            need(isinstance(name, str) and isinstance(tensor, torch.Tensor), "INVALID_ARGUMENT", "Expected named tensors")
            need(not tensor.is_sparse and not tensor.is_quantized, "UNSUPPORTED_DTYPE", "Only dense unquantized tensors supported")
            if tensor.is_floating_point():
                need(bool(torch.isfinite(tensor).all()), "NONFINITE", "Tensor contains NaN or infinity", tensor=name)
            prepared[name] = tensor.detach().cpu().contiguous().clone()
            inventory.append({"name": name, "shape": list(tensor.shape), "dtype": str(tensor.dtype), "elements": tensor.numel()})
        fd, name = tempfile.mkstemp(prefix=".pending-", dir=self.root)
        os.close(fd)
        temporary = Path(name)
        try:
            save_file(prepared, str(temporary))
            with temporary.open("rb") as stream:
                os.fsync(stream.fileno())
            return self._commit(temporary, ".safetensors", kind, {**(metadata or {}), "tensors": inventory})
        finally:
            temporary.unlink(missing_ok=True)

    def ref(self, artifact_id):
        checksum(artifact_id, "artifact_id")
        descriptor = self.root / (artifact_id + ".ref.json")
        need(descriptor.is_file() and not descriptor.is_symlink(), "UNKNOWN_ARTIFACT", "Artifact is not retained", artifact_id=artifact_id)
        value = loads(descriptor.read_bytes())
        need(value["artifact_id"] == artifact_id and digest({k: v for k, v in value.items() if k != "artifact_id"}) == artifact_id,
             "IDENTITY_MISMATCH", "Artifact descriptor changed")
        path = Path(value["path"])
        need(path.parent.resolve() == self.root and not path.is_symlink(), "INVALID_PATH", "Artifact escaped its store")
        need(path.is_file() and file_sha256(path) == value["sha256"],
             "IDENTITY_MISMATCH", "Artifact bytes changed", artifact_id=artifact_id)
        return value

    def load_json(self, artifact_id):
        ref = self.ref(artifact_id)
        need(ref["path"].endswith(".json"), "ARTIFACT_TYPE", "Expected a JSON artifact")
        return loads(Path(ref["path"]).read_bytes())

    def load_tensors(self, artifact_id):
        from safetensors.torch import load_file
        ref = self.ref(artifact_id)
        need(ref["path"].endswith(".safetensors"), "ARTIFACT_TYPE", "Expected tensor artifact")
        return load_file(ref["path"], device="cpu")

    def tensor(self, reference):
        need(isinstance(reference, dict), "INVALID_ARGUMENT", "Expected artifact/tensor reference")
        tensors = self.load_tensors(reference["artifact_id"])
        name = reference.get("tensor", "value")
        need(name in tensors, "UNKNOWN_TENSOR", "Tensor not in artifact", tensor=name)
        return tensors[name]
