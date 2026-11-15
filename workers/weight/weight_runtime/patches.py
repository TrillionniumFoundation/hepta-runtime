"""Finite typed edits with post-cast identity, coordinate counts and norm accounting."""
import hashlib

from .errors import canonical, integer, need, number


def tensor_sha256(tensor):
    import torch
    value = tensor.detach().cpu().contiguous()
    h = hashlib.sha256(canonical({"dtype": str(value.dtype), "shape": list(value.shape)}))
    h.update(value.reshape(-1).view(torch.uint8).numpy().tobytes())
    return h.hexdigest()


def squared_norm(tensor):
    total = 0.0
    flat = tensor.detach().reshape(-1)
    for chunk in flat.split(262144):
        total += float(chunk.double().square().sum())
    return total


def checked_tensor(value, store, dtype, name):
    import torch
    if isinstance(value, dict):
        tensor = store.tensor(value)
    else:
        try:
            tensor = torch.as_tensor(value, dtype=dtype, device="cpu")
        except (TypeError, ValueError) as exc:
            from .errors import WeightError
            raise WeightError("INVALID_TENSOR", str(exc), {"field": name}) from exc
    need(tensor.numel() > 0 and not tensor.is_complex(), "INVALID_TENSOR", "Expected nonempty real tensor", field=name)
    tensor = tensor.detach().cpu().to(dtype=dtype)
    need(bool(torch.isfinite(tensor).all()), "NONFINITE", "Non-finite tensor", field=name)
    return tensor


def indices(value, length, field):
    import torch
    if value is None:
        return torch.arange(length, dtype=torch.long)
    need(isinstance(value, list) and value, "INVALID_ARGUMENT", "Indices must be a nonempty list", field=field)
    need(all(type(i) is int and 0 <= i < length for i in value) and len(set(value)) == len(value),
         "INVALID_ARGUMENT", "Indices must be unique and in bounds", field=field)
    return torch.tensor(value, dtype=torch.long)


OPERATIONS = ("scale", "zero", "add", "low_rank", "input_projection", "writer_projection", "replace_sparse")
FIELDS = {"scale": {"indices", "factor"}, "zero": {"indices"}, "add": {"indices", "value"},
          "low_rank": {"left", "right", "alpha"}, "input_projection": {"basis", "alpha"},
          "writer_projection": {"columns", "direction", "alpha", "normalize_direction"},
          "replace_sparse": {"indices", "values"}}


def edit_tensor(original, spec, store, max_elements=16777216, max_abs_alpha=8.0):
    import torch
    need(original.is_floating_point() and not original.is_sparse and not original.is_quantized,
         "UNSUPPORTED_DTYPE", "Patch target must be dense floating point")
    need(original.numel() <= max_elements, "PATCH_LIMIT", "Target exceeds patch working-set budget")
    need(bool(torch.isfinite(original).all()), "NONFINITE", "Parent tensor contains non-finite values")
    need(spec.get("expected_tensor_sha256") == tensor_sha256(original),
         "IDENTITY_MISMATCH", "Patch parent tensor hash differs", tensor=spec.get("tensor"))
    operation = spec.get("operation")
    need(operation in OPERATIONS, "UNSUPPORTED_OPERATION", "Unknown typed patch operation", operation=operation)
    need(set(spec) <= FIELDS[operation] | {"tensor", "operation", "expected_tensor_sha256", "compute_dtype"},
         "INVALID_ARGUMENT", "Unknown fields in typed patch operation")
    if "normalize_direction" in spec:
        need(type(spec["normalize_direction"]) is bool, "INVALID_ARGUMENT", "normalize_direction must be boolean")
    precision = spec.get("compute_dtype", "float64")
    need(precision in ("float32", "float64"), "UNSUPPORTED_DTYPE", "compute_dtype must be float32 or float64")
    dtype = torch.float64 if precision == "float64" else torch.float32
    work = original.detach().cpu().to(dtype=dtype).contiguous().clone()
    if operation in ("scale", "zero", "add"):
        flat = work.reshape(-1)
        selected = indices(spec.get("indices"), flat.numel(), "indices")
        if operation == "zero":
            flat[selected] = 0
        elif operation == "scale":
            factor = number(spec.get("factor"), "factor")
            need(abs(factor) <= max_abs_alpha, "PATCH_LIMIT", "Scale exceeds research bound")
            flat[selected] *= factor
        else:
            value = checked_tensor(spec.get("value"), store, dtype, "value")
            need(value.numel() in (1, selected.numel()), "SHAPE_MISMATCH", "Add value must be scalar or match selected coordinates")
            flat[selected] += value.reshape(-1)
    elif operation == "replace_sparse":
        flat = work.reshape(-1)
        selected = indices(spec.get("indices"), flat.numel(), "indices")
        values = checked_tensor(spec.get("values"), store, dtype, "values").reshape(-1)
        need(values.numel() == selected.numel(), "SHAPE_MISMATCH", "Sparse values and indices differ")
        flat[selected] = values
    else:
        need(work.ndim == 2, "SHAPE_MISMATCH", "This operation requires a matrix")
        alpha = number(spec.get("alpha", 1.0), "alpha")
        need(abs(alpha) <= max_abs_alpha, "PATCH_LIMIT", "Alpha exceeds research bound")
        if operation == "low_rank":
            left = checked_tensor(spec.get("left"), store, dtype, "left")
            right = checked_tensor(spec.get("right"), store, dtype, "right")
            need(left.ndim == right.ndim == 2 and left.shape[0] == work.shape[0]
                 and right.shape[1] == work.shape[1] and left.shape[1] == right.shape[0]
                 and 1 <= left.shape[1] <= 64, "SHAPE_MISMATCH", "Low-rank factor shapes/rank invalid")
            work += alpha * (left @ right)
        elif operation == "writer_projection":
            columns = indices(spec.get("columns"), work.shape[1], "columns")
            direction = checked_tensor(spec.get("direction"), store, dtype, "direction").reshape(-1)
            need(direction.numel() == work.shape[0], "SHAPE_MISMATCH", "Writer direction must match output dimension")
            norm = float(direction.norm())
            need(norm > 0, "INVALID_ARGUMENT", "Zero writer direction")
            if spec.get("normalize_direction", True):
                direction /= norm
            else:
                need(abs(norm - 1) <= 1e-6, "INVALID_ARGUMENT", "Direction must have unit norm")
            selected = work.index_select(1, columns)
            work[:, columns] = selected - alpha * direction[:, None] @ (direction[None, :] @ selected)
        else:
            basis = checked_tensor(spec.get("basis"), store, dtype, "basis")
            if basis.ndim == 1:
                basis = basis[None, :]
            need(basis.ndim == 2 and basis.shape[1] == work.shape[1] and 1 <= basis.shape[0] <= 64,
                 "SHAPE_MISMATCH", "Input projection basis shape invalid")
            gram = basis @ basis.T
            need(bool(torch.allclose(gram, torch.eye(len(basis), dtype=dtype), atol=1e-5, rtol=1e-5)),
                 "INVALID_ARGUMENT", "Input projection basis must be orthonormal")
            work -= alpha * (work @ basis.T) @ basis
    # A lower compute precision may round the whole work buffer. Only copy the
    # explicitly edited support back, preserving every unselected parent byte.
    if operation in ("scale", "zero", "add", "replace_sparse"):
        result = original.detach().cpu().contiguous().clone()
        edited = work.reshape(-1)[selected]
        stored = edited.to(dtype=original.dtype)
        result.reshape(-1)[selected] = stored
    elif operation == "writer_projection":
        result = original.detach().cpu().contiguous().clone()
        edited = work.index_select(1, columns)
        stored = edited.to(dtype=original.dtype)
        result[:, columns] = stored
    else:
        edited = work
        result = stored = work.to(dtype=original.dtype)
    need(bool(torch.isfinite(edited).all()), "NONFINITE", "Patch computation produced non-finite values")
    need(result.shape == original.shape and bool(torch.isfinite(result).all()),
         "NONFINITE", "Final dtype cast overflowed or changed shape")
    return result.contiguous(), {"compute_dtype": precision,
                                 "final_dtype": str(original.dtype),
                                 "cast_max_abs_error": float((stored.to(dtype) - edited).abs().max())}


def patch_metrics(before, after, global_squared_norm):
    import math
    import torch
    need(before.shape == after.shape and before.dtype == after.dtype, "SHAPE_MISMATCH", "Realized target shape/dtype differs")
    delta = after.double() - before.double()
    delta_l2 = math.sqrt(squared_norm(delta))
    parent_l2 = math.sqrt(squared_norm(before))
    relative = delta_l2 / parent_l2 if parent_l2 else (0.0 if delta_l2 == 0 else None)
    global_relative = delta_l2 / math.sqrt(global_squared_norm) if global_squared_norm else (0.0 if delta_l2 == 0 else None)
    return {"effective_changed_coordinates": int(torch.count_nonzero(before != after)),
            "delta_l2": delta_l2, "parent_tensor_l2": parent_l2,
            "tensor_relative_norm": relative, "global_relative_norm": global_relative,
            "delta_max_abs": float(delta.abs().max()), "final_tensor_sha256": tensor_sha256(after)}
