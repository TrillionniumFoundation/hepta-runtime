"""Registered closed-form numerical diagnostics, never gradient-based fitting."""
from .errors import integer, need
from .patches import checked_tensor


def analyze(params, store, max_elements):
    import torch
    operation = params.get("operation")
    need(operation in ("svd", "difference", "permutation_metrics", "statistics",
                       "concatenate", "reshape", "pair_differences", "writer_ranking"),
         "UNSUPPORTED_OPERATION", "Unknown numerical analysis operator")
    if operation == "concatenate":
        references = params.get("values")
        need(isinstance(references, list) and 1 <= len(references) <= 64,
             "ANALYSIS_LIMIT", "Concatenate expects 1..64 retained values")
        values, total = [], 0
        for reference in references:
            value = checked_tensor(reference, store, torch.float64, "value")
            total += value.numel()
            need(total <= max_elements, "ANALYSIS_LIMIT", "Concatenation exceeds element budget")
            values.append(value)
        axis = integer(params.get("axis", 0), "axis", 0, values[0].ndim - 1)
        expected = list(values[0].shape)
        need(all(v.ndim == len(expected) and all(i == axis or n == expected[i]
                 for i, n in enumerate(v.shape)) for v in values),
             "SHAPE_MISMATCH", "Non-concatenated dimensions must agree")
        value = torch.cat(values, dim=axis)
        return {"operation": operation, "result": {"shape": list(value.shape), "axis": axis},
                "arrays": store.put_tensors({"value": value}, "analysis-tensors")}
    value = checked_tensor(params["value"], store, torch.float64, "value")
    need(value.numel() <= max_elements, "ANALYSIS_LIMIT", "Analysis exceeds element budget")
    tensors, result = {}, {}
    if operation == "reshape":
        shape = params.get("shape")
        need(isinstance(shape, list) and 1 <= len(shape) <= 6
             and all(type(n) is int and (1 <= n <= max_elements or n == -1) for n in shape)
             and shape.count(-1) <= 1, "SHAPE_MISMATCH", "Invalid requested shape")
        import math
        known = math.prod(n for n in shape if n != -1)
        need(value.numel() % known == 0 if -1 in shape else known == value.numel(),
             "SHAPE_MISMATCH", "Reshape must preserve element count")
        tensors["value"] = value.reshape(shape).contiguous()
        result = {"shape": list(tensors["value"].shape)}
    elif operation == "pair_differences":
        need(3 <= value.ndim <= 5 and value.shape[1] >= 2,
             "SHAPE_MISMATCH", "Expected [states, permutations, ...features]")
        baseline = integer(params.get("reference_permutation", 0), "reference_permutation", 0, value.shape[1] - 1)
        differences = torch.cat([value[:, i:i+1] - value[:, baseline:baseline+1]
                                 for i in range(value.shape[1]) if i != baseline], dim=1)
        if params.get("flatten_to_rows", True):
            differences = differences.reshape(-1, value.shape[-1])
        tensors["difference"] = differences.contiguous()
        result = {"shape": list(differences.shape), "reference_permutation": baseline,
                  "rms": float(differences.square().mean().sqrt())}
    elif operation == "writer_ranking":
        need(value.ndim == 2, "SHAPE_MISMATCH", "Writer ranking expects [observations, input_width] differences")
        weight = checked_tensor(params["weight"], store, torch.float64, "weight")
        direction = checked_tensor(params["direction"], store, torch.float64, "direction").reshape(-1)
        need(weight.numel() + value.numel() + direction.numel() <= max_elements,
             "ANALYSIS_LIMIT", "Writer ranking exceeds element budget")
        need(weight.ndim == 2 and weight.shape[1] == value.shape[1]
             and weight.shape[0] == direction.numel() and float(direction.norm()) > 0,
             "SHAPE_MISMATCH", "Writer direction or input width differs")
        direction = direction / direction.norm()
        projection = direction @ weight
        scalar = value @ projection
        scores = (value * scalar[:, None]).mean(0) * projection
        ranked = torch.argsort(scores, descending=True)
        count = integer(params.get("top_k", 64), "top_k", 1, min(1024, len(scores)))
        if params.get("positive_only", True):
            ranked = ranked[scores[ranked] > 0]
        chosen = ranked[:count]
        tensors = {"scores": scores, "projection": projection, "columns": chosen}
        result = {"columns": chosen.tolist(), "scores": scores[chosen].tolist(),
                  "ranking_basis": "mean(input_difference * projected_output_difference) * writer_projection",
                  "positive_only": params.get("positive_only", True)}
    elif operation == "statistics":
        result = {"shape": list(value.shape), "mean": float(value.mean()), "rms": float(value.square().mean().sqrt()),
                  "minimum": float(value.min()), "maximum": float(value.max())}
    elif operation == "difference":
        other = checked_tensor(params["other"], store, torch.float64, "other")
        need(value.shape == other.shape, "SHAPE_MISMATCH", "Difference tensors must have equal shapes")
        tensors["difference"] = value - other
        result = {"rms": float(tensors["difference"].square().mean().sqrt()),
                  "maximum_absolute": float(tensors["difference"].abs().max())}
    elif operation == "svd":
        need(value.ndim == 2, "SHAPE_MISMATCH", "SVD expects a matrix")
        rank = integer(params.get("rank", 8), "rank", 1, min(64, *value.shape))
        if params.get("center_columns", False):
            value = value - value.mean(dim=0, keepdim=True)
        _, singular, vh = torch.linalg.svd(value, full_matrices=False)
        tensors = {"basis": vh[:rank].contiguous(), "singular_values": singular}
        result = {"rank": rank, "shape": list(value.shape), "singular_values_preview": singular[:16].tolist(),
                  "center_columns": params.get("center_columns", False)}
    else:
        need(value.ndim == 3 and value.shape[0] >= 2 and value.shape[1] >= 2,
             "SHAPE_MISMATCH", "Expected [states, permutations, semantic classes]")
        centered = value - value.mean(dim=-1, keepdim=True)
        canonical = centered[:, 0, :]
        nuisance = float((centered - centered.mean(dim=1, keepdim=True)).square().mean().sqrt())
        amplitude = float(canonical.square().mean().sqrt())
        contrast = float((canonical - canonical.mean(dim=0, keepdim=True)).square().mean().sqrt())
        result = {"permutation_centered_rms": nuisance, "canonical_rms": amplitude,
                  "state_contrast_rms": contrast,
                  "nuisance_over_amplitude": nuisance / amplitude if amplitude else None,
                  "nuisance_over_state_contrast": nuisance / contrast if contrast else None,
                  "semantic_alignment": "caller must provide a semantically aligned option axis"}
    arrays = store.put_tensors(tensors, "analysis-tensors") if tensors else None
    return {"operation": operation, "result": result, "arrays": arrays}
