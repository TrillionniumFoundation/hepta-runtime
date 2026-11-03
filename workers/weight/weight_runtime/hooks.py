"""Bounded activation capture and local causal interventions with guaranteed cleanup."""
from .errors import identifier, integer, need, number, WeightError
from .patches import checked_tensor


def install_hooks(provider, store, captures, interventions, captured, stack, max_elements):
    import torch
    need(isinstance(captures, list) and len(captures) <= 16 and isinstance(interventions, list) and len(interventions) <= 8,
         "CAPTURE_LIMIT", "Too many hooks/interventions")
    counter = {"elements": 0}
    common_fields = {"module", "where", "tensor_index", "select", "semantic_order", "token_indices"}
    for spec in captures:
        need(isinstance(spec, dict) and set(spec) <= common_fields | {"name"},
             "INVALID_ARGUMENT", "Unknown capture fields")
    for spec in interventions:
        need(isinstance(spec, dict) and set(spec) <= common_fields | {"operation", "factor", "value", "direction", "alpha"},
             "INVALID_ARGUMENT", "Unknown intervention fields")

    def tensor_value(value, spec):
        if isinstance(value, torch.Tensor):
            return value, None
        index = integer(spec.get("tensor_index", 0), "tensor_index", 0, 32)
        need(isinstance(value, tuple) and index < len(value) and isinstance(value[index], torch.Tensor),
             "UNSUPPORTED_ACTIVATION", "Selected hook value is not a tensor or tuple tensor")
        return value[index], index

    def restore_value(value, index, new):
        if index is None:
            return new
        values = list(value)
        values[index] = new
        return tuple(values)

    def selected(tensor, spec):
        selection = spec.get("select", "all")
        if selection == "all":
            return tensor, lambda new: new
        need(tensor.ndim == 3, "SHAPE_MISMATCH", "Token selection requires [batch, tokens, width]")
        if selection == "markers":
            positions = getattr(provider, "marker_positions", None)
            need(positions is not None, "UNSUPPORTED_CAPABILITY", "Provider has no semantic marker positions")
            if spec.get("semantic_order", True):
                order = getattr(provider, "_order", None)
                need(order is not None, "UNSUPPORTED_CAPABILITY", "No option alignment metadata")
                positions = positions.index_select(1, torch.argsort(torch.tensor(order)))
        elif selection == "tokens":
            ids = spec.get("token_indices")
            need(isinstance(ids, list) and 1 <= len(ids) <= 1024 and len(set(ids)) == len(ids)
                 and all(type(i) is int and 0 <= i < tensor.shape[1] for i in ids),
                 "INVALID_ARGUMENT", "Invalid token indices")
            positions = torch.tensor(ids)[None, :].expand(tensor.shape[0], -1)
        else:
            raise WeightError("INVALID_ARGUMENT", "Unknown activation selection")
        need(positions.shape[0] == tensor.shape[0] and bool((positions >= 0).all())
             and bool((positions < tensor.shape[1]).all()), "SHAPE_MISMATCH", "Marker positions do not fit captured tensor")
        indices = positions.to(tensor.device)[:, :, None].expand(-1, -1, tensor.shape[-1])
        return tensor.gather(1, indices), lambda new: tensor.clone().scatter(1, indices, new)

    for i, spec in enumerate(captures):
        name = identifier(spec.get("name", "capture" + str(i)), "capture name")
        module = provider.module.get_submodule(spec["module"])
        where = spec.get("where", "output")
        need(where in ("input", "output"), "INVALID_ARGUMENT", "Hook where must be input/output")

        def capture(value, spec=spec, name=name):
            tensor, _ = tensor_value(value, spec)
            view, _ = selected(tensor, spec)
            counter["elements"] += view.numel()
            need(counter["elements"] <= max_elements, "CAPTURE_LIMIT", "Captured activations exceed element budget")
            ordinal = sum(k.startswith(name + ".") for k in captured)
            captured[name + "." + str(ordinal)] = view.detach().cpu().clone()

        if where == "input":
            handle = module.register_forward_pre_hook(lambda module, args, fn=capture: fn(args))
        else:
            handle = module.register_forward_hook(lambda module, args, output, fn=capture: fn(output))
        stack.callback(handle.remove)

    for spec in interventions:
        module = provider.module.get_submodule(spec["module"])
        where = spec.get("where", "output")
        need(where in ("input", "output"), "INVALID_ARGUMENT", "Hook where must be input/output")

        def intervene(value, spec=spec):
            tensor, index = tensor_value(value, spec)
            view, restore_selection = selected(tensor, spec)
            need(view.is_floating_point() and view.numel() <= max_elements,
                 "CAPTURE_LIMIT", "Intervention tensor is unsupported or too large")
            operation = spec.get("operation")
            if operation == "scale":
                factor = number(spec["factor"], "factor")
                need(abs(factor) <= 8, "PATCH_LIMIT", "Intervention scale outside bound")
                new = view * factor
            elif operation == "replace":
                new = checked_tensor(spec["value"], store, view.dtype, "replacement")
                need(new.shape == view.shape, "SHAPE_MISMATCH", "Activation replacement shape differs")
            elif operation == "subtract_direction":
                direction = checked_tensor(spec["direction"], store, torch.float64, "direction").reshape(-1)
                need(direction.numel() == view.shape[-1] and float(direction.norm()) > 0,
                     "SHAPE_MISMATCH", "Activation direction shape/norm invalid")
                direction /= direction.norm()
                alpha = number(spec.get("alpha", 1.0), "alpha")
                need(abs(alpha) <= 8, "PATCH_LIMIT", "Intervention alpha outside bound")
                work = view.double()
                new = (work - alpha * (work @ direction)[..., None] * direction).to(view.dtype)
            else:
                raise WeightError("UNSUPPORTED_OPERATION", "Unknown activation intervention")
            need(new.shape == view.shape and new.dtype == view.dtype and bool(torch.isfinite(new).all()),
                 "NONFINITE", "Invalid post-cast activation intervention")
            return restore_value(value, index, restore_selection(new))

        if where == "input":
            handle = module.register_forward_pre_hook(lambda module, args, fn=intervene: fn(args))
        else:
            handle = module.register_forward_hook(lambda module, args, output, fn=intervene: fn(output))
        stack.callback(handle.remove)
