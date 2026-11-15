def verify_preparation(value, qualified, qualification_identity, terminal):
    """Use the independent Q-only foundation; exact CI cannot depend on its own success."""
    import types
    global PREPARATION_PROOF
    parent_id, parent_raw = read_file(PARENT_PATH, retain=True)
    need(parent_id['sha256'] == PARENT_SHA, 'sealed D1 qualification foundation changed')
    parent = types.ModuleType('d1_ci_receipt_only_foundation')
    parent.__file__ = str(PARENT_PATH)
    exec(compile(parent_raw, parent.__file__, 'exec'), parent.__dict__)
    inputs_id, inputs_raw = read_file(QUALIFICATION_BINDINGS_PATH, retain=True)
    need(inputs_id['sha256'] == QUALIFICATION_BINDINGS_SHA, 'actual D1 qualification prerequisites changed')
    inputs = json.loads(inputs_raw)
    need(inputs['schema'] == 'hepta-d1-c1-prerequisites/v1'
         and inputs['qualification_sealed'] is True and inputs['exact_ci_sealed'] is False,
         'Q-only prerequisite input required; exact CI must not require its own result')
    bindings = [parent_id, inputs_id]
    def bind(path, expected=None, retain=False, maximum=128 * 1024 * 1024):
        result = parent.checked(path, expected, maximum, retain)
        bindings.append(result[0] if retain else result)
        return result
    proof = parent.bind_d1_qualification(inputs, bind)
    need(proof['passed'] is True and proof['original_job_id'] == JOB_ID
         and proof['qualification'] == qualification_identity
         and proof['preparation']['sha256'] == PREPARATION_SHA
         and proof['terminal']['sha256'] == NATIVE_TERMINAL_SHA,
         'D1 qualification proof differs from exact CI inputs')
    need(json.loads(parent.checked(ROOT / 'preparation.json', retain=True)[1]) == value
         and json.loads(parent.checked(QUALIFICATION / 'report.json', retain=True)[1]) == qualified
         and json.loads(parent.checked(ROOT / 'qualification-terminal-status-01.json', retain=True)[1]) == terminal,
         'caller-provided D1 qualification documents differ')
    ADDITIONAL_PREPARATION_BINDINGS[:] = bindings
    PREPARATION_PROOF = proof
