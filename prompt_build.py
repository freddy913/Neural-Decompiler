def build_prompt_and_write_debug(
    target_func_data,
    context_funcs,
    header_block,
    write_debug_files=True,
):
    """
    Builds the final input string for the model and writes debug files if specified.
    (Context Functions + <TARGET_SEP> + Target Function)
    """

    target_name = target_func_data.get('name') 
    target_segment = target_func_data.get('assembly', '').strip()
    
    callers_block = []
    callees_block = []

    for entry in context_funcs:
        role = entry.get('role', 'context')
        name = entry.get('name') or 'unknown_function'

        if entry.get('append_mode') == 'c_approx' and entry.get('c_approx'):
            code = entry.get('c_approx') or ""
        else:
            code = entry.get('assembly') or ""

        if not code:
            continue

        block_tuple = (name, code.strip())  
        if role == 'caller':
            callers_block.append(block_tuple)
        elif role == 'callee':
            callees_block.append(block_tuple)
        else:
            callees_block.append(block_tuple)

    def dedup(blocks):
        seen = set()
        out = []
        for nm, cd in blocks:
            if nm in seen:
                continue
            seen.add(nm)
            out.append((nm, cd))
        return out

    callers_block = dedup(callers_block)
    callees_block = dedup(callees_block)

    parts = []

    if header_block:
        parts.append(header_block.rstrip())

    # Target first
    parts.append(f"Target: {target_name}\n{target_segment}")

    # Callers (BY)
    if callers_block:
        parts.append("BY")
        for nm, cd in callers_block:
            parts.append(f"Caller: {nm}\n{cd}")

    # Callees (TO)
    if callees_block:
        parts.append("TO")
        for nm, cd in callees_block:
            parts.append(f"Callee: {nm}\n{cd}")

    prompt = "\n\n".join(parts) + "\n"

    # --- Debug-Files schreiben ---
    if write_debug_files:
        # 1. context overview
        with open("selected_context_functions.txt", "w", encoding="utf-8") as f:
            for entry in context_funcs or []:
                name = entry.get('name', 'unknown_function')
                degree = entry.get('degree', 'n/a')
                role = entry.get('role', 'context')
                mode = entry.get('append_mode', 'assembly')
                f.write(f";;; Function: {name} (degree {degree}, role {role}, mode {mode})\n")
            f.write("\n")

        # 2. model input
        with open("final_model_input.txt", "w", encoding="utf-8") as f:
            f.write(prompt)

        # 3. target assembly only
        with open("target_assembly.txt", "w", encoding="utf-8") as f:
            f.write(target_segment)

    return prompt