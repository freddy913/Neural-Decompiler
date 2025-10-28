def build_prompt_and_write_debug(
    target_func_data,
    context_funcs,
    target_func_name_for_header,
    write_debug_files=True
):
    """
    Builds the final input string for the model and writes debug files if specified.
    (Context Functions + <TARGET_SEP> + Target Function)
    """

    if write_debug_files:
        with open("selected_context_functions.txt", "w", encoding="utf-8") as f:
            for entry in context_funcs:
                f.write(
                    f";;; Function: {entry.get('name', 'unknown_function')} "
                    f"(degree {entry.get('degree', 'n/a')}, role {entry.get('role', 'context')})\n"
                )
                f.write(entry.get('assembly', '') + "\n\n")
    
    context_segments = []
    for entry in context_funcs:
        if entry.get('append_mode') != 'assembly':
            code = entry.get('c_approx') or ""
        else:
            code = entry.get('assembly') or ""

        if not code:
            continue
        
        name = entry.get('name') or 'unknown_function'
        degree = entry.get('degree', 'n/a')
        role = entry.get('role', 'context')
        header = f";;; Context: {name} (degree {degree}, role {role})"
        context_segments.append(header + "\n" + code)

    target_segment = target_func_data.get('assembly', '')
    target_name = target_func_data.get('name', target_func_name_for_header)
    target_header = f";;; Target: {target_name}"

    final_context_input_string = "\n<SEP>\n".join(context_segments)
    final_context_input_string += "\n<TARGET_SEP>\n" + target_header + "\n" + target_segment

    if write_debug_files:
        with open("final_model_input.txt", "w", encoding="utf-8") as outf:
            outf.write(final_context_input_string)

        with open("target_assembly.txt", "w", encoding="utf-8") as f:
            f.write(target_func_data['assembly'])

    return final_context_input_string