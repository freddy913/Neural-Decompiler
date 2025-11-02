from Config import (
    TARGET_BINARY_PATH,
    TARGET_FUNCTION_NAME,
    CONTEXT_THRESHOLD_TOKENS,
    MYTOKENIZER,
    WRITE_DEBUG_FILES,
    FUNCTION_TXT,
    ASSEMBLY_TXT,
)

from Heuristic import (
    real_c_code_lookup, 
    apply_heuristic, 
    get_context_candidates_with_degrees,
    filter_candidate_funcs_runtime_safe,
    build_candidate_func_data,
    build_header_block_from_binary,
)

from HintsAndLabels import (
    build_dwarf_lookup_for_repo, 
    finalize_label_for_training, 
)

from ElfFeatures import (
    load_project,
    get_function_data,
    collect_constant_pool_for_function,
)

from AsmNormalizer import join_semicolon, normalize_model_input_with_context_groups

import os, re, sys, time

INPUT_DIR = os.path.join(".", "INPUT")
FUNCTION_TXT_PATH = os.path.join(INPUT_DIR, FUNCTION_TXT)
ASSEMBLY_TXT_PATH = os.path.join(INPUT_DIR, ASSEMBLY_TXT)

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

    #TODO: remove as items already deduped earlier
    # def dedup(blocks):
    #     seen = set()
    #     out = []
    #     for nm, cd in blocks:
    #         if nm in seen:
    #             continue
    #         seen.add(nm)
    #         out.append((nm, cd))
    #     return out

    # callers_block = dedup(callers_block)
    # callees_block = dedup(callees_block)

    parts = []

    if header_block:
        parts.append(header_block.rstrip())

    # Target first
    if write_debug_files:
        parts.append(f"Target: {target_name}\n{target_segment}")
    else:
        parts.append(f"Target: {target_segment}")

    # Callers (BY)
    if callers_block:
        parts.append("BY")
        for nm, cd in callers_block:
            if write_debug_files:
                parts.append(f"Caller: {nm}\n{cd}")
            else:
                parts.append(f"Caller: {cd}")

    # Callees (TO)
    if callees_block:
        parts.append("TO")
        for nm, cd in callees_block:
            if write_debug_files:
                parts.append(f"Callee: {nm}\n{cd}")
            else:
                parts.append(f"Callee: {cd}")

    prompt = "\n\n".join(parts) + "\n"

    if write_debug_files:
        with open("selected_context_functions.txt", "w", encoding="utf-8") as f:
            for entry in context_funcs or []:
                name = entry.get('name', 'unknown_function')
                degree = entry.get('degree', 'n/a')
                role = entry.get('role', 'context')
                mode = entry.get('append_mode', 'assembly')
                f.write(f"Function: {name} (degree {degree}, role {role}, mode {mode})\n")
            f.write("\n")

        with open("final_model_input.txt", "w", encoding="utf-8") as f:
            f.write(prompt)

        with open("target_assembly.txt", "w", encoding="utf-8") as f:
            f.write(target_segment)

    return prompt

def _one_line(s): 
    if not s: return ""
    s = s.replace("\r", "\n")
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n+", " ", s)
    return s.strip()

def _compact_label(label):
    if not label: return ""
    parts = label.split("\n", 1)
    body = parts[1] if len(parts) == 2 else parts[0]
    return _one_line(body)

def init_pair_files():
    os.makedirs(INPUT_DIR, exist_ok=True)
    for p in (FUNCTION_TXT_PATH, ASSEMBLY_TXT_PATH):
        try: os.unlink(p)
        except FileNotFoundError: pass
        open(p, "w", encoding="utf-8").close()

def append_pair(model_input, label_c_code):
    asm  = _one_line(model_input)
    lbl  = _compact_label(label_c_code)
    if not asm or not lbl:
        print(f"[SKIP] asm_len={len(asm)} label_len={len(lbl)}"); sys.stdout.flush()
        return False

    with open(ASSEMBLY_TXT_PATH, "a", encoding="utf-8") as af:
        af.write(asm + "\n")
        af.flush()
        os.fsync(af.fileno())

    with open(FUNCTION_TXT_PATH, "a", encoding="utf-8") as ff:
        ff.write(lbl + "\n")
        ff.flush()
        os.fsync(ff.fileno())

    print(f"[OK {time.strftime('%H:%M:%S')}] wrote pair: asm={len(asm)} chars, lbl={len(lbl)} chars")
    sys.stdout.flush()
    return True

def build_sample(mode="train"):
    """
    mode:
    'train' - build sample for training
    'infer' - build sample for inference
    """
    project, cfg = load_project(TARGET_BINARY_PATH)
    if project is None or cfg is None:
        print("Failed to load the binary project or CFG.")
        return

    target_func = next(cfg.functions.get_by_name(TARGET_FUNCTION_NAME), None)
    if target_func is None:
        print(f"Function '{TARGET_FUNCTION_NAME}' not found.")
        return

    TARGET_FUNC_ADDR = target_func.addr
    all_functions_map = {func.addr: func for func in cfg.functions.values()}
    print(f"\n--- Target function identified: '{TARGET_FUNCTION_NAME}' at {hex(target_func.addr)} ---")

    context_candidates = get_context_candidates_with_degrees(target_func, cfg)
    caller_degrees = context_candidates['callers']
    callee_degrees = context_candidates['callees']

    candidate_funcs = (
        [(func, degree, 'caller') for func, degree in caller_degrees.items()] +
        [(func, degree, 'callee') for func, degree in callee_degrees.items()]
    )

    print("\n--- Context Analysis (Generation 1) ---")
    print(f"Found {len(context_candidates['callers'])} unique calling function(s):")
    for caller in sorted(list(context_candidates['callers']), key=lambda f: f.name):
        print(f"  - '{caller.name}'")
        
    print(f"\nFound {len(context_candidates['callees'])} unique called function(s):")
    for callee in sorted(list(context_candidates['callees']), key=lambda f: f.name):
        print(f"  - '{callee.name}'")

    seen_addresses = set()
    deduped_candidates = []
    for func, degree, role in candidate_funcs:
        if func.addr not in seen_addresses:
            deduped_candidates.append((func, degree, role))
            seen_addresses.add(func.addr)

    candidate_funcs_filtered = filter_candidate_funcs_runtime_safe(deduped_candidates, target_func)
    print(f"\nAfter runtime-safe filtering, {len(candidate_funcs_filtered)} candidate functions remain...")

    candidate_func_data = build_candidate_func_data(candidate_funcs_filtered, project, cfg, MYTOKENIZER)

    print("\n--- Extracting Assembly Code ---")

    target_func_data = get_function_data(target_func, project, MYTOKENIZER)
    context_funcs = apply_heuristic(
        target_func_data,
        candidate_func_data,
        CONTEXT_THRESHOLD_TOKENS,
        cfg.functions.callgraph,
        all_functions_map,
        TARGET_FUNC_ADDR,
        project,
        mode
    )

    header_block = build_header_block_from_binary(TARGET_BINARY_PATH)

    model_input_str = build_prompt_and_write_debug(
        target_func_data,
        context_funcs,
        header_block=header_block,
        write_debug_files=WRITE_DEBUG_FILES,
    )

    const_pool_target = collect_constant_pool_for_function(target_func, project)

    formatted_input = normalize_model_input_with_context_groups(
        raw_text=model_input_str,
        project=project,
        target_func_obj=target_func,
        const_pool_for_target=const_pool_target
    )

    sample = {
        "binary_path": TARGET_BINARY_PATH,
        "target_function_name": TARGET_FUNCTION_NAME,
        "model_input": formatted_input,
    }

    if mode == "train":
        real_src = real_c_code_lookup(target_func, project)

        dwarf_lookup = build_dwarf_lookup_for_repo(os.path.dirname(TARGET_BINARY_PATH))

        final_label = finalize_label_for_training(
            getattr(target_func, "name", None),
            real_src,
            const_pool_target,
            dwarf_lookup
        )

        if final_label is None:
            final_label = "/* NO_GROUND_TRUTH_AVAILABLE */"

        sample["label_c_code"] = final_label
        sample["context_role"] = "train"

    elif mode == "infer":
        sample["context_role"] = "inference"

    else:
        print(f"[WARN] Unknown mode '{mode}', defaulting to inference semantics.")
        sample["context_role"] = "inference"

    return sample

def main():

    result = build_sample(
        mode="train"
    )

    if result is None:
        return
    
    init_pair_files()

    append_pair(model_input=result['model_input'], label_c_code=result['label_c_code'])

    print("\n--- Final Transformer Input ---")
    print(f"ContextRole: {result['context_role']}")
    print(f"Target function: {result['target_function_name']}")
    print(f"Input tokens preview:\n{result['model_input']}")
    if "label_c_code" in result:
        print(f"\nLabel preview:\n{result['label_c_code']}")

if __name__ == "__main__":
    main()
    
