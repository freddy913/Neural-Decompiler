from config import (
    TARGET_BINARY_PATH,
    TARGET_FUNCTION_NAME,
    CONTEXT_THRESHOLD_TOKENS,
    MYTOKENIZER,
) 

from heuristic import real_c_code_lookup
from dwarf_labeling import (
    build_dwarf_lookup_for_repo,
    collect_constant_pool_for_function,
    finalize_label_for_training,
    pick_best_match
)

from binary_analysis import load_project, get_function_data
from candidate_selection import (
    get_context_candidates_with_degrees,
    remove_junk_functions,
    filter_candidate_funcs_runtime_safe,
    build_candidate_func_data,
)

from heuristic import apply_heuristic
from prompt_build import build_prompt_and_write_debug
from header_inference import build_header_block_from_binary

import os

def pick_best_match(candidates, executable_path):
    exec_dir = os.path.dirname(executable_path)
    def distance(cand):
        o_dir = os.path.dirname(cand["o_path"])
        rel = os.path.relpath(o_dir, exec_dir)
        depth = rel.count(os.sep)
        return depth
    return sorted(candidates, key=distance)[0] if candidates else None

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

    context_candidates = get_context_candidates_with_degrees(target_func, cfg, 2)
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

    # candidate_funcs_filtered = remove_junk_functions(candidate_funcs)
    candidate_funcs_filtered = filter_candidate_funcs_runtime_safe(deduped_candidates, target_func)
    print(f"\nAfter filtering junk functions, {len(candidate_funcs_filtered)} candidate functions remain for context consideration.")

    candindate_func_data = build_candidate_func_data(candidate_funcs_filtered, project, cfg, MYTOKENIZER)

    print("\n--- Extracting Assembly Code ---")

    target_func_data = get_function_data(target_func, project, MYTOKENIZER)
    context_funcs = apply_heuristic(
        target_func_data,
        candindate_func_data,
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
        write_debug_files=True,
    )

    sample = {
        "binary_path": TARGET_BINARY_PATH,
        "target_function_name": TARGET_FUNCTION_NAME,
        "model_input": model_input_str,
    }

    if mode == "train":
        real_src = real_c_code_lookup(target_func, project)

        dwarf_lookup = build_dwarf_lookup_for_repo(os.path.dirname(TARGET_BINARY_PATH))

        const_pool = collect_constant_pool_for_function(target_func, project)

        final_label = finalize_label_for_training(
            getattr(target_func, "name", None),
            real_src,
            const_pool,
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

    print("\n--- Final Transformer Input ---")
    print(f"ContextRole: {result['context_role']}")
    print(f"Target function: {result['target_function_name']}")
    # print(f"Input tokens preview:\n{result['model_input'][:500]}")
    # if "label_c_code" in result:
    #     print(f"\nLabel preview:\n{result['label_c_code'][:200]}")
    print(f"Input tokens preview:\n{result['model_input']}")
    if "label_c_code" in result:
        print(f"\nLabel preview:\n{result['label_c_code']}")

if __name__ == "__main__":
    main()
    
