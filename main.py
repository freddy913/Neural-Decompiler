from config import (
    TARGET_BINARY_PATH,
    TARGET_FUNCTION_NAME,
    CONTEXT_THRESHOLD_TOKENS,
    MYTOKENIZER,
)

from binary_analysis import load_project, get_function_data
from candidate_selection import (
    get_context_candidates_with_degrees,
    remove_junk_functions,
    build_candidate_func_data,
)

from heuristic import apply_heuristic
from prompt_build import build_prompt_and_write_debug

def main():
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

    candidate_funcs_filtered = remove_junk_functions(candidate_funcs)
    print(f"\nAfter filtering junk functions, {len(candidate_funcs_filtered)} candidate functions remain for context consideration.")

    candindate_func_data = build_candidate_func_data(candidate_funcs_filtered, project, cfg, MYTOKENIZER)

    print("\n--- Extracting Assembly Code ---")

    target_func_data = get_function_data(target_func, project, MYTOKENIZER)
    with open("target_assembly.txt", "w", encoding="utf-8") as f:
        f.write(target_func_data['assembly'])

    context_funcs = apply_heuristic(
        target_func_data,
        candindate_func_data,
        CONTEXT_THRESHOLD_TOKENS,
        cfg.functions.callgraph,
        all_functions_map,
        TARGET_FUNC_ADDR
    )

    final_prompt = build_prompt_and_write_debug(
        target_func_data,
        context_funcs,
        target_func_name_for_header=TARGET_FUNCTION_NAME,
        write_debug_files=True
    )

    print("\n--- Final Transformer Input ---")
    print(f"Context segments included: {len(context_funcs)}")
    print("Combined input saved to 'final_model_input.txt'")

if __name__ == "__main__":
    main()
    