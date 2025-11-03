import argparse
import json
import os, re, sys, time

import Config

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

from AddrMap import build_addr2line_resolver

INPUT_DIR = os.path.join(".", "INPUT")
FUNCTION_TXT_PATH = os.path.join(INPUT_DIR, FUNCTION_TXT)
ASSEMBLY_TXT_PATH = os.path.join(INPUT_DIR, ASSEMBLY_TXT)
CHUNK_STATE_ROOT = os.path.join(".", "CHUNK_STATE")

def _chunk_slug(value):
    if not value:
        return "target"
    return re.sub(r"[^0-9A-Za-z_]+", "_", value)

def persist_chunk_state(sample):
    chunk_plan = sample.get("chunk_plan") or []
    if not chunk_plan:
        return None

    target_slug = _chunk_slug(sample.get("target_function_name"))
    binary_path = sample.get("binary_path")
    try:
        rel_bin = os.path.relpath(binary_path) if binary_path else None
    except Exception:
        rel_bin = binary_path
    binary_slug = _chunk_slug(rel_bin) if rel_bin else "binary"
    slug = f"{target_slug}__{binary_slug}"
    state_dir = os.path.join(CHUNK_STATE_ROOT, slug)
    os.makedirs(state_dir, exist_ok=True)

    state_payload = {
        "binary_path": sample.get("binary_path"),
        "target_function": sample.get("target_function_name"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "chunk_strategy": sample.get("chunk_strategy"),
        "slug": slug,
        "expected_output_files": [f"{entry.get('name')}.c" for entry in chunk_plan],
        "chunks": [
            {
                "index": entry.get("index"),
                "name": entry.get("name"),
                "token_count": entry.get("token_count"),
                "assembly_file": f"{entry.get('name')}_assembly.txt",
            }
            for entry in chunk_plan
        ],
    }

    state_path = os.path.join(state_dir, "chunk_state.json")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state_payload, f, indent=2)

    for entry in chunk_plan:
        assembly_path = os.path.join(state_dir, f"{entry['name']}_assembly.txt")
        with open(assembly_path, "w", encoding="utf-8") as af:
            af.write(entry["assembly"])

    return state_path

def combine_chunk_outputs(chunk_plan, outputs_dir, target_name, binary_path=None, output_dir=None):
    if not chunk_plan or not outputs_dir:
        return None

    if not os.path.isdir(outputs_dir):
        print(f"[WARN] Chunk output directory '{outputs_dir}' does not exist.")
        return None

    target_slug = _chunk_slug(target_name)
    try:
        rel_bin = os.path.relpath(binary_path) if binary_path else None
    except Exception:
        rel_bin = binary_path
    binary_slug = _chunk_slug(rel_bin) if rel_bin else None
    slug = f"{target_slug}__{binary_slug}" if binary_slug else target_slug

    if output_dir is None:
        output_dir = outputs_dir
    os.makedirs(output_dir, exist_ok=True)

    combined_parts = []
    missing = []

    for entry in chunk_plan:
        expected_file = f"{entry['name']}.c"
        chunk_path = os.path.join(outputs_dir, expected_file)
        if not os.path.exists(chunk_path):
            missing.append(expected_file)
            continue
        with open(chunk_path, "r", encoding="utf-8", errors="ignore") as cf:
            combined_parts.append(cf.read().strip())

    if not combined_parts:
        print("[WARN] No chunk outputs were found to combine.")
        if missing:
            print(f"[WARN] Missing chunk outputs: {', '.join(missing)}")
        return None

    combined_path = os.path.join(output_dir, f"{slug}_combined.c")
    with open(combined_path, "w", encoding="utf-8") as out_f:
        out_f.write("\n\n".join(part for part in combined_parts if part))

    if missing:
        print(f"[WARN] Missing chunk outputs: {', '.join(missing)}")

    return combined_path

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

    addr2line = build_addr2line_resolver(TARGET_BINARY_PATH)


    target_func = next(cfg.functions.get_by_name(TARGET_FUNCTION_NAME), None)
    target_src_loc = addr2line(target_func.addr) if target_func else None

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

    for entry in candidate_func_data["all_functions"]:
        fobj = entry["function_obj"]
        entry["src_loc"] = addr2line(fobj.addr)

    context_funcs = apply_heuristic(
        target_func_data,
        candidate_func_data,
        CONTEXT_THRESHOLD_TOKENS,
        cfg.functions.callgraph,
        all_functions_map,
        TARGET_FUNC_ADDR,
        project,
        mode,
        target_src_loc=target_src_loc,
    )
    context_funcs = context_funcs or []

    chunk_plan = target_func_data.get("chunk_plan")
    chunk_strategy = target_func_data.get("chunk_strategy")

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

    if chunk_plan:
        sample["chunk_plan"] = chunk_plan
    if chunk_strategy:
        sample["chunk_strategy"] = chunk_strategy

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

def _set_target_config(binary_path, function_name):
    Config.TARGET_BINARY_PATH = binary_path
    Config.TARGET_FUNCTION_NAME = function_name

    global TARGET_BINARY_PATH, TARGET_FUNCTION_NAME
    TARGET_BINARY_PATH = binary_path
    TARGET_FUNCTION_NAME = function_name

def _iter_compiled_binaries(compiled_root):
    if not os.path.isdir(compiled_root):
        print(f"[WARN] Compiled directory '{compiled_root}' does not exist.")
        return

    for repo_name in sorted(os.listdir(compiled_root)):
        repo_path = os.path.join(compiled_root, repo_name)
        if not os.path.isdir(repo_path):
            continue

        for root, _, files in os.walk(repo_path):
            for fname in sorted(files):
                if re.match(r"^executable\d+$", fname):
                    yield repo_name, os.path.join(root, fname)
            # executables are expected directly under repo subdirectories; no need to walk deeper
            break

def main():
    parser = argparse.ArgumentParser(description="Run decompiler pipeline")
    parser.add_argument(
        "--mode",
        choices=["train", "infer"],
        default="train",
        help="Mode: train for dataset generation, infer for analysis",
    )
    parser.add_argument(
        "--binary-path",
        type=str,
        default=Config.TARGET_BINARY_PATH,
        help="Path to the target binary",
    )
    parser.add_argument(
        "--function-name",
        type=str,
        default=Config.TARGET_FUNCTION_NAME,
        help="Name of the target function in the binary",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Process all binaries inside the COMPILED directory (train mode recommended)",
    )
    parser.add_argument(
        "--chunk-output-dir",
        type=str,
        default=None,
        help="Optional directory containing per-chunk C outputs to merge after inference.",
    )

    args = parser.parse_args()

    mode = args.mode

    if args.batch:
        compiled_root = os.path.join(os.path.dirname(__file__), "COMPILED")

        if mode == "train":
            init_pair_files()

        processed = 0
        successes = 0

        for repo_name, binary_path in _iter_compiled_binaries(compiled_root):
            processed += 1
            print(f"\n=== [{processed}] Processing {repo_name}: {binary_path} ===")
            try:
                _set_target_config(binary_path, args.function_name)
                result = build_sample(mode=mode)
            except Exception as exc:
                print(f"[WARN] Failed to process '{binary_path}': {exc}")
                continue

            if result is None:
                print(f"[WARN] Skipping '{binary_path}': build_sample returned no result.")
                continue

            chunk_state_path = None
            chunk_plan = result.get("chunk_plan")
            if chunk_plan:
                chunk_state_path = persist_chunk_state(result)
                if chunk_state_path:
                    print(f"[Chunk] State saved to {chunk_state_path}")
                expected_files = ", ".join(f"{entry['name']}.c" for entry in chunk_plan)
                if expected_files:
                    print(f"[Chunk] Expected output files: {expected_files}")
                if args.chunk_output_dir:
                    combined_path = combine_chunk_outputs(
                        chunk_plan,
                        args.chunk_output_dir,
                        result.get("target_function_name"),
                        binary_path=result.get("binary_path"),
                        output_dir=args.chunk_output_dir,
                    )
                    if combined_path:
                        print(f"[Chunk] Combined output saved to {combined_path}")

            if mode == "train":
                label = result.get('label_c_code')
                if not label:
                    print(f"[WARN] Skipping '{binary_path}': no label generated in train mode.")
                    continue
                append_pair(model_input=result['model_input'], label_c_code=label)
                successes += 1
            else:
                print(f"ContextRole: {result['context_role']}")
                print(f"Target function: {result['target_function_name']}")
                print(f"Model input:\n{result['model_input']}")
                successes += 1

        print(f"\nBatch processing complete. Succeeded: {successes}/{processed}")
        return

    _set_target_config(args.binary_path, args.function_name)

    result = build_sample(mode=mode)

    if result is None:
        return

    chunk_plan = result.get("chunk_plan")
    chunk_state_path = None
    if chunk_plan:
        chunk_state_path = persist_chunk_state(result)

    if mode == "train":
        init_pair_files()
        label = result.get('label_c_code')
        if not label:
            print("[WARN] No label generated in train mode; skipping pair write.")
            return

        append_pair(model_input=result['model_input'], label_c_code=label)

        print("\n--- Final Transformer Input ---")
        print(f"ContextRole: {result['context_role']}")
        print(f"Target function: {result['target_function_name']}")
        print(f"Input tokens preview:\n{result['model_input']}")
        print(f"\nLabel preview:\n{label}")
    else:
        print("\n--- Inference Mode Output ---")
        print(f"ContextRole: {result['context_role']}")
        print(f"Target function: {result['target_function_name']}")
        print(f"Model input:\n{result['model_input']}")

    if chunk_plan:
        print("\n--- Chunk Plan ---")
        for entry in chunk_plan:
            print(f"Part {entry['index']}: {entry['token_count']} tokens -> {entry['name']}")
        if chunk_state_path:
            print(f"Chunk state saved to: {chunk_state_path}")
        if args.chunk_output_dir:
            combined_path = combine_chunk_outputs(
                chunk_plan,
                args.chunk_output_dir,
                result.get("target_function_name"),
                binary_path=result.get("binary_path"),
            )
            if combined_path:
                print(f"Combined chunk output written to: {combined_path}")
        expected_files = ", ".join(f"{entry['name']}.c" for entry in chunk_plan)
        print(f"Expected chunk output files (for AI results): {expected_files}")

if __name__ == "__main__":
    main()
    
