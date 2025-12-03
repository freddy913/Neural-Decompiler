import argparse
import json
import os, re, sys, time
import random

import Config

from Config import (
    TARGET_BINARY_PATH,
    TARGET_FUNCTION_NAME,
    CONTEXT_THRESHOLD_TOKENS,
    MYTOKENIZER,
    WRITE_DEBUG_FILES,
    FUNCTION_TXT,
    ASSEMBLY_TXT,
    USE_ASSEMBLY_ONLY,
)

from Heuristic import (
    get_real_c_code,
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
PAIR_JSONL_PATH = None
CHUNK_STATE_ROOT = os.path.join(".", "CHUNK_STATE")

def compute_context_budget(target_token_count):
    """
    Nonlinear context budget based on decompilation and RAG literature. (!!8K Encoder)
    """
    if target_token_count <= 128:
        return 1000
    elif target_token_count <= 256:
        return 1500
    elif target_token_count <= 512:
        return 2500
    elif target_token_count <= 1024:
        return 3500
    elif target_token_count <= 2000:
        return 5000
    else:
        return 6500

def get_token_length_of_entry(entry, tokenizer):
    if "token_count" in entry and entry["token_count"] is not None:
        return entry["token_count"]
    # fallback: use raw tokenizer length of assembly
    asm = entry.get("assembly", "")
    return len(tokenizer(asm, truncation=False)["input_ids"])

def _binary_slug_from_path(binary_path: str) -> str:
    """
    Create a slug from the last two path components of the binary path.
    Falls back to the last component and finally to 'sample' if unavailable.
    """
    normalized = os.path.normpath(binary_path or "")
    parts = [part for part in normalized.split(os.sep) if part]
    if not parts:
        return "sample"

    last_part = parts[-1]
    base_name, extension = os.path.splitext(last_part)
    last_component = base_name if extension else last_part

    if len(parts) >= 2:
        return f"{parts[-2]}_{last_component}"

    return last_component or "sample"


def _ensure_pair_jsonl_path() -> str:
    """Resolve and cache the JSONL path for the current binary/function."""
    global PAIR_JSONL_PATH
    if PAIR_JSONL_PATH:
        return PAIR_JSONL_PATH

    slug = _binary_slug_from_path(TARGET_BINARY_PATH)
    function_name = TARGET_FUNCTION_NAME or "target"
    random_suffix = random.randint(0, 99)
    filename = f"{slug}_{function_name}_{random_suffix}.jsonl"
    PAIR_JSONL_PATH = os.path.join(INPUT_DIR, filename)
    return PAIR_JSONL_PATH



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

    context_funcs = context_funcs or []

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
    global PAIR_JSONL_PATH
    PAIR_JSONL_PATH = None

def _append_pair_jsonl(asm_payload: str, lbl_payload: str):
    """Append the provided pair as a JSONL entry."""
    payload = {"input": asm_payload, "output": lbl_payload}
    jsonl_path = _ensure_pair_jsonl_path()
    os.makedirs(os.path.dirname(jsonl_path), exist_ok=True)
    with open(jsonl_path, "a", encoding="utf-8") as pf:
        json.dump(payload, pf)
        pf.write("\n")

def append_pair(model_input, label_c_code):
    asm  = _one_line(model_input)
    lbl_full = (label_c_code or "").strip()
    lbl_preview = _compact_label(label_c_code)
    if not asm or not lbl_full:
        print(f"[SKIP] asm_len={len(asm)} label_len={len(lbl_full)}"); sys.stdout.flush()
        return False

    with open(ASSEMBLY_TXT_PATH, "a", encoding="utf-8") as af:
        af.write(asm + "\n")
        af.flush()
        os.fsync(af.fileno())

    with open(FUNCTION_TXT_PATH, "a", encoding="utf-8") as ff:
        ff.write(lbl_full + "\n\n")
        ff.flush()
        os.fsync(ff.fileno())

    _append_pair_jsonl(asm, lbl_full)

    print(f"[OK {time.strftime('%H:%M:%S')}] wrote pair: asm={len(asm)} chars, lbl={len(lbl_full)} chars")
    if lbl_preview and lbl_preview != lbl_full:
        print(f"         label preview: {lbl_preview[:96]}{'…' if len(lbl_preview) > 96 else ''}")
    sys.stdout.flush()
    return True

def build_sample(mode="train", UseContext="false", source_hint=None, dwarf_lookup=None):
    """
    mode:
    'train' - build sample for training
    'test' - build test sample for inference
    """
    if not os.path.isfile(TARGET_BINARY_PATH):
        print(f"[ERR] Binary '{TARGET_BINARY_PATH}' not found. Build/compile the target before running build_sample.")
        return

    project, cfg = load_project(TARGET_BINARY_PATH)

    if project is None or cfg is None:
        print("Failed to load the binary project or CFG.")
        return

    # TODO: rewind if addr2line is still needed and what target_src_loc is used for
    addr2line = build_addr2line_resolver(TARGET_BINARY_PATH)
    ####

    target_func = next(cfg.functions.get_by_name(TARGET_FUNCTION_NAME), None)
    target_src_loc = addr2line(target_func.addr) if target_func else None

    if target_func is None:
        print(f"Function '{TARGET_FUNCTION_NAME}' not found.")
        return

    target_func_data = get_function_data(target_func, project, MYTOKENIZER)
    # if target func token size > CONTEXT_THRESHOLD_TOKENS: break from here; no decompilation possible
    if target_func_data.get("token_count", 0) > CONTEXT_THRESHOLD_TOKENS:
        print(f"[WARN] Target function token count {target_func_data.get('token_count')} exceeds context threshold {CONTEXT_THRESHOLD_TOKENS}. Skipping sample generation.")
        return
    
    header_block = build_header_block_from_binary(TARGET_BINARY_PATH)
    if header_block:
        header_tokens = len(MYTOKENIZER(header_block, truncation=False)["input_ids"])
    else:
        header_tokens = 0

    target_tokens = target_func_data.get("token_count", 0)
    def _compute_context_budget(target_token_count):
        if target_token_count <= 128:
            return 1000
        elif target_token_count <= 256:
            return 1500
        elif target_token_count <= 512:
            return 2500
        elif target_token_count <= 1024:
            return 3500
        elif target_token_count <= 2000:
            return 5000
        else:
            return 6500

    raw_context_budget = compute_context_budget(target_tokens)
    MARKER_BUFFER_TOKENS = 128
    max_budget = CONTEXT_THRESHOLD_TOKENS - target_tokens - header_tokens - MARKER_BUFFER_TOKENS
    max_budget = max(0, max_budget)
    context_budget = min(raw_context_budget, max_budget)
    
    TARGET_FUNC_ADDR = target_func.addr
    all_functions_map = {func.addr: func for func in cfg.functions.values()}
    print(f"\n--- Target function identified: '{TARGET_FUNCTION_NAME}' at {hex(target_func.addr)} ---")

    # TODO: rewind if dwarf_lookup is still needed
    dwarf_ref = dwarf_lookup
    if mode == "train" and dwarf_ref is None:
        dwarf_ref = build_dwarf_lookup_for_repo(os.path.dirname(TARGET_BINARY_PATH))
    ####

    if UseContext == "true":
        context_funcs = get_context_candidates_with_degrees(target_func, cfg)
        caller_degrees = context_funcs['callers']
        callee_degrees = context_funcs['callees']

        context_candidates = (
            [(func, degree, 'caller') for func, degree in caller_degrees.items()] +
            [(func, degree, 'callee') for func, degree in callee_degrees.items()]
        )

        print("\n--- Context Analysis (Generation 1) ---")
        print(f"Found {len(context_funcs['callers'])} unique calling function(s):")
        for caller in sorted(list(context_funcs['callers']), key=lambda f: f.name):
            print(f"  - '{caller.name}'")
            
        print(f"\nFound {len(context_funcs['callees'])} unique called function(s):")
        for callee in sorted(list(context_funcs['callees']), key=lambda f: f.name):
            print(f"  - '{callee.name}'")

        seen_addresses = set()
        deduped_candidates = []
        for func, degree, role in context_candidates:
            if func.addr not in seen_addresses:
                deduped_candidates.append((func, degree, role))
                seen_addresses.add(func.addr)

        candidate_funcs_filtered = filter_candidate_funcs_runtime_safe(deduped_candidates, target_func)
        print(f"\nAfter runtime-safe filtering, {len(candidate_funcs_filtered)} candidate functions remain...")

        candidate_func_data = build_candidate_func_data(candidate_funcs_filtered, project, cfg, MYTOKENIZER)

        print("\n--- Extracting Assembly Code ---")

        for entry in candidate_func_data["all_functions"]:
            fobj = entry["function_obj"]
            entry["src_loc"] = addr2line(fobj.addr)
            
        context_funcs = apply_heuristic(
            target_func_data,
            candidate_func_data,
            context_budget,
            cfg.functions.callgraph,
            all_functions_map,
            TARGET_FUNC_ADDR,
            project,
            mode,
            dwarf_lookup=dwarf_ref,
            target_src_loc=target_src_loc,
            assembly_only=USE_ASSEMBLY_ONLY,
        ) or []

        

    ## TODO: REMOVE CHUNKPLAN BECAUSE WE DONT CHUNK 
    #chunk_plan = target_func_data.get("chunk_plan")
    chunk_plan = None
    #chunk_strategy = target_func_data.get("chunk_strategy")
    chunk_strategy = None
    ####
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

    ## TODO: REMOVE CHUNKPLAN BECAUSE WE DONT CHUNK
    if chunk_plan:
        sample["chunk_plan"] = chunk_plan
    if chunk_strategy:
        sample["chunk_strategy"] = chunk_strategy
    ####

    if mode == "train":
        real_src = get_real_c_code(
            target_func,
            project,
            purpose="target",
            source_hint=source_hint,
            dwarf_lookup=dwarf_ref,
        )

        formatted_output = finalize_label_for_training(
            getattr(target_func, "name", None),
            real_src,
            const_pool_target,
            dwarf_ref
        )

        if formatted_output is None:
            formatted_output = "/* NO_GROUND_TRUTH_AVAILABLE */"

        sample["label_c_code"] = formatted_output
        sample["context_role"] = "train"

    elif mode == "test":
        sample["context_role"] = "test"

    else:
        print(f"[WARN] Unknown mode '{mode}', defaulting to inference semantics.")
        sample["context_role"] = "test"

    return sample

def _set_target_config(binary_path, function_name):
    Config.TARGET_BINARY_PATH = binary_path
    Config.TARGET_FUNCTION_NAME = function_name

    global TARGET_BINARY_PATH, TARGET_FUNCTION_NAME, PAIR_JSONL_PATH
    TARGET_BINARY_PATH = binary_path
    TARGET_FUNCTION_NAME = function_name
    PAIR_JSONL_PATH = None

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
        choices=["train", "test"],
        default="train",
        help="Mode: train for dataset generation, test for analysis",
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
        "--source-path",
        type=str,
        default=None,
        help="Optional path hint to the original source file for the target function",
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

    parser.add_argument(
        "--UseContext",
        choices=["true", "false"],
        default="true",
        help="Use Context: 'true' for adding context to the input string, 'false' for only the target as input"
    )

    parser.add_argument(
        "--worklist",
        type=str,
        default=None,
        help="Optional TSV file: each line 'ABS_BINARY_PATH<TAB>FUNCTION_NAME'"
    )

    args = parser.parse_args()

    mode = args.mode
    UseContext = args.UseContext
    source_hint_arg = args.source_path

    # ========= NEU: batch + worklist =========
    if args.batch and args.worklist:
        # wir verarbeiten DEINE liste, nicht den festen COMPILED/ baum
        if mode == "train":
            init_pair_files()

        with open(args.worklist, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]

        processed = 0
        successes = 0
        for line in lines:
            processed += 1
            # Format: /abs/path/to/executable0<TAB>funcname
            parts = line.split("\t")
            bin_path = parts[0]
            func_name = parts[1] if len(parts) > 1 and parts[1] else args.function_name

            print(f"\n=== [{processed}] Processing {bin_path} :: {func_name} ===")
            try:
                _set_target_config(bin_path, func_name)
                result = build_sample(mode=mode, UseContext=UseContext, source_hint=source_hint_arg)
            except Exception as exc:
                print(f"[WARN] Failed to process '{bin_path}' / '{func_name}': {exc}")
                continue

            if result is None:
                print(f"[WARN] build_sample returned no result.")
                continue

            if mode == "train":
                label = result.get("label_c_code")
                if not label:
                    print(f"[WARN] no label generated; skipping pair write.")
                    continue
                append_pair(model_input=result["model_input"], label_c_code=label)

            successes += 1

        print(f"\nBatch (worklist) complete. Succeeded: {successes}/{processed}")
        return
    # ========= ENDE NEU =========

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
                result = build_sample(mode=mode, UseContext=UseContext, source_hint=source_hint_arg)
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

    result = build_sample(mode=mode, UseContext=UseContext, source_hint=source_hint_arg)

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
        print("\n--- Test Mode Output ---")
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
