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
    VERBOSE,
)

from Heuristic import (
    get_real_c_code,
    apply_heuristic,
    get_context_candidates_with_degrees,
    filter_candidate_funcs_runtime_safe,
    build_candidate_func_data,
    build_header_block_from_binary,
    is_relevant_user_like_function,
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
MARKER_BUFFER_TOKENS = 128

class MockProject:
    def __init__(self, binary_path):
        self.filename = binary_path
        # Dummy loader for robustness in case get_real_c_code accesses it
        self.loader = type('obj', (object,), {'main_object': type('obj', (object,), {'binary': binary_path})})

class MockFunction:
    def __init__(self, name):
        self.name = name
        self.addr = 0   # Dummy address

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

# TODO: not used?
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

def _ensure_pair_jsonl_path(binary_path: str, function_name: str) -> str:
    """Resolve and cache the JSONL path for the current binary/function."""
    # global PAIR_JSONL_PATH
    # if PAIR_JSONL_PATH:
    #     return PAIR_JSONL_PATH

    slug = _binary_slug_from_path(binary_path)
    function_slug = function_name or "target"
    random_suffix = random.randint(0, 999)
    filename = f"{slug}_{function_slug}_{random_suffix}.jsonl"
    PAIR_JSONL_PATH = os.path.join(INPUT_DIR, filename)
    return PAIR_JSONL_PATH

def write_debug_artifacts(
    target_func_data,
    context_funcs,
    header_block
):
    """
    Writes debug files to disk so humans can inspect the context selection.
    Does NOT affect the actual model input anymore.
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

        if not code: continue

        block_tuple = (name, code.strip())  
        if role == 'caller':
            callers_block.append(block_tuple)
        else:
            callees_block.append(block_tuple)
            
    parts = []
    
    if header_block:
        parts.append("--- HEADER BLOCK ---")
        parts.append(header_block.rstrip())

    parts.append(f"\n--- TARGET FUNCTION: {target_name} ---")
    parts.append(target_segment)

    if callers_block:
        parts.append(f"\n--- CALLERS ({len(callers_block)}) ---")
        for nm, cd in callers_block:
            parts.append(f"// Function: {nm}\n{cd}")

    if callees_block:
        parts.append(f"\n--- CALLEES ({len(callees_block)}) ---")
        for nm, cd in callees_block:
            parts.append(f"// Function: {nm}\n{cd}")

    human_readable_prompt = "\n".join(parts) + "\n"

    try:
        os.makedirs("DEBUG", exist_ok=True)
        with open("DEBUG/selected_context_functions.txt", "w", encoding="utf-8") as f:
            for entry in context_funcs:
                name = entry.get('name', 'unknown_function')
                degree = entry.get('degree', 'n/a')
                role = entry.get('role', 'context')
                mode = entry.get('append_mode', 'assembly')
                score = entry.get('score', 0)
                f.write(f"Function: {name:<30} | Role: {role:<8} | Deg: {degree} | Score: {score} | Mode: {mode}\n")
            f.write("\n")

        with open("DEBUG/final_model_input.txt", "w", encoding="utf-8") as f:
            f.write(human_readable_prompt)

        with open("DEBUG/target_assembly.txt", "w", encoding="utf-8") as f:
            f.write(target_segment)
            
    except Exception as e:
        print(f"[WARN] write debug files failed: {e}")

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

def _append_pair_jsonl(asm_payload: str, lbl_payload: str, jsonl_path: str):
    """Append the provided pair as a JSONL entry."""
    payload = {"input": asm_payload, "output": lbl_payload}
    #jsonl_path = _ensure_pair_jsonl_path()
    os.makedirs(os.path.dirname(jsonl_path), exist_ok=True)
    with open(jsonl_path, "a", encoding="utf-8") as pf:
        json.dump(payload, pf)
        pf.write("\n")

def append_pair(model_input, label_c_code, jsonl_path=None):
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

    if jsonl_path is None:
        jsonl_path = _ensure_pair_jsonl_path()
    _append_pair_jsonl(asm, lbl_full, jsonl_path=jsonl_path)

    if VERBOSE: print(f"[OK {time.strftime('%H:%M:%S')}] wrote pair: asm={len(asm)} chars, lbl={len(lbl_full)} chars")
    if lbl_preview and lbl_preview != lbl_full:
        print(f"         label preview: {lbl_preview[:96]}{'…' if len(lbl_preview) > 96 else ''}")
    sys.stdout.flush()
    return True

def _generate_input_from_binary(binary_path, function_name, UseContext="true"):
    """
    This function is the deterministic core of the pipeline.
    It takes a binary path and function name and ALWAYS produces the same input string.
    No 'mode', no label lookup.
    """
    
    project, cfg = load_project(binary_path)
    if not project or not cfg:
        print(f"[WARN] Angr fails at {binary_path}")
        return None

    target_func = next(cfg.functions.get_by_name(function_name), None)
    if not target_func or not is_relevant_user_like_function(target_func):
        return None

    target_func_data = get_function_data(target_func, project, MYTOKENIZER)
    target_tokens = target_func_data.get("token_count", 0)
    if target_tokens > CONTEXT_THRESHOLD_TOKENS:
        return None

    header_block = build_header_block_from_binary(binary_path)
    header_tokens = len(MYTOKENIZER(header_block, truncation=False)["input_ids"]) if header_block else 0
    
    context_budget_raw = compute_context_budget(target_tokens)
    max_budget = CONTEXT_THRESHOLD_TOKENS - target_tokens - header_tokens - MARKER_BUFFER_TOKENS
    context_budget = max(0, min(context_budget_raw, max_budget))

    context_funcs = []
    if UseContext == "true":
        all_functions_map = {func.addr: func for func in cfg.functions.values()}
        context_funcs_raw = get_context_candidates_with_degrees(target_func, cfg)
        
        context_candidates = []
        for func, degree in context_funcs_raw['callers'].items(): context_candidates.append((func, degree, 'caller'))
        for func, degree in context_funcs_raw['callees'].items(): context_candidates.append((func, degree, 'callee'))
        
        seen = set(); deduped = []
        for f,d,r in context_candidates:
            if f.addr not in seen: deduped.append((f,d,r)); seen.add(f.addr)
        
        filtered = filter_candidate_funcs_runtime_safe(deduped, target_func)
        candidate_data = build_candidate_func_data(filtered, project, cfg, MYTOKENIZER)
        
        context_funcs = apply_heuristic(
            target_func_data, candidate_data, context_budget,
            cfg.functions.callgraph, all_functions_map, target_func.addr,
            project, mode="test", assembly_only=True
        ) or []

    callers_asm = []
    callees_asm = []
    
    for entry in context_funcs:
        role = entry.get('role', 'context')
        if entry.get('append_mode') == 'c_approx' and entry.get('c_approx'):
            code = entry.get('c_approx') or ""
        else:
            code = entry.get('assembly') or ""
            
        if not code.strip(): continue
        
        if role == 'caller':
            callers_asm.append(code)
        else: 
            callees_asm.append(code)

    if WRITE_DEBUG_FILES:
        write_debug_artifacts(target_func_data, context_funcs, header_block)

    const_pool_target = collect_constant_pool_for_function(target_func, project)
    
    formatted_input = normalize_model_input_with_context_groups(
        target_asm=target_func_data.get('assembly', ''),
        caller_list=callers_asm,
        callee_list=callees_asm,
        header=header_block,
        project=project,
        target_func_obj=target_func,
        const_pool_for_target=const_pool_target
    )
    
    return formatted_input


def build_sample(binary_path: str, function_name: str, mode="train", UseContext="true", source_hint=None, dwarf_lookup=None):
    """
    Wrapper around the core function that handles mode (train/test).
    """

    if mode == "train":
        dwarf_ref = dwarf_lookup or build_dwarf_lookup_for_repo(os.path.dirname(binary_path))
        mock_proj = MockProject(binary_path)
        mock_func = MockFunction(function_name)
        
        check_src = get_real_c_code(
            mock_func, mock_proj, purpose="target", source_hint=source_hint, dwarf_lookup=dwarf_ref
        )
        
        if not check_src or "{" not in check_src.strip():
            if VERBOSE: print(f"[FAST-SKIP] No valid C source for '{function_name}'.")
            return None

    project, _ = load_project(binary_path)
    if not project:
        print(f"[WARN] Angr-Fehler bei {binary_path} (früher Check)")
        return None
        
    target_func = next(project.kb.functions.get_by_name(function_name), None)
    if not target_func:
        print(f"[WARN] Funktion {function_name} nicht gefunden.")
        return None

    const_pool_target = collect_constant_pool_for_function(target_func, project)

    model_input = _generate_input_from_binary(binary_path, function_name, UseContext)
    
    if not model_input:
        return None 

    sample = {
        "binary_path": binary_path,
        "target_function_name": function_name,
        "model_input": model_input,
        "context_role": mode,
        "constant_pool": const_pool_target
    }

    if mode == "train":
        formatted_output = finalize_label_for_training(
            function_name, check_src, const_pool_target, dwarf_ref
        )
        
        if not formatted_output:
            if VERBOSE: print("[SKIP] Final label validation failed.")
            return None
            
        sample["label_c_code"] = formatted_output

    return sample

# def _set_target_config(binary_path, function_name):
#     Config.TARGET_BINARY_PATH = binary_path
#     Config.TARGET_FUNCTION_NAME = function_name

#     global TARGET_BINARY_PATH, TARGET_FUNCTION_NAME, PAIR_JSONL_PATH
#     TARGET_BINARY_PATH = binary_path
#     TARGET_FUNCTION_NAME = function_name
#     PAIR_JSONL_PATH = None

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
            break

def main():
    parser = argparse.ArgumentParser(description="Run decompiler pipeline")
    parser.add_argument(
        "--mode",
        choices=["train", "test"],
        default="test",
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

    if args.batch and args.worklist:
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

            if VERBOSE: print(f"\n=== [{processed}] Processing {bin_path} :: {func_name} ===")
            #set config globally
            #_set_target_config(bin_path, func_name)
            try:
                result = build_sample(binary_path=bin_path, function_name= func_name, mode=mode, UseContext=UseContext, source_hint=source_hint_arg)
            except Exception as exc:
                if WRITE_DEBUG_FILES: print(f"[WARN] Failed to process '{bin_path}' / '{func_name}': {exc}")
                continue

            if result is None:
                if WRITE_DEBUG_FILES: print(f"[WARN] build_sample returned no result.")
                continue
            
            const_pool = result.get("constant_pool")
            jsonl_path = _ensure_pair_jsonl_path(bin_path, func_name)

            if const_pool:
                mapping = {}
                for info in const_pool.values():
                    placeholder, text = info.get("placeholder"), info.get("text")
                    if placeholder and text and placeholder.startswith(("STR", "FMT", "CMD")):
                        mapping[placeholder] = json.dumps(text)

                if mapping:
                    map_path = jsonl_path.replace(".jsonl", ".map.json")
                    os.makedirs(os.path.dirname(map_path), exist_ok=True)
                    with open(map_path, "w") as f:
                        json.dump(mapping, f, indent=2)

            if mode == "train":
                label = result.get("label_c_code")
                if not label:
                    if WRITE_DEBUG_FILES: print(f"[WARN] no label generated; skipping pair write.")
                    continue

                append_pair(model_input=result["model_input"], label_c_code=label, jsonl_path=jsonl_path)

            successes += 1

        if VERBOSE: print(f"\nBatch (worklist) complete. Succeeded: {successes}/{processed}")
        return

    if args.batch:
        compiled_root = os.path.join(os.path.dirname(__file__), "COMPILED")

        if mode == "train":
            init_pair_files()

        processed = 0
        successes = 0

        for repo_name, binary_path in _iter_compiled_binaries(compiled_root):
            processed += 1
            if VERBOSE: print(f"\n=== [{processed}] Processing {repo_name}: {binary_path} ===")
            #_set_target_config(binary_path, args.function_name)
            try:
                result = build_sample(binary_path=bin_path, function_name= func_name, mode=mode, UseContext=UseContext, source_hint=source_hint_arg)
            except Exception as exc:
                if WRITE_DEBUG_FILES: print(f"[WARN] Failed to process '{binary_path}': {exc}")
                continue

            if result is None:
                if WRITE_DEBUG_FILES: print(f"[WARN] Skipping '{binary_path}': build_sample returned no result.")
                continue

            const_pool = result.get("constant_pool")
            jsonl_path = _ensure_pair_jsonl_path(bin_path, func_name)

            if const_pool:
                mapping = {}
                for info in const_pool.values():
                    placeholder, text = info.get("placeholder"), info.get("text")
                    if placeholder and text and placeholder.startswith(("STR", "FMT", "CMD")):
                        mapping[placeholder] = json.dumps(text)

                if mapping:
                    map_path = jsonl_path.replace(".jsonl", ".map.json")
                    os.makedirs(os.path.dirname(map_path), exist_ok=True)
                    with open(map_path, "w") as f:
                        json.dump(mapping, f, indent=2)
            
            if mode == "train":
                label = result.get('label_c_code')
                if not label:
                    if WRITE_DEBUG_FILES: print(f"[WARN] Skipping '{binary_path}': no label generated in train mode.")
                    continue
                append_pair(model_input=result['model_input'], label_c_code=label, jsonl_path=jsonl_path)
                successes += 1
            else:
                if VERBOSE:
                    print(f"Target function: {result['target_function_name']}")
                    print(f"Model input:\n{result['model_input']}")
                successes += 1

        if VERBOSE: print(f"\nBatch processing compl ete. Succeeded: {successes}/{processed}")
        return

    #_set_target_config(args.binary_path, args.function_name)
    bin_path = TARGET_BINARY_PATH
    func_name = TARGET_FUNCTION_NAME
    result = build_sample(binary_path=bin_path, function_name= func_name, mode=mode, UseContext=UseContext, source_hint=source_hint_arg)

    if result is None:
        return

    const_pool = result.get("constant_pool")
    jsonl_path = _ensure_pair_jsonl_path(bin_path, func_name)

    if const_pool:
        mapping = {}
        for info in const_pool.values():
            placeholder, text = info.get("placeholder"), info.get("text")
            if placeholder and text and placeholder.startswith(("STR", "FMT", "CMD")):
                mapping[placeholder] = json.dumps(text)

        if mapping:
            map_path = jsonl_path.replace(".jsonl", ".map.json")
            os.makedirs(os.path.dirname(map_path), exist_ok=True)
            with open(map_path, "w") as f:
                json.dump(mapping, f, indent=2)

    if mode == "train":
        init_pair_files()
        label = result.get('label_c_code')
        if not label:
            if WRITE_DEBUG_FILES: print("[WARN] No label generated in train mode; skipping pair write.")
            return

        append_pair(model_input=result['model_input'], label_c_code=label, jsonl_path=jsonl_path)

        if VERBOSE:
            print("\n--- Final Transformer Input ---")
            print(f"Target function: {result['target_function_name']}")
            print(f"Input tokens preview:\n{result['model_input']}")
            print(f"\nLabel preview:\n{label}")
    else:
        if VERBOSE:
            print("\n--- Test Mode Output ---")
            print(f"Target function: {result['target_function_name']}")
            print(f"Model input:\n{result['model_input']}")

if __name__ == "__main__":
    main()
