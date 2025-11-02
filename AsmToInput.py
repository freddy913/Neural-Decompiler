from config import (
    TARGET_BINARY_PATH,
    TARGET_FUNCTION_NAME,
    CONTEXT_THRESHOLD_TOKENS,
    MYTOKENIZER,
    WRITE_DEBUG_FILES,
    FUNCTION_TXT,
    ASSEMBLY_TXT,
)

from Heuristic import { 
    real_c_code_lookup, 
    apply_heuristic, 
    get_context_candidates_with_degrees,
    remove_junk_functions,
    filter_candidate_funcs_runtime_safe,
    build_candidate_func_data,
}

from HintsAndLabels import build_dwarf_lookup_for_repo, finalize_label_for_training, pick_best_match, collect_constant_pool_for_function, normalize_model_input_with_context_groups


from dwarf_labeling import (
    build_dwarf_lookup_for_repo,
    collect_constant_pool_for_function,
    finalize_label_for_training,
    pick_best_match,
    collect_constant_pool_for_function,
    normalize_model_input_with_context_groups,
)

from binary_analysis import load_project, get_function_data

from prompt_build import build_prompt_and_write_debug
from header_inference import build_header_block_from_binary

import os, re, sys, time

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

    # --- Debug-Files schreiben ---
    if write_debug_files:
        # 1. context overview
        with open("selected_context_functions.txt", "w", encoding="utf-8") as f:
            for entry in context_funcs or []:
                name = entry.get('name', 'unknown_function')
                degree = entry.get('degree', 'n/a')
                role = entry.get('role', 'context')
                mode = entry.get('append_mode', 'assembly')
                f.write(f"Function: {name} (degree {degree}, role {role}, mode {mode})\n")
            f.write("\n")

        # 2. model input
        with open("final_model_input.txt", "w", encoding="utf-8") as f:
            f.write(prompt)

        # 3. target assembly only
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
    for p in (FUNCTION_TXT, ASSEMBLY_TXT):
        try: os.unlink(p)
        except FileNotFoundError: pass
        open(p, "w", encoding="utf-8").close()

def append_pair(model_input, label_c_code):
    asm  = _one_line(model_input)
    lbl  = _compact_label(label_c_code)
    if not asm or not lbl:
        print(f"[SKIP] asm_len={len(asm)} label_len={len(lbl)}"); sys.stdout.flush()
        return False

    # 1) sofort schreiben
    with open(ASSEMBLY_TXT, "a", encoding="utf-8") as af:
        af.write(asm + "\n")
        af.flush()
        os.fsync(af.fileno())          # OS-Cache flushen

    with open(FUNCTION_TXT, "a", encoding="utf-8") as ff:
        ff.write(lbl + "\n")
        ff.flush()
        os.fsync(ff.fileno())

    # 2) sichtbares, ungepuffertes Log
    print(f"[OK {time.strftime('%H:%M:%S')}] wrote pair: asm={len(asm)} chars, lbl={len(lbl)} chars")
    sys.stdout.flush()                 # Notebook/Terminal sofort updaten
    return True

def normalize_assembly_line_dump(raw_text: str, const_pool=None, sym_lookup=None) -> str:
    if not raw_text:
        return ""

    # 0) künstliche Zeilenumbrüche vor bekannten Tokens/Adressen einfügen
    raw_text = re.sub(
        r'(?=(HEADERS:|#include|Target:|Caller:|Callee:|BY\b|TO\b|;;;?\s*Block\s*@|0x[0-9a-fA-F]+:))',
        '\n',
        raw_text
    )

    lines = raw_text.splitlines()
    out = []

    for ln in lines:
        s = ln.strip()
        if not s:
            continue

        # 1) Block-Zeilen raus
        if re.match(r'^;;;?\s*Block\s*@', s):
            continue

        # 2) Addressprefix "0x....:" entfernen
        s = re.sub(r'^\s*0x[0-9a-fA-F]+:\s*', '', s)

        # 3) RIP-relative konstante → Platzhalter falls möglich
        m = re.search(r'\[rip\s*\+\s*0x([0-9a-fA-F]+)\]', s)
        if m and const_pool:
            for addr_str, info in const_pool.items():
                if addr_str.startswith("__"):
                    continue
                ph = info["placeholder"]
                if addr_str.lower().endswith(m.group(1).lower()):
                    s = re.sub(r'\[rip\s*\+\s*0x[0-9a-fA-F]+\]', ph, s)
                    break

        # 4) call 0x.... → call <symbol> oder generisch
        s = re.sub(
            r'\bcall\s+0x[0-9a-fA-F]+',
            (lambda mm: f"call <{sym_lookup(mm.group(0))}>") if sym_lookup else "call <FUNC>",
            s
        )

        # 5) übrige Hexwerte in Speicheradressen → (K)
        s = re.sub(r'\[(?:[^\]]*?)0x[0-9a-fA-F]+(?:[^\]]*?)\]',
                   lambda m: re.sub(r'0x[0-9a-fA-F]+', '(K)', m.group(0)),
                   s)

        out.append(s)

    # 6) EIN Zeilen-String mit Semikolons
    one_line = ";".join(out)
    one_line = re.sub(r'\s+', ' ', one_line).strip()
    return one_line

def _strip_addr_prefix(s: str) -> str:
    return re.sub(r'^\s*0x[0-9a-fA-F]+:\s*', '', s).strip()

def _ensure_endbr64_prefix(seq: list[str]) -> str:
    """Join mit '; ' und sicherstellen, dass mit 'endbr64' begonnen wird."""
    seq = [x for x in (s.strip() for s in seq) if x]  # trim + leere raus
    joined = ";".join(seq)
    if not joined:
        return ""
    norm = re.sub(r'\s+', ' ', joined).strip()
    if not norm.lower().startswith('endbr64'):
        norm = "endbr64; " + norm
    return norm

def build_one_line_headers_target_by_to(raw_text: str) -> str:
    """
    Ziel-Layout:
      HEADERS: #include ..., #include ... TARGET: endbr64;...; BY endbr64;caller...; endbr64;caller...; TO endbr64;callee...; endbr64;callee...;

    Parsing:
      - 'HEADERS:' + '#include ...' bleiben (Includes werden hinter HEADERS: komma-separiert)
      - 'Target:' markiert Target-Bereich (Funktionsname ignorieren)
      - 'BY' bleibt als Wort-Trenner
      - 'Caller:' eröffnet neue Caller-Gruppe (ohne 'CALLER:' im Output)
      - 'Callee:' eröffnet neue Callee-Gruppe (im Output nur nach 'TO')
      - Entfernt 'Block @ ...' Zeilen und führende '0x....:'-Adresslabels
    """
    if not raw_text:
        return ""

    # Vor-Tokenisierung: weiche Umbrüche vor Markern/Labels
    tokenized = re.sub(
        r'(?=(HEADERS:|#include|Target:|Caller:|Callee:|BY\b|;;;?\s*Block\s*@|^\s*0x[0-9a-fA-F]+:))',
        '\n',
        raw_text,
        flags=re.MULTILINE
    )

    lines = [ln.strip() for ln in tokenized.splitlines() if ln.strip()]

    includes: list[str] = []
    target_seq: list[str] = []
    caller_groups: list[list[str]] = []
    callee_groups: list[list[str]] = []
    had_by = False

    section = None  # None | 'target' | 'caller' | 'callee'
    block_re = re.compile(r'^;;;?\s*Block\s*@', re.IGNORECASE)

    for s in lines:
        if s.startswith("HEADERS:"):
            continue
        if s.startswith("#include"):
            includes.append(s)
            continue
        if s.startswith("Target:"):
            section = 'target'
            continue
        if s == "BY":
            had_by = True
            section = None
            continue
        if s.startswith("Caller:"):
            section = 'caller'
            caller_groups.append([])
            continue
        if s.startswith("Callee:"):
            section = 'callee'
            callee_groups.append([])
            continue
        if block_re.match(s):
            continue

        s = _strip_addr_prefix(s)
        if not s:
            continue

        if section == 'target':
            target_seq.append(s)
        elif section == 'caller':
            if not caller_groups:
                caller_groups.append([])
            caller_groups[-1].append(s)
        elif section == 'callee':
            if not callee_groups:
                callee_groups.append([])
            callee_groups[-1].append(s)
        else:
            # Falls vor 'Target:' bereits Instruktionen kommen: konservativ zum Target
            target_seq.append(s)

    parts: list[str] = []

    if includes:
        parts.append("HEADERS: " + ", ".join(includes))

    # TARGET (immer mit endbr64-prefix)
    tgt = _ensure_endbr64_prefix(target_seq)
    if tgt:
        parts.append("TARGET: " + tgt)

    # BY + alle Caller-Gruppen (jede Gruppe beginnt mit endbr64;)
    if had_by and (caller_groups or callee_groups):
        parts.append("BY")

    for grp in caller_groups:
        grp_str = _ensure_endbr64_prefix(grp)
        if grp_str:
            parts.append(grp_str)

    # TO + alle Callee-Gruppen (jede Gruppe beginnt mit endbr64;)
    if callee_groups:
        parts.append("TO")
        for grp in callee_groups:
            grp_str = _ensure_endbr64_prefix(grp)
            if grp_str:
                parts.append(grp_str)

    return " ".join(parts).strip()

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

        # const_pool = collect_constant_pool_for_function(target_func, project)

        # final_label = finalize_label_for_training(
        #     getattr(target_func, "name", None),
        #     real_src,
        #     const_pool,
        #     dwarf_lookup
        # )
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

    # formatted_input = build_one_line_headers_target_by_to(result["model_input"])
    # model_input = normalize_assembly_line_dump(result["model_input"])
    append_pair(model_input=result['model_input'], label_c_code=result['label_c_code'])

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
    
