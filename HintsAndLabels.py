from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class
from bisect import bisect_left
import os, re, string, difflib, weakref



'''
SECTION 1: DWARF-based signature extraction
This part is only used during training, when .o files still contain DWARF.
At inference we will NOT have DWARF, so these helpers are not called.
'''

def resolve_type_name(die, cu, dwarfinfo, depth=0):
    '''
    Reconstruct a human-readable C type name from a DWARF DIE.
    This walks through pointers, qualifiers (const, volatile, ...), typedefs, etc.
    depth is used to avoid infinite recursion.
    '''
    if die is None or depth > 10:
        return "UNKNOWN_TYPE"

    tag = die.tag

    if tag == "DW_TAG_base_type":
        name_attr = die.attributes.get("DW_AT_name")
        if name_attr:
            return name_attr.value.decode("utf-8", "ignore")
        return "UNKNOWN_BASE"

    if tag == "DW_TAG_typedef":
        name_attr = die.attributes.get("DW_AT_name")
        if name_attr:
            return name_attr.value.decode("utf-8", "ignore")
        return "typedef_anon"

    if tag == "DW_TAG_pointer_type":
        tgt_attr = die.attributes.get("DW_AT_type")
        if tgt_attr:
            tgt_die = dwarfinfo.get_DIE_from_refaddr(
                tgt_attr.value + cu.cu_offset
                if describe_form_class(tgt_attr.form) == 'ref_addr'
                else tgt_attr.value
            )
            base_name = resolve_type_name(tgt_die, cu, dwarfinfo, depth+1)
        else:
            base_name = "void"
        return base_name + " *"

    if tag in ("DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type"):
        tgt_attr = die.attributes.get("DW_AT_type")
        if tgt_attr:
            tgt_die = dwarfinfo.get_DIE_from_refaddr(
                tgt_attr.value + cu.cu_offset
                if describe_form_class(tgt_attr.form) == 'ref_addr'
                else tgt_attr.value
            )
            base_name = resolve_type_name(tgt_die, cu, dwarfinfo, depth+1)
        else:
            base_name = "UNKNOWN_TYPE"

        if tag == "DW_TAG_const_type":
            return "const " + base_name
        if tag == "DW_TAG_volatile_type":
            return "volatile " + base_name
        return base_name

    if tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_enumeration_type"):
        name_attr = die.attributes.get("DW_AT_name")
        if name_attr:
            nm = name_attr.value.decode("utf-8", "ignore")
            return f"{tag.replace('DW_TAG_','')} {nm}"
        else:
            return tag.replace("DW_TAG_", "") + " /*anon*/"

    name_attr = die.attributes.get("DW_AT_name")
    if name_attr:
        return name_attr.value.decode("utf-8", "ignore")

    return "UNKNOWN_TYPE"


def build_signature_from_die(die, cu, dwarf_info):
    '''
    Given a DW_TAG_subprogram DIE, build a function signature string like:
    "int CheckSum(unsigned short *ptr, int nbytes);"
    Fallback to UNKNOWN_TYPE / param if DWARF info is incomplete.
    '''
    name_attr = die.attributes.get("DW_AT_name")
    if not name_attr:
        return None
    func_name = name_attr.value.decode("utf-8", "ignore")

    ret_attr = die.attributes.get("DW_AT_type")
    if ret_attr:
        ret_die = dwarf_info.get_DIE_from_refaddr(
            ret_attr.value + cu.cu_offset
            if describe_form_class(ret_attr.form) == 'ref_addr'
            else ret_attr.value
        )
        ret_type_name = resolve_type_name(ret_die, cu, dwarf_info)
    else:
        ret_type_name = "void"

    params = []
    for child in die.iter_children():
        if child.tag == "DW_TAG_formal_parameter":
            p_name_attr = child.attributes.get("DW_AT_name")
            p_name = p_name_attr.value.decode("utf-8", "ignore") if p_name_attr else "param"

            p_type_attr = child.attributes.get("DW_AT_type")
            if p_type_attr:
                p_type_die = dwarf_info.get_DIE_from_refaddr(
                    p_type_attr.value + cu.cu_offset
                    if describe_form_class(p_type_attr.form) == 'ref_addr'
                    else p_type_attr.value
                )
                p_type_name = resolve_type_name(p_type_die, cu, dwarf_info)
            else:
                p_type_name = "UNKNOWN_TYPE"

            params.append(f"{p_type_name} {p_name}")

    param_list = ", ".join(params) if params else "void"
    sig = f"{ret_type_name} {func_name}({param_list});"
    return sig

def extract_types_from_o(o_path):
    types = []
    with open(o_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return types
        dwarf_info = elf.get_dwarf_info()
        for cu in dwarf_info.iter_CUs():
            top = cu.get_top_DIE()
            for die in top.iter_children():
                if die.tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
                    name_attr = die.attributes.get("DW_AT_name")
                    if not name_attr:
                        continue
                    name = name_attr.value.decode("utf-8", "ignore")
                    types.append({
                        "name": name,
                        "o_path": o_path,
                        "die": die,
                        "cu": cu,
                        "dwarf_info": dwarf_info,
                    })
    return types

def extract_functions_from_o(o_path):
    '''
    Load a single .o ELF file, iterate DWARF compilation units,
    collect DW_TAG_subprogram DIEs, and build:
    {
        func_name: [
            {
                "signature_hint": "...",
                "die": <DIE>,
                "cu": <CU>,
                "dwarf_info": <dwarf_info>
            },
            ...
        ],
        ...
    }
    '''
    results = {}

    with open(o_path, 'rb') as f:
        elf = ELFFile(f)

        if not elf.has_dwarf_info():
            return results
        
        dwarf_info = elf.get_dwarf_info()
        for cu in dwarf_info.iter_CUs():
            top_die = cu.get_top_DIE()
            for die in top_die.iter_children():
                if die.tag == 'DW_TAG_subprogram':
                    name_attr = die.attributes.get('DW_AT_name')
                    if not name_attr:
                        continue
                    func_name = name_attr.value.decode('utf-8', 'ignore')
                    signature_hint = build_signature_from_die(die, cu, dwarf_info)
                    if signature_hint:
                        results.setdefault(func_name, []).append({
                            "signature_hint": signature_hint,
                            "die": die,
                            "cu": cu,
                            "dwarf_info": dwarf_info,
                            "o_path": o_path
                        })
    return results

_DWARF_CACHE: dict[str, dict] = {}

def build_dwarf_lookup_for_repo(compiled_dir_root):
    '''
    Traverse COMPILED/<repo>/..., gather DWARF info from all .o files,
    and build a mapping:
    dwarf_lookup[func_name] = [
        {
            "o_path": ".../foo.o",
            "signature_hint": "int foo(int x);",
            "die": ...,
            "cu": ...,
            "dwarf_info": ...
        },
        ...
    ]
    '''
    compiled_dir_root = os.path.abspath(compiled_dir_root)
    cached = _DWARF_CACHE.get(compiled_dir_root)
    if cached is not None:
        return cached
    
    func_to_o = {} 
    type_to_o = {}

    for root, dirs, files in os.walk(compiled_dir_root):
        for fn in files:
            if not fn.endswith(".o"):
                continue
            o_path = os.path.join(root, fn)
            dwarf_funcs = extract_functions_from_o(o_path)
            for f_name, func_infos in dwarf_funcs.items():
                for info in func_infos:
                    func_to_o.setdefault(f_name, []).append(info)

            dwarf_types = extract_types_from_o(o_path)
            for type_info in dwarf_types:
                type_name = type_info["name"]
                type_to_o.setdefault(type_name, []).append(type_info)
    
    dwarf_lookup = { "functions": func_to_o, "types": type_to_o }
    _DWARF_CACHE[compiled_dir_root] = dwarf_lookup

    return dwarf_lookup


def build_signature_hint_from_lookup(func_name, dwarf_lookup):
    '''
    Look up a function name in the aggregated DWARF lookup.
    Return one signature string if available, else None.
    '''
    if not dwarf_lookup:
        return None
    func_map = dwarf_lookup.get("functions", dwarf_lookup)
    lst = func_map.get(func_name)
    if not lst:
        return None
    return lst[0].get("signature_hint")


def pick_best_match(candidates, target_binary_path):
    '''
    Given a list of candidate DWARF entries for the same function name,
    choose the most plausible one.
    We try to pick the one whose o_path directory looks closest to the binary.

    This is heuristic. You can refine it later:
    - same parent dir?
    - shortest path distance?
    '''
    if not candidates:
        return None

    # simple heuristic: prefer candidates where the dirname of the .o
    # appears as substring in the binary path
    best = candidates[0]
    best_score = -1
    bin_dir = os.path.dirname(target_binary_path)

    for c in candidates:
        o_dir = os.path.dirname(c.get("o_path", ""))
        score = 0
        if o_dir in bin_dir or bin_dir in o_dir:
            score += 1
        if score > best_score:
            best_score = score
            best = c

    return best

'''
SECTION 3: Annotate ground truth C code with placeholders.
We take the "real" C function body we recovered from source (training only).
We replace literal strings in that body with our placeholders like STRx..., CMDx..., FMTx....
We also normalize stdout/stderr to STREAM_STDOUT / STREAM_STDERR so the model learns
a stable representation independent of FILE* specifics.
'''

def _similar(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()

def annotate_real_c_body_with_placeholders(real_src, const_pool):
    annotated = real_src

    print("\n[ANNOTATION_DEBUG] checking replacements:")
    repls = []
    for addr_str, info in const_pool.items():
        if addr_str.startswith("__"):
            continue
        kind = info.get("kind")
        if kind in ("STR", "CMD", "FMT"):
            original_txt = info["text"].split("\x00")[0]
            if not original_txt:
                continue
            placeholder = info["placeholder"]
            repls.append((original_txt, placeholder))
            print(f"  candidate: {repr(original_txt[:60])} -> {placeholder}")

    repls.sort(key=lambda x: len(x[0]), reverse=True)

    for orig, ph in repls:
        escaped_variants = [
            orig,
            orig.replace("\n", "\\n"),
            orig.replace("\\n", "\n"),
            orig.strip(),
            orig.replace("\n", ""),
        ]

        matched = False
        for variant in escaped_variants:
            pat = r'"{}"'.format(re.escape(variant))
            new_annotated = re.sub(pat, ph, annotated)
            if new_annotated != annotated:
                annotated = new_annotated
                print(f"  [EXACT_MATCH] {repr(variant[:40])} -> {ph}")
                matched = True
                break

        # Fuzzy fallback: try to match similar substrings if exact fails
        if not matched:
            candidates = re.findall(r'"(.*?)"', annotated)
            for c in candidates:
                if _similar(orig, c) > 0.8:
                    annotated = annotated.replace(f'"{c}"', ph)
                    print(f"  [FUZZY_MATCH] {repr(c[:40])} ≈ {repr(orig[:40])} -> {ph}")
                    matched = True
                    break

        if not matched:
            print(f"  [MISS FINAL] {repr(orig[:40])}")

    # annotated = annotated.replace("stderr", "STREAM_STDERR")
    # annotated = annotated.replace("stdout", "STREAM_STDOUT")
    return annotated

'''
assembly labeling helpers
'''
def strip_c_comments(code: str) -> str:
    """
    Removes //... and /*...*/ comments,
    without breaking strings/chars.
    """
    OUT, SLASH, LINE, BLOCK, STRING, CHAR, ESC = range(7)
    state = OUT
    out = []
    quote = None  # " or '

    i = 0
    while i < len(code):
        c = code[i]

        if state == OUT:
            if c == '/':
                state = SLASH
            elif c == '"':
                out.append(c); state = STRING
            elif c == "'":
                out.append(c); state = CHAR
            else:
                out.append(c)
        elif state == SLASH:
            if c == '/':
                state = LINE
            elif c == '*':
                state = BLOCK
            else:
                out.append('/')
                out.append(c)
                state = OUT
        elif state == LINE:
            if c == '\n':
                out.append('\n')
                state = OUT
        elif state == BLOCK:
            if c == '*' and i + 1 < len(code) and code[i + 1] == '/':
                i += 1
                state = OUT
        elif state == STRING:
            out.append(c)
            if c == '\\':
                state = ESC
                quote = '"'
            elif c == '"':
                state = OUT
        elif state == CHAR:
            out.append(c)
            if c == '\\':
                state = ESC
                quote = "'"
            elif c == "'":
                state = OUT
        elif state == ESC:
            out.append(c)
            state = STRING if quote == '"' else CHAR

        i += 1

    # if we ended in SLASH state, output the slash
    if state == SLASH:
        out.append('/')

    return ''.join(out)

def finalize_label_for_training(func_name, real_src, const_pool, dwarf_lookup):
    '''
    Build the final training label for one function.

    Steps:
    1. Annotate the real source with placeholders (STRx..., CMDx..., FMTx...)
    2. Use the DWARF signature hint only if we have no source body

    Returns:
        final_label (str) or None
    '''
    annotated_body = None
    if real_src:
        annotated_body = annotate_real_c_body_with_placeholders(real_src, const_pool)
        annotated_body = strip_c_comments(annotated_body)

    #sig_hint = build_signature_hint_from_lookup(func_name, dwarf_lookup)

    if annotated_body:
        body = annotated_body.strip()
        if "{" in body and "}" in body and len(body) > 20:
            return body

        return None

    # if sig_hint:
    #     return sig_hint.strip()

    return None
