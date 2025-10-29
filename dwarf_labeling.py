from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class
import os, re, string, difflib

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
    func_to_o = {} 

    for root, dirs, files in os.walk(compiled_dir_root):
        for fn in files:
            if fn.endswith(".o"):
                o_path = os.path.join(root, fn)
                dwarf_funcs = extract_functions_from_o(o_path)
                for f_name, func_infos in dwarf_funcs.items():
                    for info in func_infos:
                        func_to_o.setdefault(f_name, []).append(info)

    return func_to_o


def build_signature_hint_from_lookup(func_name, dwarf_lookup):
    '''
    Look up a function name in the aggregated DWARF lookup.
    Return one signature string if available, else None.
    '''
    lst = dwarf_lookup.get(func_name)
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
SECTION 2: Constant pool extraction.
Goal:
Find static data (strings, shell commands, format strings, etc.) referenced
by a function's machine code, assign placeholders like STRx401abc, CMDx402def, ...
This is what Akin described:
    printf("hello world")  ->  printf(STRx4019e7)
Later at inference we won't have DWARF, but the model should still emit STRx...,
which we can post-process back to actual bytes from memory.
'''

def _is_printable_ascii(buf_bytes):
    '''
    Heuristic: buffer is considered "text-like" if >=70% of bytes are printable ASCII.
    '''
    printable = set(bytes(string.printable, "ascii"))
    score = sum((b in printable and b not in b"\x0b\x0c") for b in buf_bytes)
    return (len(buf_bytes) > 0) and (score / len(buf_bytes) >= 0.7)


def _classify_blob(text_str):
    '''
    Decide placeholder kind for a string:
      CMD -> likely shell/command payload (iptables, chmod, etc.)
      FMT -> looks like printf-style format string ("%s", "%d", ...)
      STR -> normal human-readable message/log/error
    '''
    lowered = text_str.lower()

    shell_keywords = [
        "iptables", "chmod", "chown", "wget", "curl", "rm ",
        "ifconfig", ";", "&&", "||"
    ]
    if any(kw in lowered for kw in shell_keywords):
        return "CMD"

    if re.search(r"%[0-9]*[duxspcf]", text_str):
        return "FMT"

    return "STR"

def make_placeholder(kind_prefix, addr_int):
    '''
    Build "STRx4019e7" / "CMDx402abc" / "FMTx403def" / "DATx404000"
    from the kind and absolute address.
    '''
    hexaddr = format(addr_int, "x")
    return f"{kind_prefix}x{hexaddr}"


def read_zero_terminated(project, start_addr, maxlen=4096):
    '''
    Read bytes starting at 'start_addr' from the loaded binary in angr
    until we hit a 0x00 byte or maxlen or memory read fails.
    '''
    out = bytearray()
    for i in range(maxlen):
        try:
            chunk = project.loader.memory.load(start_addr + i, 1)
        except Exception:
            break
        if not chunk or len(chunk) == 0:
            break
        b = chunk[0]
        if b == 0:
            break
        out.append(b)
    return bytes(out)


def _rip_relative_target(insn, opnd):
    '''
    Compute absolute address for RIP-relative memory operand.
    insn.address      : start address of instruction
    insn.size         : size in bytes of instruction
    opnd.mem.disp     : displacement (int)
    effective = insn.address + insn.size + disp
    '''
    disp = opnd.mem.disp
    return insn.address + insn.size + disp


def _get_capstone_insn(insn):
    '''
    angr basic block instructions can be:
      - real capstone CsInsn
      - a wrapper with .insn holding CsInsn
      - sometimes .capstone or .capstone.insn etc.

    We try a few common layouts and return the real CsInsn
    (the one that actually has .operands, .address, .size).
    '''
    # case 1: insn is already CsInsn-like
    if hasattr(insn, "operands") and hasattr(insn, "address") and hasattr(insn, "size"):
        return insn

    # case 2: wrapper.insn
    cand = getattr(insn, "insn", None)
    if cand is not None and hasattr(cand, "operands"):
        return cand

    # case 3: wrapper.capstone or wrapper.capstone.insn
    cap_attr = getattr(insn, "capstone", None)
    if cap_attr is not None:
        if hasattr(cap_attr, "operands") and hasattr(cap_attr, "address"):
            return cap_attr
        deep = getattr(cap_attr, "insn", None)
        if deep is not None and hasattr(deep, "operands"):
            return deep

    return None


def try_extract_rodata_addr_from_insn(insn):
    '''
    Return int absolute address of a constant (string, fmt, cmd, data)
    referenced by this instruction, or None.
    '''
    cs_insn = _get_capstone_insn(insn)
    if cs_insn is None:
        return None

    # we also need the top-level wrapper's address/size for RIP-relative calc
    # angr wrappers always have .address / .size, so fall back there
    insn_addr = getattr(insn, "address", None)
    insn_size = getattr(insn, "size", None)
    if insn_addr is None and hasattr(cs_insn, "address"):
        insn_addr = cs_insn.address
    if insn_size is None and hasattr(cs_insn, "size"):
        insn_size = cs_insn.size

    for op in cs_insn.operands:
        # IMM
        if op.type == X86_OP_IMM:
            imm_val = getattr(op, "imm", None)
            if isinstance(imm_val, int) and imm_val > 0x1000:
                return imm_val

        # MEM
        if op.type == X86_OP_MEM:
            base_reg = op.mem.base
            disp     = op.mem.disp

            if base_reg == X86_REG_RIP and insn_addr is not None and insn_size is not None:
                abs_addr = insn_addr + insn_size + disp
                if abs_addr > 0x1000:
                    return abs_addr

            if base_reg == 0 and disp and disp > 0x1000:
                return disp

    return None


def collect_constant_pool_for_function(func_obj, project):
    '''
    Iterate all machine instructions in func_obj.
    For each instruction, try to find referenced constant addresses
    (typical for strings / format strings / shell commands in .rodata).

    For each found address:
      1. Read NUL-terminated bytes at that address
      2. If printable, classify as CMD / FMT / STR
      3. Otherwise classify as DAT
      4. Build placeholder token, e.g. STRx401abc

    Returns:
      { "0x401abc": { "bytes": b"...",
                      "text": "Not enough privileges...",
                      "kind": "STR",
                      "placeholder": "STRx401abc" },
        ...
      }
    '''
    seen = {}
    for block in getattr(func_obj, "blocks", []):
        cap = getattr(block, "capstone", None)
        if cap is None:
            continue

        for insn in getattr(cap, "insns", []):
            addr_candidate = try_extract_rodata_addr_from_insn(insn)
            if addr_candidate is None:
                continue
            if addr_candidate in seen:
                continue

            raw = read_zero_terminated(project, addr_candidate, maxlen=4096)

            if not raw:
                seen[addr_candidate] = {
                    "bytes": b"",
                    "text": "",
                    "kind": "DAT",
                    "placeholder": make_placeholder("DAT", addr_candidate),
                }
                continue

            try:
                txt = raw.decode("utf-8", "ignore")
            except Exception:
                txt = ""

            if not _is_printable_ascii(raw):
                seen[addr_candidate] = {
                    "bytes": raw,
                    "text": txt,
                    "kind": "DAT",
                    "placeholder": make_placeholder("DAT", addr_candidate),
                }
                continue

            kind = _classify_blob(txt)
            seen[addr_candidate] = {
                "bytes": raw,
                "text": txt,
                "kind": kind,
                "placeholder": make_placeholder(kind, addr_candidate),
            }

    final_pool = {}
    for addr_int, info in seen.items():
        final_pool[f"0x{addr_int:x}"] = info

    print(f"\n[CONST_POOL_DEBUG] Function: {getattr(func_obj, 'name', hex(getattr(func_obj, 'addr', 0)))}")
    if not final_pool:
        print("  -> No constants detected.")
    else:
        for addr, info in final_pool.items():
            print(f"  {addr}  {info['kind']:4}  {repr(info['text'][:60])}  ->  {info['placeholder']}")

    return final_pool


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
        if info["kind"] in ("STR", "CMD", "FMT"):
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

    annotated = annotated.replace("stderr", "STREAM_STDERR")
    annotated = annotated.replace("stdout", "STREAM_STDOUT")
    return annotated

'''
SECTION 4: Final label assembly.
This is what you feed as "label_c_code" during training:
   <DWARF signature if available>
   <annotated ground truth body with STRx... etc.>

At inference the model won't see DWARF or real_src,
but it has learned to output that style.
'''


def finalize_label_for_training(func_name, real_src, const_pool, dwarf_lookup):
    '''
    Build the final training label for one function.

    Steps:
    1. Annotate the real source with placeholders (STRx..., CMDx..., FMTx...)
    2. Prepend the DWARF signature hint if available

    Returns:
        final_label (str) or None
    '''
    annotated_body = None
    if real_src:
        annotated_body = annotate_real_c_body_with_placeholders(real_src, const_pool)

    sig_hint = build_signature_hint_from_lookup(func_name, dwarf_lookup)

    if annotated_body and sig_hint:
        return sig_hint.strip() + "\n" + annotated_body.strip()

    if annotated_body:
        return annotated_body.strip()

    if sig_hint:
        return sig_hint.strip()

    return None
