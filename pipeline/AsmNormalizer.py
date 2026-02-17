"""
Takes the raw Capstone disassembly produced by ElfFeatures and turns it into
the deterministic, token-efficient format that the LongT5 model actually sees.

What happens during normalization:
  1. RIP-relative memory operands like [rip+0x2a3f] are replaced with constant
     pool placeholders (STRx..., FMTx..., etc.) looked up from the pool dict.
  2. call instructions pointing at hex addresses are resolved to symbolic names
     (e.g. call printf@plt) using a cached PLT/GOT symbol map.
  3. Absolute jump targets become sequential labels (@jmp0, @jmp1, ...).
  4. Trailing padding after ret (nop / int3 / next prologue) is stripped.
  5. ptr-size qualifiers (qword ptr, dword ptr ...) are removed.

The final output is a single flat string:
  HEADER:<includes> TARGET:func;<asm> CALLERS:FN{<asm>} CALLEES:FN{<asm>}
"""
import os
import re
import weakref
from bisect import bisect_left
import re as _re_end

from ElfFeatures import _function_symbol_addrs

_LABEL_DEBUG = os.environ.get("LABEL_DEBUG") == "1"
_PLT_SUFFIX_RE = re.compile(r'@plt$', re.IGNORECASE)
STREAM_STDERR = "STREAM_STDERR"
STREAM_STDOUT = "STREAM_STDOUT"
STREAM_UNKNOWN = "STREAM_UNKNOWN"
_STREAM_TOKENS = {STREAM_STDERR, STREAM_STDOUT}

_PLACEHOLDER_RE = re.compile(r'\b(?:STR|FMT|CMD|DAT)x[0-9a-fA-F]+\b')
_RIP_REL_OPERAND_RE = re.compile(r'\[rip\s*(?P<sign>[+-])\s*0x(?P<hex>[0-9a-fA-F]+)\]', re.IGNORECASE)
_PTR_TO_PLACEHOLDER_RE = re.compile(
    r'\b(?:[a-z0-9]+word|byte)\s+ptr\s+('
    r'(?:STR|FMT|CMD|DAT)x[0-9a-fA-F]+'
    r'|STREAM_STDERR|STREAM_STDOUT|STREAM_UNKNOWN'
    r'|[_a-zA-Z][_a-zA-Z0-9@.<>]+'
    r')',
    re.IGNORECASE
)
_RET_RE = _re_end.compile(r'^\s*ret\s*;?\s*$', re.IGNORECASE)
_CALL_RESOLVE_RADIUS = 48
_CALL_SYMBOL_CACHE: dict[int, tuple[weakref.ReferenceType, dict[int, str], list[int]]] = {}

def _dbg(msg: str) -> None:
    if _LABEL_DEBUG:
        print(f"[LABEL_DEBUG] {msg}")


def _normalize_symbol_generic(sym: str | None) -> str:
    """
    Normalizes symbol names by removing version suffixes and @ decorators.
    Args:
        :param sym: Symbol name string or None.
        :return: Normalized symbol name as a string.
    """
    if not sym: return ""
    base = sym.strip().split('@@')[0].split('@')[0]
    return base

def _store_call_symbol_map(project, mapping: dict[int, str]) -> None:
    """
    Stores a call symbol mapping in cache using weak references.
    Args:
        :param project: Angr project object to associate with mapping.
        :param mapping: Dictionary mapping addresses to symbol names.
        :return: None.
    """
    try:
        ref = weakref.ref(project)
    except TypeError:
        ref = lambda: None
    _CALL_SYMBOL_CACHE[id(project)] = (ref, mapping, sorted(mapping.keys()))

def _get_call_symbol_map(project) -> tuple[dict[int, str], list[int]]:
    """
    Retrieves or builds call symbol mapping for a project with caching.
    Args:
        :param project: Angr project object.
        :return: Tuple of (mapping dict, sorted address list).
    """
    pid = id(project)
    entry = _CALL_SYMBOL_CACHE.get(pid)
    if entry:
        ref, mapping, sorted_addrs = entry
        if ref() is not None:
            return mapping, sorted_addrs
    mapping = _build_call_symbol_map(project)
    sorted_addrs = sorted(mapping.keys())
    _store_call_symbol_map(project, mapping)
    return mapping, sorted_addrs

def _build_call_symbol_map(project) -> dict[int, str]:
    """
    Builds a mapping from call addresses to function symbols from PLT and imports.
    Args:
        :param project: Angr project object.
        :return: Dictionary mapping addresses to symbol names.
    """
    mapping: dict[int, str] = {}
    loader = getattr(project, "loader", None)
    if loader is None:
        return mapping

    # Collect symbols from main object and shared libs
    objects = []
    main_obj = getattr(loader, "main_object", None)
    if main_obj is not None: objects.append(main_obj)
    try:
        shared = getattr(loader, "shared_objects", {}) or {}
        objects.extend(shared.values())
    except Exception: pass

    def _add(addr, name):
        if isinstance(addr, int) and addr > 0 and name:
            base = _normalize_symbol_generic(name)
            if base: mapping.setdefault(addr, base)

    for obj in objects:
        # PLT/Imports logic
        try:
            for name, sym in (getattr(obj, "imports", {}) or {}).items():
                _add(getattr(sym, "rebased_addr", getattr(sym, "resolved_addr", None)), name)
            for name, addr in (getattr(obj, "plt", {}) or {}).items():
                _add(addr, name)
            for addr, name in (getattr(obj, "reverse_plt", {}) or {}).items():
                _add(addr, name)
        except Exception: pass

    mapping.update(_function_symbol_addrs(project))
    return mapping

def _resolve_call_symbol(project, abs_or_text: str) -> str | None:
    """
    Resolves a call instruction target address to its symbol name.
    Args:
        :param project: Angr project object.
        :param abs_or_text: Assembly text containing a hex address.
        :return: Symbol name as string, or None if not found.
    """
    try:
        m = re.search(r'0x[0-9a-fA-F]+', abs_or_text)
        if not m: return None
        addr = int(m.group(0), 16)
    except Exception: return None

    mapping, sorted_addrs = _get_call_symbol_map(project)
    sym = mapping.get(addr)
    if sym: return sym

    # Fuzzy search for nearest symbol
    best_sym = None
    best_delta = _CALL_RESOLVE_RADIUS + 1
    idx = bisect_left(sorted_addrs, addr)

    def scan(start, step):
        nonlocal best_sym, best_delta
        j = start
        while 0 <= j < len(sorted_addrs):
            c_addr = sorted_addrs[j]
            delta = abs(c_addr - addr)
            if delta > _CALL_RESOLVE_RADIUS: break
            if delta < best_delta:
                best_delta = delta
                best_sym = mapping.get(c_addr)
            j += step
    scan(idx, -1)
    scan(idx, 1)

    if best_sym:
        mapping.setdefault(addr, best_sym)
        return best_sym
    return None


def _tighten_commas_semicolons(s: str) -> str:
    """
    Removes whitespace around commas and semicolons.
    Args:
        :param s: Input string.
        :return: Tightened string.
    """
    s = re.sub(r'\s*,\s*', ',', s)
    s = re.sub(r'\s*;\s*', ';', s)
    return s

def _strip_addr_prefix(s: str) -> str:
    """
    Strips address prefix from assembly line.
    Args:
        :param s: Assembly line with optional address prefix.
        :return: Line without address prefix.
    """
    return re.sub(r'^\s*0x[0-9a-fA-F]+:\s*', '', s).strip()

def join_semicolon(seq: list[str]) -> str:
    """
    Joins assembly lines with semicolon delimiters.
    Args:
        :param seq: List of assembly instruction strings.
        :return: Joined string with semicolons.
    """
    seq = [x.strip() for x in seq if x.strip()]
    if not seq: return ""
    return "; ".join(seq)

def _drop_block_lines(s: str) -> bool:
    """
    Determines if an assembly line should be dropped from output.
    Args:
        :param s: Assembly line string.
        :return: True if line should be dropped, False otherwise.
    """
    if "Block @" in s or re.match(r'^\s*;;;?\s*Block\s*@', s, re.IGNORECASE):
        return True
    
    if s.strip().endswith(":"):
        return True
        
    return False


def _tokenize_model_input(raw_text: str) -> list[str]:
    """
    Splits assembly text into individual line tokens.
    Args:
        :param raw_text: Raw assembly text block.
        :return: List of non-empty stripped lines.
    """
    if not raw_text: return []
    return [ln.strip() for ln in raw_text.splitlines() if ln.strip()]

def _const_pool_lookup_maps(const_pool: dict | None):
    """
    Creates lookup maps for constant pool placeholders with caching.
    Args:
        :param const_pool: Constant pool dictionary.
        :return: Tuple of (displacement map, tail map) dictionaries.
    """
    if not const_pool: return {}, {}
    if "__lookup_cache__" in const_pool:
        return const_pool["__lookup_cache__"]["disp_map"], const_pool["__lookup_cache__"]["tail_map"]

    disp_map: dict[int, str] = {}
    tail_map: dict[str, str] = {}
    for key, info in const_pool.items():
        if not isinstance(info, dict): continue
        ph = info.get("placeholder")
        if not ph: continue
        for disp in info.get("rip_offsets") or []:
            disp_map[disp] = ph
        # Fallback for hex string matching
        addr_int = info.get("address_int")
        if isinstance(addr_int, int):
            h = format(addr_int, "x")
            for ln in range(3, len(h) + 1):
                tail_map.setdefault(h[-ln:].lower(), ph)
    
    const_pool["__lookup_cache__"] = {"disp_map": disp_map, "tail_map": tail_map}
    return disp_map, tail_map

def _replace_rip_rel_with_pool(line: str, const_pool: dict) -> str:
    """
    Replaces RIP-relative memory operands with constant pool placeholders.
    Args:
        :param line: Assembly instruction line.
        :param const_pool: Constant pool dictionary.
        :return: Line with placeholders substituted.
    """
    if not const_pool: return line
    disp_map, tail_map = _const_pool_lookup_maps(const_pool)

    def _sub(match: re.Match) -> str:
        sign = match.group('sign') or '+'
        disp_val = int(match.group('hex'), 16)
        if sign == '-': disp_val = -disp_val
        
        ph = disp_map.get(disp_val)
        if not ph: ph = tail_map.get(match.group('hex').lower())
        
        if ph: return ph
        return match.group(0).replace(" ", "")

    line = _RIP_REL_OPERAND_RE.sub(_sub, line)
    return _PTR_TO_PLACEHOLDER_RE.sub(r'\1', line)

def _rewrite_calls(line: str, project) -> str:
    """
    Rewrites call instructions to use resolved symbol names with @plt suffix.
    Args:
        :param line: Assembly instruction line.
        :param project: Angr project object.
        :return: Rewritten line with symbolic call targets.
    """
    def _sub(mm):
        sym = _resolve_call_symbol(project, mm.group(0))
        
        if sym:
            if sym.endswith("@plt"):
                return f"call {sym}"
            return f"call {sym}@plt"
        return "call <FUNC>"
    return re.sub(r'\bcall\s+0x[0-9a-fA-F]+', _sub, line)

def _looks_like_new_prologue(line: str) -> bool:
    """
    Checks if line appears to be start of a new function prologue.
    Args:
        :param line: Assembly instruction line.
        :return: True if line looks like a prologue, False otherwise.
    """
    s = line.strip().lower()
    return s.startswith("endbr64") or s.startswith("push rbp")

def _cut_after_function_end(seq: list[str]) -> list[str]:
    """
    Truncates instruction sequence after function return and trailing NOPs.
    Args:
        :param seq: List of assembly instruction strings.
        :return: Truncated list ending at function boundary.
    """
    out = []
    saw_ret = False
    for line in seq:
        if saw_ret:
            if _looks_like_new_prologue(line): break
            if not re.match(r'^(nop|int3|ud2|align)', line.strip().lower()):
                break
        out.append(line)
        if _RET_RE.match(line): saw_ret = True
    return out

def _ensure_prologue_first(seq: list[str]) -> list[str]:
    """
    Moves endbr64 instruction to first position if present.
    Args:
        :param seq: List of assembly instruction strings.
        :return: Reordered list with prologue first.
    """
    for idx, line in enumerate(seq):
        if line.strip().lower().startswith("endbr64"):
            if idx == 0: return seq
            return [seq[idx]] + seq[:idx] + seq[idx+1:]
    return seq

def _normalize_operands(line: str) -> str:
    """
    Normalizes assembly operands by removing ptr keywords and lowercasing hex.
    Args:
        :param line: Assembly instruction line.
        :return: Normalized line string.
    """
    line = re.sub(r'0X[0-9A-F]+', lambda m: m.group(0).lower(), line)
    
    line = line.replace("qword ptr", "").replace("dword ptr", "")
    line = line.replace("byte ptr", "").replace("word ptr", "")
    line = line.replace("xmmword ptr", "")
    
    line = re.sub(r'\s*,\s*', ',', line)
    line = re.sub(r'\s+', ' ', line)
    return line.strip()


def normalize_model_input_with_context_groups(
    target_asm: str,
    caller_list: list[str],
    callee_list: list[str],
    header: str,
    project,
    target_func_obj,
    const_pool_for_target: dict
) -> str:
    """
    Normalizes and formats assembly with context into structured model input.
    Args:
        :param target_asm: Assembly code of the target function.
        :param caller_list: List of caller function assembly strings.
        :param callee_list: List of callee function assembly strings.
        :param header: Header block with include directives.
        :param project: Angr project object.
        :param target_func_obj: Target function object.
        :param const_pool_for_target: Constant pool for the target function.
        :return: Formatted model input string.
    """
    
    def _process_one_asm_block(raw_asm):
        if not raw_asm: return ""
        lines = _tokenize_model_input(raw_asm)
        
        cleaned_lines = []
        for s in lines:
            if _drop_block_lines(s): continue
            cleaned_lines.append(s)
            
        if not cleaned_lines: return ""

        addr_to_label = {}
        jump_targets = set()
        
        line_addr_map = []
        
        for s in cleaned_lines:
            m_addr = re.match(r'^\s*(0x[0-9a-fA-F]+):', s)
            current_addr = None
            if m_addr:
                current_addr = int(m_addr.group(1), 16)
            
            line_addr_map.append((current_addr, s))
            
            m_jmp = re.search(r'\b(?:j[a-z]{1,3}|jmp|call)\s+(0x[0-9a-fA-F]+)', s, re.IGNORECASE)
            if m_jmp:
                target = int(m_jmp.group(1), 16)
                jump_targets.add(target)

        sorted_targets = sorted(list(jump_targets))
        for i, addr in enumerate(sorted_targets):
            addr_to_label[addr] = f"@jmp{i}"

        final_lines = []
        
        for addr, line in line_addr_map:
            if addr in addr_to_label:
                label = addr_to_label[addr]
                pass 

            s = _replace_rip_rel_with_pool(line, const_pool_for_target)
            s = _rewrite_calls(s, project)

            def _repl_jmp(m):
                val = int(m.group(1), 16)
                if val in addr_to_label:
                    return f"{m.group(0).split()[0]} {addr_to_label[val]}"
                return m.group(0)
            s = re.sub(r'\b(?:j[a-z]{1,3}|jmp)\s+(0x[0-9a-fA-F]+)', _repl_jmp, s)

            s = _strip_addr_prefix(s)
            
            if addr in addr_to_label:
                s = f"{addr_to_label[addr]}; {s}"

            final_lines.append(s)

        seq = _ensure_prologue_first(final_lines)
        seq = _cut_after_function_end(seq)
        seq = [_normalize_operands(x) for x in seq]
        return _tighten_commas_semicolons(join_semicolon(seq))

    target_str = _process_one_asm_block(target_asm)

    final_callers = []
    for c_asm in caller_list:
        norm = _process_one_asm_block(c_asm)
        if norm:
            final_callers.append(f"FN{{{norm}}}")

    final_callees = []
    for c_asm in callee_list:
        norm = _process_one_asm_block(c_asm)
        if norm:
            final_callees.append(f"FN{{{norm}}}")

    final_header = ""
    if header and "HEADERS:" in header:
        final_header = header.replace("HEADERS:", "").strip().replace("\n", " ")
    
    if not final_header:
        full_text = target_str + " ".join(final_callers) + " ".join(final_callees)
        needed = set()
        if "printf" in full_text or "puts" in full_text: needed.add("#include <stdio.h>")
        if "malloc" in full_text or "free" in full_text: needed.add("#include <stdlib.h>")
        if needed: final_header = " ".join(sorted(needed))

    def fmt_list(lst): return " ".join(lst) if lst else "none"

    return (
        f"HEADER:{final_header} "
        f"TARGET:func;{target_str} "
        f"CALLERS:{fmt_list(final_callers)} "
        f"CALLEES:{fmt_list(final_callees)}"
    ).strip()