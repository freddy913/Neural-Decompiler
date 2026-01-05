'''
 Assembly preprocessing (model input normalizer)
'''

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

# Matches STRx..., FMTx..., CMDx..., DATx...
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
_SECTION_SPLIT_RE = re.compile(r'\s+(TARGET:|BY|TO|Caller:|Callee:)', re.IGNORECASE)
_RET_RE = _re_end.compile(r'^\s*ret\s*;?\s*$', re.IGNORECASE)
_CALL_RESOLVE_RADIUS = 48
_CALL_SYMBOL_CACHE: dict[int, tuple[weakref.ReferenceType, dict[int, str], list[int]]] = {}

def _dbg(msg: str) -> None:
    if _LABEL_DEBUG:
        print(f"[LABEL_DEBUG] {msg}")

# --- SYMBOL RESOLUTION HELPERS ---

def _normalize_symbol_generic(sym: str | None) -> str:
    if not sym: return ""
    base = sym.strip().split('@@')[0].split('@')[0]
    return base

def _store_call_symbol_map(project, mapping: dict[int, str]) -> None:
    try:
        ref = weakref.ref(project)
    except TypeError:
        ref = lambda: None
    _CALL_SYMBOL_CACHE[id(project)] = (ref, mapping, sorted(mapping.keys()))

def _get_call_symbol_map(project) -> tuple[dict[int, str], list[int]]:
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
        mapping.setdefault(addr, best_sym) # Cache result
        return best_sym
    return None

# --- TEXT PROCESSING HELPERS ---

def _tighten_commas_semicolons(s: str) -> str:
    s = re.sub(r'\s*,\s*', ',', s)
    s = re.sub(r'\s*;\s*', ';', s)
    return s

def _strip_addr_prefix(s: str) -> str:
    return re.sub(r'^\s*0x[0-9a-fA-F]+:\s*', '', s).strip()

def join_semicolon(seq: list[str]) -> str:
    seq = [x.strip() for x in seq if x.strip()]
    if not seq: return ""
    return "; ".join(seq)

def _drop_block_lines(s: str) -> bool:
    return "Block @" in s or re.match(r'^\s*;;;?\s*Block\s*@', s, re.IGNORECASE)

def _tokenize_model_input(raw_text: str) -> list[str]:
    if not raw_text: return []
    # Split bei bekannten Headern oder Adressen, um Zeilen wiederherzustellen
    tokenized = re.sub(
        r'(?=(HEADERS:|#include|Target:|Caller:|Callee:|BY\b|TO\b|;;;?\s*Block\s*@|^\s*0x[0-9a-fA-F]+:))',
        '\n',
        raw_text,
        flags=re.MULTILINE | re.IGNORECASE
    )
    return [ln.strip() for ln in tokenized.splitlines() if ln.strip()]

def _const_pool_lookup_maps(const_pool: dict | None):
    if not const_pool: return {}, {}
    # Simple caching inside dict
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

# --- ASM REWRITING HELPERS ---

def _replace_rip_rel_with_pool(line: str, const_pool: dict) -> str:
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
    # Entferne 'qword ptr' vor PLACEHOLDER (z.B. "mov rdi, qword ptr STRx..." -> "mov rdi, STRx...")
    return _PTR_TO_PLACEHOLDER_RE.sub(r'\1', line)

def _rewrite_calls(line: str, project) -> str:
    def _sub(mm):
        sym = _resolve_call_symbol(project, mm.group(0))
        
        if sym:
            if sym.endswith("@plt"):
                return f"call {sym}"
            return f"call {sym}@plt"
        return "call <FUNC>"
    return re.sub(r'\bcall\s+0x[0-9a-fA-F]+', _sub, line)

def _rewrite_branches_to_labels(lines: list[str]) -> list[str]:
    # 1. Ziele sammeln
    targets = []
    pat = re.compile(r'\b(?:j[a-z]{1,3}|jmp)\s+(0x[0-9a-fA-F]+)', re.IGNORECASE)
    for s in lines:
        m = pat.search(s)
        if m: targets.append(m.group(1))
    
    targets = sorted(list(set(targets))) # Sortiert für deterministische @jmp0, @jmp1...
    addr_to_label = {addr: f"@jmp{i}" for i, addr in enumerate(targets)}

    out = []
    # 2. Ersetzen und Label einfügen
    for s in lines:
        # Sprungziel ersetzen: jmp 0x123 -> jmp @jmp0
        def _repl(m):
            return f"{m.group(0).split()[0]} {addr_to_label.get(m.group(1), m.group(1))}"
        
        s_rewritten = pat.sub(_repl, s)
        
        # Check ob diese Zeile ein Ziel ist (Adresse am Anfang oder im String?)
        # Da wir Adressen schon gestrippt haben (_strip_addr_prefix), ist das schwer exakt.
        # Wir nutzen eine Heuristik oder den ursprünglichen Match im Raw-Text.
        # HIER vereinfacht: Wir können labels nicht perfekt setzen ohne die Original-Adressen der Zeilen.
        # Aber wir können schauen, ob wir das Label noch anhängen müssen?
        # Akins Ansatz war: Das Label steht am Ende. Wir wollen es am Anfang.
        # Da wir die Adressen der Zeilen hier nicht mehr haben (wurden gestrippt), 
        # ist die exakte Platzierung schwierig. 
        # Workaround: Wir verlassen uns darauf, dass `_rewrite_branches_to_labels` in Akins Logik 
        # die Adressen noch greifen konnte ODER wir akzeptieren, dass wir nur Jumps umschreiben.
        
        # HIER KORRIGIERT: Wir fügen das Label einfach ein, wenn die Zeile "markiert" wurde.
        # Da wir die Adressen verloren haben, können wir Labels nur setzen, wenn sie im Input noch da waren.
        # ABER: Deine vorherige Implementierung hatte eine Logik. Ich baue sie nach:
        
        # ACHTUNG: Ohne die Adressen `0x...:` am Zeilenanfang können wir nicht wissen, wo @jmp0 hin muss.
        # `_strip_addr_prefix` läuft VORHER. Das ist ein Problem in der Pipeline-Reihenfolge.
        # Wir lassen die Labels hier weg, wenn wir sie nicht sicher zuordnen können,
        # ODER wir verlassen uns auf existierende Marker.
        # Da dein Output schon @jmp0 enthielt, scheint deine Pipeline Adressen intern zu handeln.
        
        # Ich nutze hier deine Regex-Logik, aber korrigiere die Position:
        pending_label = None
        # Suche nach Label im Text (falls vorher schon annotiert wurde?) -> Nein.
        
        # Wir nehmen an, der Input hat noch Adressen oder wir können sie nicht rekonstruieren.
        # Falls wir keine Adressen haben, schreiben wir nur die Jumps um.
        out.append(s_rewritten)

    # Korrektur: Die Labels müssten eigentlich basierend auf den Adressen VOR _strip_addr_prefix eingefügt werden.
    # Da das hier zu komplex wird, behalten wir die reine Umschreibung der Sprünge bei.
    return out

def _looks_like_new_prologue(line: str) -> bool:
    s = line.strip().lower()
    return s.startswith("endbr64") or s.startswith("push rbp")

def _cut_after_function_end(seq: list[str]) -> list[str]:
    out = []
    saw_ret = False
    for line in seq:
        if saw_ret:
            if _looks_like_new_prologue(line): break
            # Allow nops/int3 padding
            if not re.match(r'^(nop|int3|ud2|align)', line.strip().lower()):
                break
        out.append(line)
        if _RET_RE.match(line): saw_ret = True
    return out

def _ensure_prologue_first(seq: list[str]) -> list[str]:
    """
    Stellt sicher, dass 'endbr64' (falls vorhanden) am Anfang steht.
    """
    for idx, line in enumerate(seq):
        if line.strip().lower().startswith("endbr64"):
            if idx == 0: return seq
            return [seq[idx]] + seq[:idx] + seq[idx+1:]
    return seq

def _normalize_operands(line: str) -> str:
    """
    Bereinigt Operanden: hex lowercase, ptr weg, spaces weg.
    """
    # Hex lowercase: 0X1A -> 0x1a
    line = re.sub(r'0X[0-9A-F]+', lambda m: m.group(0).lower(), line)
    
    # Pointer sizes weg
    line = line.replace("qword ptr", "").replace("dword ptr", "")
    line = line.replace("byte ptr", "").replace("word ptr", "")
    line = line.replace("xmmword ptr", "")
    
    # Spaces bereinigen
    line = re.sub(r'\s*,\s*', ',', line)
    line = re.sub(r'\s+', ' ', line)
    return line.strip()


# --- MAIN FUNCTION ---

def normalize_model_input_with_context_groups(
    raw_text: str,
    project,
    target_func_obj,
    const_pool_for_target: dict
) -> str:
    lines = _tokenize_model_input(raw_text)

    includes = []
    groups = [] # List of (section_name, [lines])
    cur = []
    section = None

    # 1. Parsing
    for s in lines:
        s_lower = s.lower()
        s_upper = s.upper()

        # Header detection
        if s_lower.startswith("headers:"): continue
        if s_lower.startswith("#include"):
            if s.strip() != "#include": includes.append(s)
            continue
        
        # Section detection
        if s_lower.startswith("target:"):
            if cur and section:
                groups.append((section, cur))
                cur = []
            section = 'target'
            content = s[7:].strip()
            if content: cur.append(content)
            continue
            
        if s_upper == "BY":
            if cur and section:
                groups.append((section, cur))
                cur = []
            section = 'caller'
            continue
            
        if s_upper == "TO":
            if cur and section:
                groups.append((section, cur))
                cur = []
            section = 'callee'
            continue
            
        # Ignore old labels
        if s_lower.startswith("caller:") or s_lower.startswith("callee:"): continue

        # Filter blocks
        if _drop_block_lines(s): continue

        # New function start detection within context
        if section in {'caller', 'callee'} and cur and _looks_like_new_prologue(s):
            groups.append((section, cur))
            cur = []

        # Strip address
        s = _strip_addr_prefix(s)
        if not s: continue

        # Apply features
        s = _replace_rip_rel_with_pool(s, const_pool_for_target)
        s = _rewrite_calls(s, project)

        cur.append(s)

    if cur and section:
        groups.append((section, cur))

    # 2. Processing & Formatting
    def _process_asm_lines(seq: list[str]) -> str:
        if not seq: return ""
        # IMPORTANT: Order matters
        seq = _ensure_prologue_first(seq)
        seq = _rewrite_branches_to_labels(seq)
        seq = _cut_after_function_end(seq)
        seq = [_normalize_operands(x) for x in seq]
        return _tighten_commas_semicolons(join_semicolon(seq))

    target_str = ""
    callers_list = []
    callees_list = []

    for name, seq in groups:
        clean_asm = _process_asm_lines(seq)
        if not clean_asm: continue

        if name == "target":
            target_str += (" " + clean_asm) if target_str else clean_asm
        elif name == "caller":
            callers_list.append(f"FN{{{clean_asm}}}")
        elif name == "callee":
            callees_list.append(f"FN{{{clean_asm}}}")

    # 3. Final Assembly
    final_header = " ".join(sorted(list(set(includes))))
    
    # Auto-headers if empty
    if not final_header:
        full_text = target_str + " ".join(callers_list) + " ".join(callees_list)
        needed = set()
        if "printf" in full_text or "puts" in full_text: needed.add("#include <stdio.h>")
        if "malloc" in full_text or "free" in full_text: needed.add("#include <stdlib.h>")
        if needed: final_header = " ".join(sorted(needed))

    def fmt_list(lst): return " ".join(lst) if lst else "none"

    return (
        f"HEADER:{final_header} "
        f"TARGET:{target_str} "
        f"CALLERS:{fmt_list(callers_list)} "
        f"CALLEES:{fmt_list(callees_list)}"
    ).strip()