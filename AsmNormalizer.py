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
_CALL_RESOLVE_RADIUS = 48
_FUSE_LOOKBACK = 12
_CALL_SYMBOL_CACHE: dict[int, tuple[weakref.ReferenceType, dict[int, str], list[int]]] = {}

def _dbg(msg: str) -> None:
    if _LABEL_DEBUG:
        print(f"[LABEL_DEBUG] {msg}")

_PLT_SUFFIX_RE = re.compile(r'@plt$', re.IGNORECASE)
STREAM_STDERR = "STREAM_STDERR"
STREAM_STDOUT = "STREAM_STDOUT"
STREAM_UNKNOWN = "STREAM_UNKNOWN"
_STREAM_TOKENS = {STREAM_STDERR, STREAM_STDOUT}
_REG_CAPTURE_RE = re.compile(
    r'\b(?:mov|lea|movzx|movsxd)\s+((?:r|e)(?:di|si|dx|cx)|r8d?|r9d?)\s*,\s*([^;]+)',
    re.IGNORECASE
)
_REG_CANONICAL = {
    "edi": "rdi",
    "esi": "rsi",
    "edx": "rdx",
    "ecx": "rcx",
    "r8d": "r8",
    "r9d": "r9",
}
_STDIO_FDS = {"0", "0x0", "1", "0x1", "2", "0x2"}

_SECTION_SPLIT_RE = re.compile(r'\s+(TARGET:|BY|TO|Caller:|Callee:)', re.IGNORECASE)

_RET_RE = _re_end.compile(r'^\s*ret\s*;?\s*$', re.IGNORECASE)

def _store_call_symbol_map(project, mapping: dict[int, str]) -> None:
    try:
        ref = weakref.ref(project)
    except TypeError:
        ref = lambda: None  # type: ignore
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

    objects = []
    main_obj = getattr(loader, "main_object", None)
    if main_obj is not None:
        objects.append(main_obj)
    try:
        shared = getattr(loader, "shared_objects", {}) or {}
        objects.extend(shared.values())
    except Exception:
        pass

    def _add(addr, name, force_plt=False):
        if not isinstance(addr, int) or addr <= 0:
            return
        if not name:
            return
        base = _normalize_symbol_generic(name)
        if not base:
            return
        sym_name = f"{base}@plt" if force_plt and not base.endswith("@plt") else base
        mapping.setdefault(addr, sym_name)

    for obj in objects:
        try:
            for sym in getattr(obj, "symbols", []):
                if getattr(sym, "is_function", False):
                    _add(getattr(sym, "rebased_addr", None), getattr(sym, "name", None))
        except Exception:
            pass

        try:
            imports = getattr(obj, "imports", {}) or {}
            for name, sym in imports.items():
                addr = getattr(sym, "rebased_addr", None)
                if addr is None:
                    addr = getattr(sym, "resolved_addr", None)
                _add(addr, name, True)
        except Exception:
            pass

        try:
            plt_map = getattr(obj, "plt", {}) or {}
            for name, addr in plt_map.items():
                _add(addr, name, True)
        except Exception:
            pass

        try:
            rev = getattr(obj, "reverse_plt", {}) or {}
            for addr, name in rev.items():
                _add(addr, name, True)
        except Exception:
            pass

        try:
            pltgot = getattr(obj, "pltgot", None)
            if isinstance(pltgot, dict):
                for addr, name in pltgot.items():
                    _add(addr, name, True)
        except Exception:
            pass

    # already normalized imports from ElfFeatures
    mapping.update(_function_symbol_addrs(project))
    return mapping

def _tighten_commas_semicolons(s: str) -> str:
    s = re.sub(r'\s*,\s*', ',', s)
    s = re.sub(r'\s*;\s*', ';', s)
    return s

def _strip_addr_prefix(s: str) -> str:
    # "0x401234: mov ..." -> "mov ..."
    return re.sub(r'^\s*0x[0-9a-fA-F]+:\s*', '', s).strip()

def join_semicolon(seq: list[str]) -> str:
    seq = [x for x in (s.strip() for s in seq) if x]
    if not seq:
        return ""
    joined = ";".join(seq)
    return re.sub(r'\s+', ' ', joined).strip()

def _drop_block_lines(s: str) -> bool:
    if "Block @" in s:
        return True
    if re.match(r'^\s*;;;?\s*Block\s*@', s, re.IGNORECASE):
        return True
    return False

def _tokenize_model_input(raw_text: str) -> list[str]:
    if not raw_text:
        return []
    tokenized = re.sub(
        r'(?=(HEADERS:|#include|Target:|Caller:|Callee:|BY\b|TO\b|;;;?\s*Block\s*@|^\s*0x[0-9a-fA-F]+:))',
        '\n',
        raw_text,
        flags=re.MULTILINE | re.IGNORECASE
    )
    return [ln.strip() for ln in tokenized.splitlines() if ln.strip()]

def _resolve_call_symbol(project, abs_or_text: str) -> str | None:
    try:
        m = re.search(r'0x[0-9a-fA-F]+', abs_or_text)
        if not m:
            return None
        addr = int(m.group(0), 16)
    except Exception:
        return None

    mapping, sorted_addrs = _get_call_symbol_map(project)
    sym = mapping.get(addr)
    if sym:
        if _LABEL_DEBUG:
            _dbg(f"resolve_call: {hex(addr)} -> {sym} (direct)")
        return sym

    best_sym = None
    best_delta = _CALL_RESOLVE_RADIUS + 1

    idx = bisect_left(sorted_addrs, addr)

    def scan(start, step):
        nonlocal best_sym, best_delta
        j = start
        while 0 <= j < len(sorted_addrs):
            candidate_addr = sorted_addrs[j]
            delta = abs(candidate_addr - addr)
            if delta > _CALL_RESOLVE_RADIUS:
                break
            if delta < best_delta:
                best_delta = delta
                best_sym = mapping.get(candidate_addr)
            j += step

    scan(idx, -1)
    scan(idx, 1)

    if best_sym:
        mapping.setdefault(addr, best_sym)
        _store_call_symbol_map(project, mapping)
        if _LABEL_DEBUG:
            _dbg(f"resolve_call: {hex(addr)} -> {best_sym} (radius {best_delta:#x})")
        return best_sym

    if _LABEL_DEBUG:
        _dbg(f"resolve_call: {hex(addr)} unresolved")
    return None

def _rewrite_calls(line: str, project) -> str:
    def _sub(mm):
        sym = _resolve_call_symbol(project, mm.group(0))
        return f"call {sym}" if sym else "call <FUNC>"
    return re.sub(r'\bcall\s+0x[0-9a-fA-F]+', _sub, line)

# Simple symbol extraction from "call printf@plt".
_CALL_SYM_RE = re.compile(r'\bcall\s+([_a-zA-Z0-9@._]+)\b')

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

def _const_pool_lookup_maps(const_pool: dict | None):
    if not const_pool:
        return {}, {}

    cache = const_pool.get("__lookup_cache__")
    if isinstance(cache, dict):
        disp_map = cache.get("disp_map")
        tail_map = cache.get("tail_map")
        if isinstance(disp_map, dict) and isinstance(tail_map, dict):
            return disp_map, tail_map

    disp_map: dict[int, str] = {}
    tail_map: dict[str, str] = {}

    for key, info in const_pool.items():
        if not isinstance(info, dict):
            continue
        placeholder = info.get("placeholder")
        if not placeholder:
            continue
        for disp in info.get("rip_offsets") or []:
            disp_map[disp] = placeholder
        addr_int = info.get("address_int")
        if isinstance(addr_int, int) and addr_int > 0:
            hex_str = format(addr_int, "x")
            for ln in range(3, len(hex_str) + 1):
                tail = hex_str[-ln:].lower()
                tail_map.setdefault(tail, placeholder)

    const_pool["__lookup_cache__"] = {
        "disp_map": disp_map,
        "tail_map": tail_map,
    }
    return disp_map, tail_map

def _as_placeholder(tok: str) -> str | None:
    m = _PLACEHOLDER_RE.search(tok)
    return m.group(0) if m else None

def _looks_stderr_stdout(s: str) -> str | None:
    low = s.lower()
    if "stderr" in low:
        return STREAM_STDERR
    if "stdout" in low:
        return STREAM_STDOUT
    return None

def _track_simple_reg_moves(line: str, reg_state: dict[str,str]) -> None:
    m = _REG_CAPTURE_RE.search(line)
    if not m:
        # xor rdi, rdi → 0
        x = re.search(r'\bxor\s+((?:r|e)(?:di|si|dx|cx)|r8d?|r9d?)\s*,\s*\1\b', line, re.IGNORECASE)
        if x:
            reg = _REG_CANONICAL.get(x.group(1).lower(), x.group(1).lower())
            reg_state[reg] = "0"
        return
    reg_raw = m.group(1).lower()
    reg = _REG_CANONICAL.get(reg_raw, reg_raw)
    rhs = m.group(2).strip()
    rhs = re.sub(r'\s*@jmp\d+\b.*$', '', rhs, flags=re.IGNORECASE).strip()

    rhs_lower = rhs.lower()

    # copy from other tracked reg
    reg_copy = re.fullmatch(r'(?:r|e)(?:di|si|dx|cx)|r8d?|r9d?', rhs_lower)
    if reg_copy:
        src = _REG_CANONICAL.get(rhs_lower, rhs_lower)
        val = reg_state.get(src)
        if val is not None:
            reg_state[reg] = val
        return

    # placeholder
    ph = _as_placeholder(rhs)
    if ph:
        reg_state[reg] = ph
        return

    # stderr/stdout from comment
    st = _looks_stderr_stdout(line)
    if st:
        reg_state[reg] = st
        return

    st_rhs = _looks_stderr_stdout(rhs)
    if st_rhs:
        reg_state[reg] = st_rhs
        return

    # explicit STREAM_* text
    if "STREAM_STDERR" in rhs or "STREAM_STDOUT" in rhs:
        reg_state[reg] = STREAM_STDERR if "STDERR" in rhs else STREAM_STDOUT
        return

    # immediate
    if re.fullmatch(r'(?:0x[0-9a-fA-F]+|\d+)', rhs_lower):
        reg_state[reg] = rhs_lower
        return

_LIBC_PRINTF_FAMILY = {
    "printf": ("printf", 1),
    "puts": ("puts", 1),
    "putchar": ("putchar", 1),
    "fprintf": ("fprintf", 2),
    "dprintf": ("dprintf", 2),
    "sprintf": ("sprintf", 2),
    "snprintf": ("snprintf", 3),
}
_LIBC_ALIAS_MAP_RAW = {
    "__printf_chk": "printf",
    "__fprintf_chk": "fprintf",
    "__sprintf_chk": "sprintf",
    "__snprintf_chk": "snprintf",
    "__puts_chk": "puts",
    "__putchar_chk": "putchar",
    "__fwrite_chk": "fwrite",
    "__fputs_chk": "fputs",
    "__libc_system": "system",
    "__libc_write": "write",
    "__libc_send": "send",
    "__libc_recv": "recv",
    "__libc_exit": "exit",
    "__libc_fwrite": "fwrite",
    "__libc_fputs": "fputs",
    "__libc_fprintf": "fprintf",
    "__libc_printf": "printf",
    "__libc_puts": "puts",
    "__libc_perror": "perror",
    "__libc_putc": "putchar",
    "__libc_putchar": "putchar",
    "__libc_exit_group": "exit",
    "_exit": "exit",
    "exit": "exit",
}
_LIBC_ALIAS_MAP = {k.lower(): v for k, v in _LIBC_ALIAS_MAP_RAW.items()}

def _normalize_symbol_generic(sym: str | None) -> str:
    if not sym:
        return ""
    base = sym.strip()
    base = base.split('@@', 1)[0]
    base = _PLT_SUFFIX_RE.sub("", base)
    if '@' in base:
        base = base.split('@', 1)[0]
    base = base.strip()
    if not base:
        return ""
    lower = base.lower()
    if lower in _LIBC_ALIAS_MAP:
        return _LIBC_ALIAS_MAP[lower]
    # eigene Symbole nicht zwangs-lowern
    return base

def _normalize_libc_printf_symbol(sym: str | None) -> str:
    return _normalize_symbol_generic(sym)

def _fuse_libc_calls(seq_lines: list[str]) -> list[str]:
    out = []
    i = 0
    n = len(seq_lines)
    while i < n:
        line = seq_lines[i]
        mcall = _CALL_SYM_RE.search(line)
        if not mcall:
            out.append(line)
            i += 1
            continue

        raw_callee = mcall.group(1)
        callee = _normalize_libc_printf_symbol(raw_callee)
        fam = _LIBC_PRINTF_FAMILY.get(callee)

        reg_state: dict[str,str] = {}
        win_start = max(0, i - _FUSE_LOOKBACK)
        for j in range(win_start, i):
            _track_simple_reg_moves(seq_lines[j], reg_state)

        def _canon_arg(val: str | None) -> str | None:
            if not val:
                return None
            v = val.strip()
            if _PLACEHOLDER_RE.match(v):
                return v
            if v in _STREAM_TOKENS:
                return v
            if re.fullmatch(r'(?:0x[0-9a-fA-F]+|\d+)', v):
                return v
            return None

        def _arg(reg: str):
            return reg_state.get(reg)

        fused = None

        if fam:
            fname, _ = fam
        else:
            fname = callee

        # ----- printf -----
        if fname == "printf":
            fmt = _arg("rdi") or _arg("rsi")

            # nur fusen, wenn es wirklich einer unserer Platzhalter ist
            if fmt and _PLACEHOLDER_RE.match(fmt):
                # evtl. weitere register-args einsammeln
                arg_candidates = [_arg("rsi"), _arg("rdx"), _arg("rcx"), _arg("r8"), _arg("r9")]
                extra = [a for a in arg_candidates if a and not _PLACEHOLDER_RE.match(a)]
                if extra:
                    fused = "printf(" + ",".join([fmt] + extra) + ")"
                else:
                    fused = f"printf({fmt})"
            else:
                # kein Platzhalter → gar nicht fusen
                fused = None

        # ----- fprintf -----
        elif fname == "fprintf":
            stream = _arg("rdi")
            fmt = _arg("rsi")
            if fmt and _PLACEHOLDER_RE.match(fmt):
                extra = []
                for r in ("rdx", "rcx", "r8", "r9"):
                    v = _arg(r)
                    cv = _canon_arg(v)
                    if cv:
                        extra.append(cv)
                if stream == STREAM_STDOUT:
                    if extra:
                        fused = f"printf({fmt}," + ",".join(extra) + ")"
                    else:
                        fused = f"printf({fmt})"
                elif stream == STREAM_STDERR:
                    if extra:
                        fused = f"fprintf(STREAM_STDERR,{fmt}," + ",".join(extra) + ")"
                    else:
                        fused = f"fprintf(STREAM_STDERR,{fmt})"
                else:
                    if extra:
                        fused = f"fprintf({stream or 'STREAM_UNKNOWN'},{fmt}," + ",".join(extra) + ")"
                    else:
                        fused = f"fprintf({stream or 'STREAM_UNKNOWN'},{fmt})"

        # ----- dprintf -----
        elif fname == "dprintf":
            fd = _arg("rdi")
            fmt = _arg("rsi") or _arg("rdx") or _arg("rcx")
            if fmt and _PLACEHOLDER_RE.match(fmt):
                extra = []
                for r in ("rdx", "rcx", "r8", "r9"):
                    v = _arg(r)
                    cv = _canon_arg(v)
                    if cv:
                        extra.append(cv)
                if fd in _STDIO_FDS:
                    if extra:
                        fused = f"printf({fmt}," + ",".join(extra) + ")"
                    else:
                        fused = f"printf({fmt})"
                else:
                    if extra:
                        fused = f"dprintf({fmt}," + ",".join(extra) + ")"
                    else:
                        fused = f"dprintf({fmt})"

        elif fname == "puts":
            ph = _arg("rdi") or _arg("rsi")
            if ph and _PLACEHOLDER_RE.match(ph):
                fused = f"printf({ph})"

        elif fname == "putchar":
            a1 = _arg("rdi") or _arg("rsi")
            if a1:
                fused = f"putchar({a1})"

        elif fname == "perror":
            data = _arg("rdi")
            if data and _PLACEHOLDER_RE.match(data):
                fused = f"perror({data})"
            else:
                fused = "perror(NULL)"

        elif fname == "exit":
            code = _arg("rdi")
            if code and re.fullmatch(r'(?:0x[0-9a-fA-F]+|\d+)', code):
                fused = f"exit({code})"
            else:
                fused = "exit()"

        elif fname == "write":
            buf = _arg("rsi") or _arg("rdx")
            fd = _arg("rdi")
            cbuf = _canon_arg(buf)
            if cbuf and fd and fd not in _STREAM_TOKENS:
                fused = f"write({fd},{cbuf})"

        elif fname == "send":
            buf = _arg("rsi") or _arg("rdx")
            sock = _arg("rdi")
            cbuf = _canon_arg(buf)
            if cbuf and sock:
                fused = f"send({sock},{cbuf})"

        elif fname == "recv":
            sock = _arg("rdi")
            if sock:
                fused = f"recv({sock})"

        if _LABEL_DEBUG:
            _dbg(f"libc-fuse: raw={raw_callee} norm={fname} regs={reg_state} -> {fused}")

        if fused:
            out.append(fused)
            i += 1
            continue

        out.append(line)
        i += 1

    return out

def _replace_rip_rel_with_pool(line: str, const_pool: dict) -> str:
    if not const_pool:
        return line

    disp_map, tail_map = _const_pool_lookup_maps(const_pool)

    def _strip_ptr_prefix_before_placeholder(text: str) -> str:
        return _PTR_TO_PLACEHOLDER_RE.sub(r'\1', text)

    def _sub(match: re.Match) -> str:
        sign = match.group('sign') or '+'
        disp_hex = match.group('hex')
        disp_val = int(disp_hex, 16)
        if sign == '-':
            disp_val = -disp_val

        placeholder = disp_map.get(disp_val)
        if not placeholder:
            placeholder = tail_map.get(disp_hex.lower())

        if placeholder:
            if _LABEL_DEBUG:
                _dbg(f"rip-replace: {match.group(0)} -> {placeholder} (disp={disp_val:+#x})")
            return placeholder

        return match.group(0).replace(" ", "")

    new_line = _RIP_REL_OPERAND_RE.sub(_sub, line)
    if new_line != line:
        new_line = _strip_ptr_prefix_before_placeholder(new_line)
    return new_line

def _ofs_map_for_function(lines: list[str]) -> dict[str, str]:
    key_to_id = {}
    next_id = 0

    def _assign(key):
        nonlocal next_id
        if key not in key_to_id:
            key_to_id[key] = f"ofs{next_id}"
            next_id += 1
        return key_to_id[key]

    for s in lines:
        if "fs:" in s:
            continue
        for m in re.finditer(r'\[(?:[^\]]*?)\]', s):
            key = m.group(0)
            if "rip" in key:
                continue
            _assign(key)

        for m in re.finditer(r'\b0x[0-9a-fA-F]+\b', s):
            if "fs:" in s:
                continue
            if "PTR" in s:
                _assign(m.group(0))

    return key_to_id

def _apply_ofs_map(line: str, ofs_map: dict[str, str]) -> str:
    if "fs:" in line:
        return line

    def _repl_bracket(m):
        key = m.group(0)
        k = ofs_map.get(key, None)
        if not k:
            return key
        return k

    line = re.sub(r'\[(?:[^\]]*?)\]', _repl_bracket, line)

    def _repl_hex(mm):
        key = mm.group(0)
        k = ofs_map.get(key, None)
        return k if k else key

    if "PTR" in line:
        line = re.sub(r'\b0x[0-9a-fA-F]+\b', _repl_hex, line)
    return line

def _rewrite_branches_to_labels(lines: list[str]) -> list[str]:
    jcc_pat = re.compile(r'\b(j[a-z]{1,3})\s+0x[0-9a-fA-F]+', re.IGNORECASE)
    jmp_pat = re.compile(r'\bjmp\s+0x[0-9a-fA-F]+', re.IGNORECASE)
    addr_pat = re.compile(r'0x[0-9a-fA-F]+')

    targets = []
    for s in lines:
        for mm in jcc_pat.finditer(s):
            a = addr_pat.search(mm.group(0))
            if a:
                targets.append(a.group(0))
        for mm in jmp_pat.finditer(s):
            a = addr_pat.search(mm.group(0))
            if a:
                targets.append(a.group(0))

    targets = list(dict.fromkeys(targets))
    idx_map = {addr: i for i, addr in enumerate(targets)}

    out = []
    for s in lines:
        def _br_sub(mm):
            a = addr_pat.search(mm.group(0))
            if not a:
                return mm.group(0)
            n = idx_map.get(a.group(0), None)
            if n is None:
                return mm.group(0)
            op = mm.group(0).split()[0]
            return f"{op} @jmp{n}"
        s2 = re.sub(r'\b(j[a-z]{1,3})\s+0x[0-9a-fA-F]+', _br_sub, s, flags=re.IGNORECASE)
        s2 = re.sub(r'\bjmp\s+0x[0-9a-fA-F]+', _br_sub, s2, flags=re.IGNORECASE)
        out.append(s2)

    if not idx_map:
        return out

    labeled = []
    pending_label = None
    branch_prefix_re = re.compile(r'^(?:j[a-z]{1,3}|jmp)\b', re.IGNORECASE)
    label_suffix_re = re.compile(r'@jmp(\d+)')

    for s in out:
        line = s
        if pending_label and pending_label not in line:
            line = f"{line} {pending_label}"
        pending_label = None

        labeled.append(line)

        if branch_prefix_re.match(line):
            m = label_suffix_re.search(line)
            if m:
                pending_label = f"@jmp{m.group(1)}"

    return labeled

def _looks_like_new_prologue(line: str) -> bool:
    stripped = line.strip().lower()
    if not stripped:
        return False
    # gängige neuen Funktionsanfänge
    if stripped.startswith("endbr64"):
        return True
    if stripped.startswith("push rbp") or stripped.startswith("push rbx"):
        return True
    return False

def _cut_after_function_end(seq: list[str]) -> list[str]:
    """
    Emit everything that plausibly belongs to the current function.  Only stop
    after we saw a real return and the following instruction looks like a new
    prologue (or clearly unrelated code).  Common post-ret tails such as stack
    canary stubs, int3 padding, nops, and dangling @jmp labels are preserved.
    """
    out: list[str] = []
    saw_ret = False

    def _allowed_tail(line: str) -> bool:
        stripped = line.strip().lower()
        if not stripped:
            return True
        if stripped.startswith("ret"):
            return True
        if stripped.startswith(("call __stack_chk_fail", "jmp __stack_chk_fail", "ud2", "int3", "nop")):
            return True
        if stripped.startswith(("align", "db", "dw", "dd", "dq")):
            return True
        if stripped.startswith("@jmp"):
            return True
        return False

    for line in seq:
        if saw_ret:
            if _looks_like_new_prologue(line):
                break
            if not _allowed_tail(line):
                break
        out.append(line)
        if _RET_RE.match(line):
            saw_ret = True
    return out



def normalize_model_input_with_context_groups(
    raw_text: str,
    project,
    target_func_obj,
    const_pool_for_target: dict
) -> str:
    lines = _tokenize_model_input(raw_text)

    includes = []
    groups = []
    cur = []
    section = None

    for s in lines:
        s_lower = s.lower()
        s_upper = s.upper()

        if s_lower.startswith("headers:"):
            continue
        if s_lower.startswith("#include"):
            if s.strip() == "#include":
                continue
            includes.append(s)
            continue
        if s_lower.startswith("target:"):
            if cur and section:
                groups.append((section, cur))
                cur = []
            section = 'target'
            continue
        if s_upper == "BY":
            if cur and section:
                groups.append((section, cur))
                cur = []
            groups.append(("BY", []))
            section = None
            continue
        if s_upper == "TO" or s_lower.startswith("callee:"):
            if s_upper == "TO":
                groups.append(("TO", []))
                section = None
                continue
            if cur and section:
                groups.append((section, cur))
                cur = []
            section = 'callee'
            continue
        if s_lower.startswith("caller:"):
            if cur and section:
                groups.append((section, cur))
                cur = []
            section = 'caller'
            continue

        if _drop_block_lines(s):
            continue

        s = _strip_addr_prefix(s)
        if not s:
            continue

        if section in {'caller', 'callee'} and cur and _looks_like_new_prologue(s):
            groups.append((section, cur))
            cur = []

        s = _replace_rip_rel_with_pool(s, const_pool_for_target)
        s = _rewrite_calls(s, project)

        cur.append(s)

    if cur and section:
        groups.append((section, cur))

    def _ensure_prologue_first(seq: list[str]) -> list[str]:
        for idx, line in enumerate(seq):
            if line.strip().lower().startswith("endbr64"):
                if idx == 0:
                    return seq
                return [seq[idx]] + seq[:idx] + seq[idx+1:]
        return seq

    def _norm_seq(seq: list[str]) -> str:
        if not seq:
            return ""
        seq = _ensure_prologue_first(seq)
        seq2 = _rewrite_branches_to_labels(seq)
        seq2 = _fuse_libc_calls(seq2)
        seq2 = _cut_after_function_end(seq2)
        ofs_map = _ofs_map_for_function(seq2)
        seq3 = [_apply_ofs_map(x, ofs_map) for x in seq2]
        joined = join_semicolon(seq3)
        if not joined:
            return ""
        return _tighten_commas_semicolons(joined)

    parts = []
    if includes:
        parts.append("HEADERS:" + ",".join(includes))

    # TARGET zuerst (alle vorhandenen Segmente nummerieren)
    target_idx = 0
    for name, seq in groups:
        if name == "target":
            target_idx += 1
            tag = "TARGET:" if target_idx == 1 else f"TARGET{target_idx}:"
            parts.append(tag + _norm_seq(seq))

    # BY (Caller)
    added_by = False
    for name, seq in groups:
        if name == "caller":
            grp = _norm_seq(seq)
            if grp:
                if not added_by:
                    parts.append("BY")
                    added_by = True
                parts.append(grp)

    # TO (Callee)
    added_to = False
    for name, seq in groups:
        if name == "callee":
            grp = _norm_seq(seq)
            if grp:
                if not added_to:
                    parts.append("TO")
                    added_to = True
                parts.append(grp)

    # ======= AB HIER darfst du erst den finalen String bauen =======
    out = " ".join([p for p in parts if p])

    # auto-header detection
    needed = set()
    low = out.lower()
    if "printf(" in out or "fprintf(" in out or "puts(" in out or "putchar(" in out:
        needed.add("#include <stdio.h>")
    if "strlen(" in out or "strcmp(" in out or "strcpy(" in out:
        needed.add("#include <string.h>")
    if "malloc(" in out or "free(" in out or "exit(" in out:
        needed.add("#include <stdlib.h>")
    if "assert(" in out or "__assert_fail@" in out:
        needed.add("#include <assert.h>")

    if out.startswith("HEADERS:"):
        m = _SECTION_SPLIT_RE.search(out)
        if m:
            header_part = out[:m.start()]
            rest_part = out[m.start():]
        else:
            header_part = out
            rest_part = ""

        existing = header_part[len("HEADERS:"):].split(",")
        existing = [e for e in (x.strip() for x in existing) if e and e != "#include"]

        for h in needed:
            if h not in existing:
                existing.append(h)

        out = "HEADERS:" + ",".join(existing)
        if rest_part:
            out += " " + rest_part.lstrip()
    else:
        if needed:
            out = "HEADERS:" + ",".join(sorted(needed)) + " " + out

    out = _tighten_commas_semicolons(out)
    return out
