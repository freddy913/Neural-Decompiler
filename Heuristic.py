import os
import re
import shutil
import subprocess
import random

from ElfFeatures import get_function_data, get_token_count
from Config import BASIC_SCORE, DEGREE, JUNK_FUNCTIONS, MYTOKENIZER, RUNTIME_ENTRY_FUNCTIONS
from HintsAndLabels import pick_best_match
from t5_decompiler import decompile_asm_string

'''
SECTION: Candidate Selection Heuristic
'''
def get_context_candidates(target_func, cfg):
    """
    retrieves direct neighbours in the call graph
    """
    if not target_func:
        return {'callers': set(), 'callees': set()}

    callgraph = cfg.functions.callgraph
    callers = set()
    callees = set()

    try:
        for callee_addr in callgraph.successors(target_func.addr):
            callee_func = cfg.functions.get_by_addr(callee_addr)
            if callee_func: callees.add(callee_func)
    except Exception as e:
        pass

    try:
        for caller_addr in callgraph.predecessors(target_func.addr):
            caller_func = cfg.functions.get_by_addr(caller_addr)
            if caller_func: callers.add(caller_func)
    except Exception as e:
        pass

    return {'callers': callers, 'callees': callees}

def get_context_candidates_with_degrees(target_func, cfg, degrees=DEGREE):  # TODO: validate default degree depth
    """
    retrieves neighbours in the call graph up to a certain degree
    1 = direct callers/callees
    2 = callers/callees of callers/callees
    etc.
    """
    if not target_func or degrees < 1:
        return {'callers': {}, 'callees': {}}

    callers = {}  # Map function_obj -> smallest degree observed.
    callees = {}  # Map function_obj -> smallest degree observed.

    nodes_to_search = {target_func}
    visited_addrs = set()

    for degree in range(1, degrees + 1):
        next_nodes = set()

        for node in nodes_to_search:
            # Avoid re-processing the same node address.
            if node is None or node.addr in visited_addrs:
                continue

            try:
                neigh = get_context_candidates(node, cfg)
                node_callers = neigh.get('callers', set()) or set()
                node_callees = neigh.get('callees', set()) or set()
            except Exception:
                node_callers = set()
                node_callees = set()

            for f in node_callers:
                if f is None:
                    continue
                # Skip already-visited addresses and skip the target function itself.
                if not hasattr(f, "addr") or f.addr in visited_addrs or f.addr == target_func.addr:
                    continue
                # Record the smallest degree seen for this function.
                prev = callers.get(f)
                if prev is None or degree < prev:
                    callers[f] = degree
                next_nodes.add(f)

            for f in node_callees:
                if f is None:
                    continue
                # Skip already-visited addresses and skip the target function itself.
                if not hasattr(f, "addr") or f.addr in visited_addrs or f.addr == target_func.addr:
                    continue
                prev = callees.get(f)
                if prev is None or degree < prev:
                    callees[f] = degree
                next_nodes.add(f)

            visited_addrs.add(node.addr)

        # Prepare for next round: only include nodes not yet visited.
        nodes_to_search = {f for f in next_nodes if f and hasattr(f, "addr") and f.addr not in visited_addrs and f.addr != target_func.addr}

        if not nodes_to_search:
            break

    return {'callers': callers, 'callees': callees}

def remove_junk_functions(funcs):
    """
    Filter out functions flagged as junk.
    """
    return [func for func in funcs if func[0].name not in JUNK_FUNCTIONS]

def _is_trampoline_or_tiny(func_obj, max_blocks=2, max_insns=8):
    """
    Remove wrapper / trampoline functions. Mostly 1 basic block, very few instructions.
    """
    try:
        blocks = list(func_obj.blocks)
    except Exception:
        return False  # Assume not a trampoline if inspection fails.
    
    if len(blocks) > max_blocks:
        return False  # Too many blocks to be a simple trampoline.

    insn_count = 0
    for b in blocks:
        try:
            cap = b.capstone
        except Exception:
            continue
        insns = getattr(cap, "insns", [])
        insn_count += len(insns)

    return insn_count <= max_insns


def is_relevant_user_like_function(func_obj, target_func_obj=None):
    """
    Runtime safe filtering logic.
    Uses NO ground truth .c files.
    Returns True = keep as context candidate
    """

    if func_obj is None:
        return False

    name = getattr(func_obj, "name", "")
    if not name:
        return False

    if target_func_obj is not None and func_obj.addr == target_func_obj.addr:
        return True

    if name == "main":
        return True

    if name in RUNTIME_ENTRY_FUNCTIONS:
        return False
    
    # Drop PLT stubs (libc/syscalls etc.).
    if getattr(func_obj, "is_plt", False):
        return False

    # Drop internal runtime helpers with "__" prefix.
    if name.startswith("__"):
        return False

    if _is_trampoline_or_tiny(func_obj):
        return False

    return True


def filter_candidate_funcs_runtime_safe(funcs, target_func_obj):
    """
    Returns only the entries that are ok for context.
    Uses only runtime-safe info.
    """
    cleaned = []
    for func_obj, degree, role in funcs:
        if is_relevant_user_like_function(func_obj, target_func_obj=target_func_obj):
            cleaned.append((func_obj, degree, role))
    return cleaned


def is_leaf_function(func, callgraph):
    """
    checks if a function is a leaf function (no outgoing calls)
    """
    try:
        return callgraph.out_degree(func.addr) == 0
    except Exception:
        return False

def split_target_into_chunks(target_func_data, tokenizer=MYTOKENIZER, max_chunk_tokens=3500, max_chunks=3):
    """
    Split assembly text into chunks bounded by token count limits.
    Returns list of assembly snippets.
    """
    asm = target_func_data.get("assembly", "") or ""
    if not asm:
        return []

    lines = asm.splitlines()
    chunks: list[str] = []
    current_lines: list[str] = []

    for line in lines:
        current_lines.append(line)
        joined = "\n".join(current_lines)
        try:
            tok_count = len(tokenizer(joined, add_special_tokens=False).input_ids)
        except Exception:
            tok_count = max(len(joined) // 4, 1)

        if tok_count >= max_chunk_tokens:
            chunks.append(joined)
            current_lines = []
            if len(chunks) >= max_chunks:
                break

    if current_lines and len(chunks) < max_chunks:
        chunks.append("\n".join(current_lines))

    return chunks

def extract_struct_fingerprint(assembly: str):
    # sehr grob TODO
    offs = set()
    for line in assembly.splitlines():
        m = re.search(r'\[rdi\+0x([0-9a-fA-F]+)\]', line)
        if m:
            offs.add(int(m.group(1), 16))
    return offs

def build_candidate_func_data(candidate_funcs, project, cfg, tokenizer=MYTOKENIZER):
    """
    takes the raw candidates (func_obj, degree, role), extracts the assembly and token counts
    """
    candidate_func_data = {
        'func_names': [],
        'all_functions': [],
        'total_token_count': 0
    }

    for func, degree, role in candidate_funcs:
        func_data = get_function_data(func, project, tokenizer)
        name = func_data['name'] or 'unknown_function'

        try:
            is_leaf = is_leaf_function(func, cfg.functions.callgraph)
        except Exception as e:
            is_leaf = False

        entry = {
            'function_obj': func,
            'name': name,
            'assembly': func_data['assembly'],
            'token_count': func_data['token_count'],
            'degree': degree,
            'role': role,
            'is_leaf': is_leaf,
            'score': BASIC_SCORE,
            'struct_fp': extract_struct_fingerprint(func_data["assembly"]), 
        }

        candidate_func_data['all_functions'].append(entry)
        candidate_func_data['func_names'].append(entry['name'])
        candidate_func_data['total_token_count'] += func_data['token_count']
    # Sorted ascending by degree for deterministic processing.  # TODO: consider secondary sort by token size.

    candidate_func_data['all_functions'].sort(key=lambda x: x.get('degree', float('inf')))
    # Update func_names to match the new ordering.
    candidate_func_data['func_names'] = [entry.get('name') for entry in candidate_func_data['all_functions']]

    return candidate_func_data

''' 
SECTION: Header Mapping and Extraction
'''
HEADER_MAP = {
    "<stdio.h>": [
        "printf", "fprintf", "sprintf", "snprintf",
        "puts", "putchar", "perror",
        "scanf", "fscanf", "sscanf",
        "fgets", "fputs",
        "fopen", "fclose", "fread", "fwrite",
    ],
    "<stdlib.h>": [
        "malloc", "calloc", "realloc", "free",
        "exit", "abort",
        "atoi", "atof", "strtol", "strtoul",
        "qsort", "rand", "srand",
        "abs", "labs",
    ],
    "<string.h>": [
        "strcpy", "strncpy", "strcat", "strncat",
        "strcmp", "strncmp", "strlen", "strstr",
        "memcpy", "memmove", "memcmp", "memset",
        "strerror", "strtok", "strpbrk", "strrchr",
    ],
    "<math.h>": [
        "sin", "cos", "tan",
        "sqrt", "pow", "log",
        "exp", "log10", "ceil", "floor",
    ],
    "<unistd.h>": [
        "read", "write", "close",
        "sleep", "usleep",
        "fork", "execve",
        "pipe", "dup", "dup2",
        "getpid",
    ],
    "<pthread.h>": [
        "pthread_create", "pthread_join",
        "pthread_mutex_lock", "pthread_mutex_unlock",
        "pthread_cond_wait", "pthread_cond_signal",
        "pthread_rwlock_init", "pthread_rwlock_destroy",
        "pthread_rwlock_rdlock", "pthread_rwlock_wrlock",
    ],
    "<netinet/in.h>": [
        "socket", "bind", "listen", "accept",
        "inet_addr", "htons", "htonl", "ntohs", "ntohl",
    ],
    "<sys/types.h>": [
        "open", "close", "read", "write",
        "lseek", "stat", "fstat",
        "unlink", "rename",
    ],
    "<time.h>": [
        "clock", "time", "ctime",
        "difftime", "strftime", "localtime",
        "mktime", "gmtime", "asctime",
    ],
    "<fcntl.h>": [
        "open", "close", "read", "write",
        "fcntl", "ioctl", "pipe2", "dup2", "select",
    ],
}

def _strip_symbol_version(sym: str) -> str:
    """
    Removes ABI Version decorations from a symbol name as printf@@GLIBC_2.2.5 becomes printf
    """
    if '@@' in sym:
        return sym.split('@@')[0]
    elif '@' in sym:
        return sym.split('@')[0]
    return sym

def _readelf_symbols(binary_path: str) -> list[str]:
    """
    
    """
    if shutil.which("readelf") is None:
        return []  # readelf not available.

    try:
        out = subprocess.check_output(
            ["readelf", "-s", binary_path],
            text=True,
            errors="ignore"
        )
    except Exception:
        return []
    
    # Undefined symbols appear as: GLOBAL  DEFAULT  UND <name>.
    symbols = []
    for line in out.splitlines():
        if "UND" not in line and "UND " not in line and "UNDEF" not in line:
            continue

        parts = line.strip().split()
        if not parts:
            continue

        cand = parts[-1]  # Usually the last token is the symbol name.

        # Filter out common decorations.
        if cand in ("UND", "UNDEF"):
            continue

        symbols.append(cand)

    return symbols

def extract_external_symbols(binary_path: str) -> set[str]:
    """
    Delivers a set of external, undefined symbol names without GLIBC version,
    e.g. { "printf", "socket", "htons" }.
    """
    raw_syms = _readelf_symbols(binary_path)
    clean = set()

    for sym in raw_syms:
        base = _strip_symbol_version(sym)

        # Skip internal or compiler-generated symbols.
        if base.startswith("__"):
            continue

        clean.add(base)

    return clean

def map_symbols_to_headers(symbols: set[str]) -> list[str]:
    """
    Uses HEADER_MAP to determine which #includes are necessary.
    Returns a sorted, unique list.
    """
    needed_headers = []
    for header, sym_list in HEADER_MAP.items():
        for s in symbols:
            if s in sym_list:
                needed_headers.append(header)
                break  # Adding the header once is sufficient.

    # Deduplicate while preserving order (dict.fromkeys keeps insertion order on Python 3.7+).
    needed_headers = list(dict.fromkeys(needed_headers))
    return needed_headers

def build_header_block_from_angr_subset(project, func_objs):  # TODO: implement angr-based header discovery
    # Placeholder: collect external symbols via angr and map them to headers.
    ...
    pass

_HEADER_CACHE: dict[str, str] = {}

def build_header_block_from_binary(binary_path: str) -> str:
    """
    Main-Entry:
    - collects external symbols via readelf
    - maps them to headers
    - builds a string block like:
        HEADERS:
        #include <stdio.h>
        #include <sys/socket.h>
        ...
    If no headers are found, returns an empty string.
    """
    abs_path = os.path.abspath(binary_path)
    cached = _HEADER_CACHE.get(abs_path)
    if cached is not None:
        return cached
    
    symbols = extract_external_symbols(abs_path)
    headers = map_symbols_to_headers(symbols)

    if not headers:
        block = ""
    else:
        lines = ["HEADERS:"]
        for h in headers:
            lines.append(f"#include {h}")
        block = "\n".join(lines) + "\n"
    
    _HEADER_CACHE[abs_path] = block
    return block


def _count_non_junk_callees(func_obj, callgraph, all_program_funcs, junk_set=JUNK_FUNCTIONS):
    """
    Return the number of outgoing call edges whose destination is not in junk_set.
    """
    if not func_obj:
        return 0

    try:
        successor_addrs = callgraph.successors(func_obj.addr)
        non_junk_count = 0
        for addr in successor_addrs:
            callee_func = all_program_funcs.get(addr)
            if callee_func and callee_func.name not in junk_set:
                non_junk_count += 1
        return non_junk_count
        
    except Exception:
        return 0

def _candidate_func_calls_target(candidate_addr, cg, target_addr):
    """
    Check if the candidate function has a direct call to the target function.
    Returns True if it does, False otherwise.
    """
    try:
        return target_addr in cg.successors(candidate_addr)
    except Exception:
        return False

def _target_calls_candidate(target_addr, cg, candidate_addr):
    """
    Check if the target function directly calls the candidate function.
    """
    try:
        return candidate_addr in cg.successors(target_addr)
    except Exception:
        return False

def _get_block_and_insn_counts(func_obj):
    """
    Return (block_count, insn_count) for a function object.
    """
    if func_obj is None:
        return None, None

    try:
        blocks = list(func_obj.blocks)
    except Exception:
        return None, None

    insn_count = 0
    for b in blocks:
        try:
            cap = b.capstone
        except Exception:
            continue
        insn_count += len(getattr(cap, "insns", []))

    return len(blocks), insn_count

def _is_stub_like(func_obj):
    """
    Detect lightweight or stubby routines that should not receive caller/callee bonuses.
    """
    if func_obj is None:
        return False

    name = getattr(func_obj, "name", "") or ""
    if name in JUNK_FUNCTIONS or name.startswith("__"):
        return True

    if getattr(func_obj, "is_plt", False):
        return True

    return _is_trampoline_or_tiny(func_obj)

def _cfg_fingerprint(func_obj):
    """
    Build a coarse CFG fingerprint.
    """
    if func_obj is None:
        return None

    try:
        g = func_obj.graph
    except Exception:
        return None

    try:
        nodes = g.number_of_nodes()
        edges = g.number_of_edges()
        branchy = sum(1 for n, deg in g.out_degree() if deg > 1)
    except Exception:
        return None

    cyclomatic = max(edges - nodes + 1, 0)
    branch_ratio = branchy / max(nodes, 1)

    return {
        "nodes": nodes,
        "edges": edges,
        "cyclomatic": cyclomatic,
        "branch_ratio": branch_ratio,
    }

def _cfg_similarity_bonus(target_obj, candidate_obj, strong_threshold=0.7):
    """
    Grant a moderate bonus when CFG fingerprints are clearly similar.
    """
    tgt_fp = _cfg_fingerprint(target_obj)
    cand_fp = _cfg_fingerprint(candidate_obj)
    if not tgt_fp or not cand_fp:
        return 0

    diffs = []
    for key in ("nodes", "edges", "cyclomatic"):
        a = tgt_fp.get(key)
        b = cand_fp.get(key)
        if a is None or b is None:
            continue
        diffs.append(abs(a - b) / max(a, b, 1))

    for key in ("branch_ratio",):
        a = tgt_fp.get(key)
        b = cand_fp.get(key)
        if a is None or b is None:
            continue
        diffs.append(abs(a - b))

    if not diffs:
        return 0

    avg_diff = sum(diffs) / len(diffs)
    similarity = max(0.0, 1.0 - avg_diff)

    if similarity >= strong_threshold:
        return 10

    return 0

STOP_TOKENS = {
    "init", "start", "stop", "helper", "func", "function", "handle", "process",
    "do", "run", "main", "task", "worker", "thread", "loop", "call", "impl",
    "util", "common", "generic", "default", "base",
}

def _split_identifiers(name: str):
    """
    Split function names into meaningful tokens.
    """
    if not name:
        return []
    name = name.replace(".", "_")
    parts = re.split(r"[_\W]+", name)
    tokens = []
    for p in parts:
        subtokens = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+", p)
        if subtokens:
            tokens.extend(subtokens)
        else:
            tokens.append(p)
    tokens = [t.lower() for t in tokens if t]
    return tokens

def _semantic_name_bonus(target_obj, candidate_obj, min_len=4, bonus=15):
    """
    Bonus for meaningful shared name fragments outside a stoplist.
    """
    t_name = getattr(target_obj, "name", "") or ""
    c_name = getattr(candidate_obj, "name", "") or ""

    t_tokens = {tok for tok in _split_identifiers(t_name) if len(tok) >= min_len and tok not in STOP_TOKENS}
    c_tokens = {tok for tok in _split_identifiers(c_name) if len(tok) >= min_len and tok not in STOP_TOKENS}

    if not t_tokens or not c_tokens:
        return 0

    common = t_tokens & c_tokens
    if not common:
        return 0

    return bonus

def _struct_overlap_bonus(target_struct_fp, candidate_struct_fp):
    """
    Score shared data/struct offsets between target and candidate.
    """
    if not target_struct_fp or not candidate_struct_fp:
        return 0

    overlap = target_struct_fp & candidate_struct_fp
    if not overlap:
        return 0

    # Separate specific vs. common offsets to downweight ubiquitous fields/globals.
    COMMON_STRUCT_OFFSETS = {0x0, 0x4, 0x8, 0x10, 0x14, 0x18, 0x1C, 0x20}
    specific = {o for o in overlap if o not in COMMON_STRUCT_OFFSETS}
    common = overlap - specific

    bonus = 0
    if specific:
        bonus += 25 + max(len(specific) - 1, 0) * 5
    if common:
        bonus += min(5, len(common))  # Barely reward trivially shared offsets.

    # Approximate dependency strength: high coverage of shared fields boosts a bit.
    union_size = len(target_struct_fp | candidate_struct_fp)
    coverage = len(overlap) / max(union_size, 1)
    if len(overlap) >= 2 and coverage >= 0.5:
        bonus += 5

    return bonus

LEXICAL_STOP_TOKENS = {
    "mov", "add", "sub", "mul", "div", "xor", "and", "or", "cmp", "test",
    "jmp", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe",
    "push", "pop", "call", "lea", "nop", "ret",
    "byte", "word", "dword", "qword", "ptr",
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
    "loc", "var", "tmp",
}

_REGEX_REG = re.compile(
    r"\b(?:r[0-9]+|r1[0-5]|r[8-9]|rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|"
    r"eax|ebx|ecx|edx|esi|edi|esp|ebp|al|ah|bl|bh|cl|ch|dl|dh)\b",
    re.IGNORECASE,
)

def _normalize_assembly_for_lexical(assembly: str) -> str:
    """
    Strip register names and lower-case to dampen compiler/register variance.
    """
    if not assembly:
        return ""
    text = assembly.lower()
    text = _REGEX_REG.sub("<reg>", text)
    return text

def _extract_lexical_fingerprint(assembly: str):
    """
    Extract rare-ish lexical tokens from assembly (constants, strings, notable symbols).
    """
    if not assembly:
        return set()

    assembly = _normalize_assembly_for_lexical(assembly)
    fp = set()

    for m in re.finditer(r"0x[0-9a-fA-F]+", assembly):
        lit = m.group(0).lower()
        if len(lit) >= 6:  # 0x + at least 4 hex chars
            fp.add(lit)

    for m in re.finditer(r'"([^"]+)"', assembly):
        lit = m.group(1).strip().lower()
        if len(lit) >= 4:
            fp.add(lit)

    for m in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b", assembly):
        tok = m.group(0).lower()
        if len(tok) >= 4 and tok not in LEXICAL_STOP_TOKENS:
            fp.add(tok)

    return fp

def _lexical_overlap_bonus(target_lex_fp, candidate):
    """
    Small tie-breaker bonus for rare lexical overlaps (constants/strings/symbols).
    """
    if not target_lex_fp:
        return 0

    cand_fp = candidate.get("lex_fp")
    if cand_fp is None:
        cand_fp = _extract_lexical_fingerprint(candidate.get("assembly", "") or "")
        candidate["lex_fp"] = cand_fp

    overlap = target_lex_fp & cand_fp
    if not overlap:
        return 0

    return min(5, 2 + len(overlap))

def _extract_api_signature(assembly: str) -> set[str]:
    """
    Extract called API names as a coarse semantic signature.
    """
    if not assembly:
        return set()

    apis = set()
    for m in re.finditer(r"\bcall(?:q)?\s+([A-Za-z_][A-Za-z0-9_@.\-]*)", assembly):
        name = m.group(1)
        name = name.replace("plt.", "")
        name = _strip_symbol_version(name)
        name = name.split("@")[0]
        if not name or name.startswith("__"):
            continue
        apis.add(name.lower())
    return apis

def _api_signature_bonus(target_api_sig, candidate, base_bonus=12, max_bonus=15):
    """
    Bonus for overlapping API-call signatures (fallback when names are weak/absent).
    """
    if not target_api_sig:
        return 0

    cand_sig = candidate.get("api_sig")
    if cand_sig is None:
        cand_sig = _extract_api_signature(candidate.get("assembly", "") or "")
        candidate["api_sig"] = cand_sig

    if not cand_sig:
        return 0

    overlap = target_api_sig & cand_sig
    if not overlap:
        return 0

    return min(max_bonus, base_bonus + max(len(overlap) - 1, 0))

def _callgraph_distance_bonus(degree, has_data_overlap):
    """
    Lightly reward 2-hop neighbors only when backed by data overlap.
    """
    if degree == 2 and has_data_overlap:
        return 5
    return 0

def _is_small_leaf_wrapper(candidate_obj, cg, target_addr, max_blocks=30, max_insns=50):
    """
    Leaf-ish wrapper: no outgoing calls besides possibly the target, and structurally small.
    """
    if candidate_obj is None:
        return False

    try:
        succ_addrs = set(cg.successors(candidate_obj.addr))
    except Exception:
        succ_addrs = set()

    non_target_calls = {addr for addr in succ_addrs if addr != target_addr}
    if non_target_calls:
        return False

    block_count, insn_count = _get_block_and_insn_counts(candidate_obj)
    if block_count is None or insn_count is None:
        return False

    return block_count <= max_blocks and insn_count <= max_insns

def _calculate_candidate_score(candidate, callgraph, all_program_funcs, target_addr, target_struct_fp=None, target_src_loc=None, target_lex_fp=None, target_api_sig=None):
    """
    Score a context candidate (higher = better).
    """
    candidate["score"] = candidate.get("score", BASIC_SCORE)

    candidate_obj = candidate.get("function_obj")
    candidate_addr = getattr(candidate_obj, "addr", None)
    target_obj = all_program_funcs.get(target_addr)

    if candidate_addr is None:
        return candidate["score"]

    direct_link = (
        _candidate_func_calls_target(candidate_addr, callgraph, target_addr)
        or _target_calls_candidate(target_addr, callgraph, candidate_addr)
    )

    if direct_link and not _is_stub_like(candidate_obj) and not _is_stub_like(target_obj):
        candidate["score"] += 30

        if _candidate_func_calls_target(candidate_addr, callgraph, target_addr):
            if _is_small_leaf_wrapper(candidate_obj, callgraph, target_addr):
                candidate["score"] += 20

    overlap_bonus = _struct_overlap_bonus(target_struct_fp, candidate.get("struct_fp"))
    if overlap_bonus:
        candidate["score"] += overlap_bonus

    cfg_bonus = _cfg_similarity_bonus(target_obj, candidate_obj)
    if cfg_bonus:
        candidate["score"] += cfg_bonus
    
    semantic_bonus = _semantic_name_bonus(target_obj, candidate_obj)
    if semantic_bonus:
        candidate["score"] += semantic_bonus

    if not semantic_bonus:
        sig_bonus = _api_signature_bonus(target_api_sig, candidate)
        if sig_bonus:
            candidate["score"] += sig_bonus

    lex_bonus = _lexical_overlap_bonus(target_lex_fp, candidate)
    if lex_bonus:
        candidate["score"] += lex_bonus

    degree = candidate.get("degree", None)
    cg_bonus = _callgraph_distance_bonus(degree, overlap_bonus > 0)
    if cg_bonus:
        candidate["score"] += cg_bonus

    if candidate.get("is_leaf") and not direct_link and overlap_bonus == 0:
        candidate["score"] -= 5

    return candidate["score"]

def add_candidate_as_c_code_to_context(remaining_candidates, context_funcs, candidate, current_budget, mode):
    added = False

    def _only_add_real_c_code():
        candidate['append_mode'] = 'c_code'
        context_funcs.append(candidate)
        try:
            remaining_candidates.remove(candidate)
        except ValueError:
            pass
        current_budget -= candidate['c_token_count']
        added = True
    
    def _decompile_and_add():
        temp_result_decomp = decompile_context_function_to_c(candidate['function_obj'], candidate.get('project'), candidate.get('model'))
        if temp_result_decomp is None:
            if mode == "test":
                return current_budget,remaining_candidates, added
            elif mode == "train":
                _only_add_real_c_code()
        else:
            candidate['c_code'] = temp_result_decomp
                
        candidate['c_token_count'] = get_token_count(candidate['c_code'])
        if candidate['c_token_count'] <= current_budget:
            _only_add_real_c_code()

    if mode == "test":
        _decompile_and_add()
        
    elif mode == "train":
        if random.random() < 0.6:
            _decompile_and_add()
        else:
            _only_add_real_c_code()

    return current_budget, remaining_candidates, added

def add_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget):
    token_count = candidate.get('token_count', 0)
    if token_count <= current_budget:
        candidate['append_mode'] = 'assembly'
        context_funcs.append(candidate)
        try:
            remaining_candidates.remove(candidate)
        except ValueError:
            pass
        current_budget -= token_count
    return current_budget

def token_degree_level_check(remaining_candidates):
    """
    computes the total token count of the current lowest degree level among remaining candidates
    returns (degree_level: int, total_token_count: int)
    """
    if not remaining_candidates:
        return None, 0

    min_degree = min((c.get('degree', float('inf')) for c in remaining_candidates))

    total_tokens_current_degree = sum(
        c.get('token_count', 0) for c in remaining_candidates if c.get('degree') == min_degree
    )

    return min_degree, total_tokens_current_degree
def add_remaining_candidates_as_c_code_to_context(remaining_candidates, context_funcs, current_budget, mode):
    prioritized_sorted = remaining_candidates

    for candidate in prioritized_sorted:
        if current_budget <= 0:
            break
        candidate['c_code'] = get_real_c_code(candidate) # TODO overwrite, im not sure if its really the real c code
        candidate['c_token_count'] = get_token_count(candidate['c_code'])
        if candidate['c_token_count'] <= current_budget:
            try:
                remaining_candidates.remove(candidate)
            except ValueError:
                pass # TODO maybe break here?
                current_budget, remaining_candidates, added = add_candidate_as_c_code_to_context(remaining_candidates, context_funcs, candidate, current_budget, mode)
            if not added:
                remaining_candidates.append(candidate)
                # maybe unnessary
    return current_budget, remaining_candidates

def add_remaining_candidates_to_context(remaining_candidates, context_funcs, current_budget, REDUCTION_LEVEL):
    """
    Fills budget with candidates from the given degree group, prioritized by score.
    Returns (new_budget: int, stop_processing: bool)
    stop_processing indicates that no further candidates can fit into the budget.
    """
    # Not enough budget for the whole degree: prioritize within this degree.
    # TODO: Revisit whether we should scan per degree or across all candidates.
    prioritized_sorted = remaining_candidates
        
    for candidate in prioritized_sorted:
        if current_budget <= 0:
            break

        if candidate['token_count'] <= current_budget:
            try:
                remaining_candidates.remove(candidate)
            except ValueError:
                pass # TODO maybe break here?
            if REDUCTION_LEVEL == 1:
                # random value between 0 and 1
                if random.random() < 0.6:
                    current_budget, remaining_candidates = add_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget)
                else:
                    current_budget = add_candidate_as_c_code_to_context(remaining_candidates, context_funcs, candidate, current_budget)
            elif REDUCTION_LEVEL == 0:
                current_budget = add_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget)

    return current_budget, remaining_candidates

def estimate_c_token_complexity(func):
    """
    Estimates the expected C code token count based on CFG complexity.
    Returns a numeric score (higher = more complex/more tokens).
    """
    if not func:
        return float('inf')  # Treat missing function as maximally complex.

    function_cfg = func.graph
    
    if not function_cfg:
        return 1  # No graph: assume trivially small.

    # Estimation heuristic:
    # Base the complexity on CFG nodes/edges; edges often capture branching constructs.

    num_nodes = function_cfg.number_of_nodes()
    num_edges = function_cfg.number_of_edges()

    # Cyclomatic complexity: E - N + 2P (simplified here).
    complexity_score = (num_edges * 1.5) + (num_nodes * 1.0)

    # Scale factor (approximate): assume 1 complexity point ≈ 5 C tokens.
    estimated_tokens = complexity_score * 5.0
    
    return estimated_tokens
    
def _decode_dwarf_str(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "ignore")
    return value


def _extract_function_from_source(src_text, func_name):
    if not src_text or not func_name:
        return None

    if not re.search(rf'\b{re.escape(func_name)}\s*\(', src_text):
        return None

    sig_regex = re.compile(
        rf'([A-Za-z0-9_\*\s]+?\b{re.escape(func_name)}\s*\([^;]*\)\s*\{{)',
        re.MULTILINE,
    )
    match = sig_regex.search(src_text)
    if not match:
        return None

    start_idx = match.start()
    brace_depth = 0
    i = start_idx
    n = len(src_text)
    in_string = False
    string_char = None

    while i < n:
        ch = src_text[i]

        if in_string:
            if ch == string_char:
                in_string = False
            elif ch == "\\":
                i += 1
        else:
            if ch in ('"', "'"):
                in_string = True
                string_char = ch
            elif ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    end_idx = i + 1
                    snippet = src_text[start_idx:end_idx]
                    return snippet.lstrip()
        i += 1

    return None


def _load_file_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return None


def _scan_dir_for_func_once(dir_path, func_name, exact_filename=None):
    if not dir_path or not os.path.isdir(dir_path):
        return None

    if exact_filename:
        full = os.path.join(dir_path, exact_filename)
        if os.path.isfile(full):
            text = _load_file_text(full)
            snippet = _extract_function_from_source(text, func_name)
            if snippet: return snippet

    # #Fallback 
    # for fname in os.listdir(dir_path):
    #     if not fname.endswith(".c"):
    #         continue
    #     full_path = os.path.join(dir_path, fname)
    #     text = _load_file_text(full_path)
    #     if not text:
    #         continue
    #     snippet = _extract_function_from_source(text, func_name)
    #     if snippet:
    #         return snippet
    return None


def _resolve_source_path_from_die(candidate, binary_path=None):
    die = candidate.get("die") if candidate else None
    cu = candidate.get("cu") if candidate else None
    dwarf_info = candidate.get("dwarf_info") if candidate else None
    if not die or not cu or not dwarf_info:
        return None

    try:
        line_program = dwarf_info.line_program_for_CU(cu)
    except Exception:
        line_program = None

    if not line_program:
        return None

    file_attr = die.attributes.get("DW_AT_decl_file")
    if not file_attr:
        return None

    file_index = file_attr.value
    try:
        file_entry = line_program["file_entry"][file_index - 1]
    except Exception:
        return None

    file_name = _decode_dwarf_str(getattr(file_entry, "name", None))
    if not file_name:
        return None

    dir_candidates = []

    dir_index = getattr(file_entry, "dir_index", 0)
    try:
        include_dirs = line_program["include_directory"]
    except Exception:
        include_dirs = []
    if dir_index and dir_index - 1 < len(include_dirs):
        dir_entry = _decode_dwarf_str(include_dirs[dir_index - 1])
        if dir_entry:
            dir_candidates.append(dir_entry)

    comp_dir_attr = cu.get_top_DIE().attributes.get("DW_AT_comp_dir")
    comp_dir = _decode_dwarf_str(comp_dir_attr.value) if comp_dir_attr else None
    if comp_dir:
        dir_candidates.append(comp_dir)

    repo_path = None
    o_path = candidate.get("o_path")
    if o_path:
        repo_path = os.path.dirname(o_path)
        if repo_path:
            repo_path = repo_path.replace("/COMPILED/", "/C_COMPILE/", 1)
            dir_candidates.append(repo_path)

    if binary_path and "/COMPILED/" in binary_path:
        repo_dir = os.path.dirname(binary_path).replace("/COMPILED/", "/C_COMPILE/", 1)
        dir_candidates.append(repo_dir)

    potential_paths = []
    if os.path.isabs(file_name):
        potential_paths.append(os.path.normpath(file_name))
    else:
        for base in dir_candidates:
            if not base:
                continue
            joined = os.path.normpath(os.path.join(base, file_name))
            potential_paths.append(joined)
        potential_paths.append(os.path.normpath(file_name))

    normalized_paths = []
    for path in potential_paths:
        if not path:
            continue
        normalized_paths.append(path)
        if "/COMPILED/" in path:
            normalized_paths.append(path.replace("/COMPILED/", "/C_COMPILE/", 1))

    for candidate_path in normalized_paths:
        if candidate_path and os.path.isfile(candidate_path):
            return candidate_path

    return None


def _extract_source_text_from_die(candidate, binary_path=None):
    if not candidate:
        return None

    func_name_attr = candidate.get("die").attributes.get("DW_AT_name") if candidate.get("die") else None
    func_name = _decode_dwarf_str(func_name_attr.value) if func_name_attr else None
    if not func_name:
        return None

    source_path = _resolve_source_path_from_die(candidate, binary_path=binary_path)
    if not source_path:
        return None

    try:
        with open(source_path, "r", encoding="utf-8", errors="ignore") as handle:
            source_text = handle.read()
    except OSError:
        return None

    return _extract_function_from_source(source_text, func_name)

def _die_addr_range(candidate):
    die = candidate.get("die") if candidate else None
    if not die:
        return None

    low = die.attributes.get("DW_AT_low_pc")
    high = die.attributes.get("DW_AT_high_pc")

    if not low:
        return None

    low_pc = low.value

    if not high:
        return (low_pc, low_pc)

    # DW_AT_high_pc can be absolute addr OR an offset from low_pc (DWARF spec)
    hv = high.value
    if isinstance(hv, int) and hv < 0x100000:  # heuristic: small => offset
        high_pc = low_pc + hv
    else:
        high_pc = hv

    return (low_pc, high_pc)

def get_real_c_code(
    func_obj,
    project,
    *,
    purpose="target",
    source_hint=None,
    dwarf_lookup=None,
    max_recursive_depth=2,
):
    """
    Resolve the most reliable C-source snippet for func_obj.

    purpose="target": strict, rely on explicit hints/derived dirs/DWARF.
    purpose="context": allow guarded recursive search nearby.
    """
    func_name = getattr(func_obj, "name", None)
    if not func_name or func_name.startswith("__"):
        return None

    def _try_file(path):
        text = _load_file_text(path)
        if not text:
            return None
        return _extract_function_from_source(text, func_name)

    if source_hint:
        snippet = _try_file(source_hint)
        if snippet:
            return snippet

    binary_path = getattr(project, "filename", None)
    if binary_path is None:
        try:
            binary_path = project.loader.main_object.binary
        except Exception:
            binary_path = None

    c_base_dir = None
    if binary_path and "/COMPILED/" in binary_path:
        c_base_dir = binary_path.replace("/COMPILED/", "/C_COMPILE/", 1)
        c_base_dir = os.path.dirname(c_base_dir)

    if c_base_dir:
        snippet = _scan_dir_for_func_once(c_base_dir, func_name, exact_filename=f"{func_name}.c")
        if snippet:
            return snippet

    if dwarf_lookup:
        func_map = dwarf_lookup.get("functions", dwarf_lookup)
        candidates = func_map.get(func_name) if func_map else None
        if candidates:
            best_candidate = None
            for cand in candidates:
                r = _die_addr_range(cand)
                if not r:
                    continue
                lo, hi = r
                if lo <= func_obj.addr < hi:
                    best_candidate = cand
                    break

            # fallback to old heuristic
            if best_candidate is None:
                best_candidate = pick_best_match(candidates, binary_path or "")

            snippet = _extract_source_text_from_die(best_candidate, binary_path=binary_path)
            if snippet:
                return snippet

    if purpose == "context" and c_base_dir:
        for root, dirs, files in os.walk(c_base_dir):
            rel = os.path.relpath(root, c_base_dir)
            depth = 0 if rel in (".", "") else rel.count(os.sep) + 1
            if depth > max_recursive_depth:
                dirs[:] = []
                continue

            for fname in files:
                if not fname.endswith(".c"):
                    continue
                full_path = os.path.join(root, fname)
                snippet = _try_file(full_path)
                if snippet:
                    return snippet

    return None

def decompile_context_function_to_c(func_obj, candidate, project, model): 
    """
    Decompiles the given function object to C code using the project's decompiler.
    """
    # TODO : so # c_approx = decompile_asm_string(candidate)
    try:
        result = subprocess.run(["python3", "inference.py"], capture_output=True, text=True, check=True)
        output = result.stdout
        if "===== OUTPUT =====" in output:
                return output.split("===== OUTPUT =====", 1)[1].strip()
        else:
            return None
    except subprocess.CalledProcessError as e:
        return f"Error running inference.py: {e.stderr}"
        

def add_decompiled_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget): 
    """
    Adds a decompiled candidate to the context functions, updating the budget.
    """
    token_count = get_token_count(candidate['c_approx'])
    candidate['c_token_count'] = token_count
    if token_count <= current_budget:
        candidate['append_mode'] = 'c_approx'
        context_funcs.append(candidate)
        try:
            remaining_candidates.remove(candidate)
        except ValueError:
            pass
        current_budget -= token_count
    return current_budget

def apply_heuristic(
    target_func_data,
    context_candidates_data,
    budget,
    callgraph,
    all_functions_map,
    target_addr,
    project,
    mode,
    dwarf_lookup=None,
    target_src_loc=None,
    assembly_only=True, # Default auf True, da wir nur ASM wollen
):
    """
    Wählt Kontext-Funktionen (nur Assembly) basierend auf Score und Budget.
    """
    context_candidates_data = context_candidates_data or {}
    all_candidate_entries = context_candidates_data.get('all_functions', []) or []
    
    # 1. Budget berechnen (WICHTIG: budget ist schon bereinigt übergeben!)
    current_budget = budget 
    
    if current_budget <= 0:
        return []

    # Fingerprints für Scoring
    target_struct_fp = extract_struct_fingerprint(target_func_data.get("assembly",""))
    target_lex_fp = _extract_lexical_fingerprint(target_func_data.get("assembly", ""))
    target_api_sig = _extract_api_signature(target_func_data.get("assembly", ""))
    
    # 2. Kandidaten scoren
    scored_candidates = []
    for candidate in all_candidate_entries:
        candidate['score'] = _calculate_candidate_score(
            candidate,
            callgraph,
            all_functions_map,
            target_addr,
            target_struct_fp=target_struct_fp,
            target_src_loc=target_src_loc,
            target_lex_fp=target_lex_fp,
            target_api_sig=target_api_sig,
        )
        scored_candidates.append(candidate)

    # 3. Sortieren: Höchster Score zuerst, bei Gleichstand kleinster Token-Count
    scored_candidates = sorted(
        scored_candidates,
        key=lambda x: (-x.get('score', 0), x.get('token_count', float('inf')))
    )

    # 4. Auffüllen (Nur Assembly)
    context_funcs = []
    remaining_candidates = scored_candidates

    # Hier nutzen wir einfach deine existierende add_candidate_to_context Logik
    # Wir iterieren durch die sortierte Liste und nehmen, was passt.
    to_remove = []
    for candidate in remaining_candidates:
        if current_budget <= 0:
            break

        toks = candidate.get('token_count', 0)
        if toks <= current_budget:
            candidate['append_mode'] = 'assembly'
            context_funcs.append(candidate)
            current_budget -= toks
            to_remove.append(candidate)
    
    return context_funcs