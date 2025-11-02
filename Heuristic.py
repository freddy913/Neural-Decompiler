import os
import random
import re
import shutil
import subprocess

from ElfFeatures import get_function_data, get_token_count
from Config import BASIC_SCORE, DEGREE, JUNK_FUNCTIONS, MYTOKENIZER, RUNTIME_ENTRY_FUNCTIONS

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
        for pred_addr in callgraph.successors(target_func.addr):
            caller_func = cfg.functions.get_by_addr(pred_addr)
            if caller_func:
                callers.add(caller_func)
    except Exception as e:
        pass

    try:
        for succ_addr in callgraph.predecessors(target_func.addr):
            callee_func = cfg.functions.get_by_addr(succ_addr)
            if callee_func:
                callees.add(callee_func)
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
    symbols = extract_external_symbols(binary_path)
    headers = map_symbols_to_headers(symbols)

    if not headers:
        return ""

    lines = ["HEADERS:"]
    for h in headers:
        lines.append(f"#include {h}")

    return "\n".join(lines) + "\n"


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

def _calculate_candidate_score(candidate, callgraph, all_program_funcs, target_addr):
    """
    Score a context candidate (higher = better).
    """
    # 1) Semantic similarity (future RAG hook).
    # similarity = calculate_embedding_similarity(candidate['name'], target_func.name, vector_db)
    # score += similarity * 30

    # 2) Bonus for directly calling the target.
    if _candidate_func_calls_target(candidate['function_obj'].addr, callgraph, target_addr):
        candidate['score'] += 30

    # 3) Penalize complex functions (non-junk callees).
    num_callees = _count_non_junk_callees(candidate['function_obj'], callgraph, all_program_funcs, JUNK_FUNCTIONS)
    candidate['score'] -= num_callees * 5

    # 4) Penalize distance in the call graph.  # TODO: confirm if degree-based iteration makes this redundant.
    candidate['score'] -= (candidate.get('degree', 0) - 1) * 10
    
    # 5) Penalize very large functions.
    c_token_count = candidate.get('token_count', 0)
    candidate['score'] -= c_token_count / 100

    return candidate['score']

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

def add_remaining_candidates_to_context(degree_group, remaining_candidates, context_funcs, current_budget, callgraph, all_program_funcs):
    """
    Fills budget with candidates from the given degree group, prioritized by score.
    Returns (new_budget: int, stop_processing: bool)
    stop_processing indicates that no further candidates can fit into the budget.
    """
    # Not enough budget for the whole degree: prioritize within this degree.
    # TODO: Revisit whether we should scan per degree or across all candidates.
    prioritized = remaining_candidates
    added_any = False
        
    # Sort the prioritized list based on score (higher is better).
    prioritized_sorted = sorted(
        prioritized,
        key=lambda x: (-x.get('score', 0), x.get('token_count', float('inf')))
    )
    for candidate in prioritized_sorted:
        if current_budget <= 0:
            break
        if candidate in context_funcs:
            try:
                remaining_candidates.remove(candidate)
            except ValueError:
                pass
            continue
        if candidate['token_count'] <= current_budget:
            current_budget = add_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget)
            added_any = True
        else:
            remaining_candidates.remove(candidate)
            continue

    if not added_any:
        any_fittable = any(c.get('token_count', 0) <= current_budget for c in remaining_candidates)
        if not any_fittable:
            # Signal the caller that no further progress is possible.
            return current_budget, True

    return current_budget, False

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

def real_c_code_lookup(func_obj, project):
    """
    Retrieves the real C code for training purposes.
    """
    func_name = getattr(func_obj, "name", None)
    if not func_name:
        return None
    
    if func_name.startswith("__"):
        return None

    binary_path = getattr(project, "filename", None)
    if binary_path is None:
        try:
            binary_path = project.loader.main_object.binary
        except Exception:
            return None
        
    c_path_dir = binary_path.replace("/COMPILED/", "/C_COMPILE/", 1)
    c_path_dir = os.path.dirname(c_path_dir) + "/"

    if not os.path.isdir(c_path_dir):
        return None
    
    candidate_source_text = None

    for fname in os.listdir(c_path_dir):
        if not fname.endswith(".c"):
            continue
        full_path = os.path.join(c_path_dir, fname)
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                src = f.read()
        except Exception:
            continue

        if not re.search(rf'\b{re.escape(func_name)}\s*\(', src):
            continue

        sig_regex = re.compile(
            rf'([A-Za-z0-9_\*\s]+?\b{re.escape(func_name)}\s*\([^;]*\)\s*\{{)',
            re.MULTILINE
        )


        m = sig_regex.search(src)
        if not m:
            continue

        start_idx = m.start()
        brace_depth = 0
        i = start_idx
        n = len(src)
        in_string = False
        string_char = None
        while i < n:
            ch = src[i]

            if in_string:
                if ch == string_char:
                    in_string = False
                elif ch == '\\':
                    i += 1
            else:
                if ch == '"' or ch == "'":
                    in_string = True
                    string_char = ch
                elif ch == '{':
                    brace_depth += 1
                elif ch == '}':
                    brace_depth -= 1
                    if brace_depth == 0:
                        end_idx = i + 1
                        candidate_source_text = src[start_idx:end_idx]
                        break

            i += 1

        if candidate_source_text is not None:
            candidate_source_text = candidate_source_text.lstrip()
            return candidate_source_text

    return None

def decompile_context_function_to_c(func_obj, project, model): 
    """
    Decompiles the given function object to C code using the project's decompiler.
    """
    
    pass

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

def apply_heuristic(target_func_data, context_candidates_data, budget, callgraph, all_functions_map, target_addr, project, mode):
    """
    Choses context functions based on the heuristic strategy within a token budget.
    """
    current_budget = budget - target_func_data['token_count']
    if current_budget <= 0:  # TODO: handle cases where the target alone exceeds the budget.
        return []
    
    try:
        total_context_tokens = context_candidates_data.get('total_token_count', 0)
        if current_budget > total_context_tokens:
            return context_candidates_data['all_functions', []].copy()
    except Exception as e:
        pass

    if current_budget <= 0.25 * budget:
        REDUCTION_LEVEL = 2
    elif current_budget <= 0.6 * budget:
        REDUCTION_LEVEL = 1
    else:
        REDUCTION_LEVEL = 0

    if REDUCTION_LEVEL == 2:
        # TODO: Define a strategy when tokens exceed ~80-90% of the budget (e.g., split targets).
        pass
    elif REDUCTION_LEVEL == 1:
        # Target is large: attempt a hybrid context strategy.
        print("INFO: Target function is large. Applying 'Hybrid Context' strategy.")

        # Step 1: score candidates with the existing scoring system.
        context_funcs = []
        remaining_candidates = context_candidates_data['all_functions'].copy()
        
        for candidate in remaining_candidates:
            candidate['score'] = _calculate_candidate_score(candidate, callgraph, all_functions_map, target_addr)

        # Step 2: estimate C token size for the top candidates and decide between assembly vs C.
        important_candidates = sorted(
            remaining_candidates,
            key=lambda x: -x.get('score', 0)
        )[:5]

        for candidate in important_candidates:
            if current_budget <= 0:
                break
            
            cand_tokens = candidate.get('token_count', 0)
            if cand_tokens > 0.5 * budget:
                continue

            if cand_tokens <= current_budget:
                current_budget = add_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget)
                continue

            estimated_c_token_size = estimate_c_token_complexity(candidate['function_obj'])
            # TODO: tighten C-token estimation; current heuristic is coarse.

            if estimated_c_token_size <= current_budget:
                # TODO: access the current mode from the project or pass explicitly.
                should_try_real_code = mode == "train" and random.random() < 0.25
                c_approx = real_c_code_lookup(candidate['function_obj'], project) if should_try_real_code else None
                if c_approx is None and mode == "train":
                    c_approx = decompile_context_function_to_c(candidate['function_obj'], project, old_model=None)  # TODO: hook actual model.
                else:
                    c_approx = decompile_context_function_to_c(candidate['function_obj'], project, actual_model=None)  # TODO: hook actual model.
                candidate['c_approx'] = c_approx
                current_budget = add_decompiled_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget)
                continue
            continue

        if current_budget > 0 and remaining_candidates:
            for candidate in remaining_candidates:
                candidate['score'] = _calculate_candidate_score(candidate, callgraph, all_functions_map, target_addr)

            current_budget, should_break = add_remaining_candidates_to_context(remaining_candidates, remaining_candidates, context_funcs, current_budget, callgraph, all_functions_map)

        return context_funcs

    elif REDUCTION_LEVEL == 0:
        context_funcs = []
        remaining_candidates = context_candidates_data['all_functions'].copy()

        # Prioritize by iteratively adding candidates from the lowest-degree group one-by-one until the budget is exhausted, then repeat for the next-lowest degree group.
        while remaining_candidates and current_budget > 0:
            current_degree, total_tokens_current_degree = token_degree_level_check(remaining_candidates)
            if current_degree is None:
                break
            
            # TODO: Decide whether to always iterate lower-degree groups first.
            degree_group = [c for c in remaining_candidates if c.get('degree') == current_degree]
            if not degree_group:
                remaining_candidates = [c for c in remaining_candidates if c.get('degree') != current_degree]
                continue

            # if current_budget >= total_tokens_current_degree:
            #     process_degree_group(degree_group, context_funcs, remaining_candidates, current_budget)

            # Prioritize candidates from this degree group; stop if nothing fits.
            for candidate in remaining_candidates:
                candidate['score'] = _calculate_candidate_score(candidate, callgraph, all_functions_map, target_addr)
            current_budget, should_break = add_remaining_candidates_to_context(degree_group, remaining_candidates, context_funcs, current_budget, callgraph, all_functions_map)

            if should_break:
                break

        return context_funcs
