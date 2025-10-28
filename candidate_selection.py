from config import JUNK_FUNCTIONS, RUNTIME_ENTRY_FUNCTIONS, BASIC_SCORE, MYTOKENIZER
from binary_analysis import get_function_data

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

def get_context_candidates_with_degrees(target_func, cfg, degrees=2): # TODO: here we use degrees=2 as default
    """
    retrieves neighbours in the call graph up to a certain degree
    1 = direct callers/callees
    2 = callers/callees of callers/callees
    etc.
    """
    if not target_func or degrees < 1:
        return {'callers': {}, 'callees': {}}

    callers = {}  # mapping: function_obj -> min degree observed
    callees = {}  # mapping: function_obj -> min degree observed

    nodes_to_search = {target_func}
    visited_addrs = set()

    for degree in range(1, degrees + 1):
        next_nodes = set()

        for node in nodes_to_search:
            # avoid re-processing the same node address
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
                # skip already-visited addresses and don't record the target function itself
                if not hasattr(f, "addr") or f.addr in visited_addrs or f.addr == target_func.addr:
                    continue
                # record the smallest degree seen for this function
                prev = callers.get(f)
                if prev is None or degree < prev:
                    callers[f] = degree
                next_nodes.add(f)

            for f in node_callees:
                if f is None:
                    continue
                # skip already-visited addresses and don't record the target function itself
                if not hasattr(f, "addr") or f.addr in visited_addrs or f.addr == target_func.addr:
                    continue
                prev = callees.get(f)
                if prev is None or degree < prev:
                    callees[f] = degree
                next_nodes.add(f)

            visited_addrs.add(node.addr)

        # prepare for next round: only include nodes not yet visited
        nodes_to_search = {f for f in next_nodes if f and hasattr(f, "addr") and f.addr not in visited_addrs and f.addr != target_func.addr}

        if not nodes_to_search:
            break

    return {'callers': callers, 'callees': callees}

def remove_junk_functions(funcs):
    """
    TODO: OLD? 
    removes junk functions from the list of function entries
    """
    return [func for func in funcs if func[0].name not in JUNK_FUNCTIONS]

def _is_trampoline_or_tiny(func_obj, max_blocks=2, max_insns=8):
    """
    Remove wrapper / trampoline functions. Mostly 1 basic block, very few instructions.
    """
    try:
        blocks = list(func_obj.blocks)
    except Exception:
        return False  # in case of error, assume not a trampoline
    
    if len(blocks) > max_blocks:
        return False  # more than max blocks, not a trampoline

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
    
    # drop everything from the PLT (libc/syscalls etc.)
    if getattr(func_obj, "is_plt", False):
        return False

    # drop intern runtime functions with __ prefix
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
    # sorted candidate func data with degree level ascending # TODO maybe sort it also based on the token size

    candidate_func_data['all_functions'].sort(key=lambda x: x.get('degree', float('inf')))
    # update func_names to match the new ordering
    candidate_func_data['func_names'] = [entry.get('name') for entry in candidate_func_data['all_functions']]

    return candidate_func_data