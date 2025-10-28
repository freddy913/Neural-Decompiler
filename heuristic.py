from config import JUNK_FUNCTIONS
from binary_analysis import get_token_count
import copy, random, os, re

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
    Scores a contetfunction (higher = better)
    """
    # 1: semantical similarity (RAG-Idee) 
    # similarity = calculate_embedding_similarity(candidate['name'], target_func.name, vector_db)
    # score += similarity * 30  # Max +30 Punkte

    # 2: direct udt-data pointer sharing
    if _candidate_func_calls_target(candidate['function_obj'].addr, callgraph, target_addr):
        candidate['score'] += 30  # Give bonus for sharing udt_pointer

    # 3: Leaf status, punishes complexity
    num_callees = _count_non_junk_callees(candidate['function_obj'], callgraph, all_program_funcs, JUNK_FUNCTIONS)
    candidate['score'] -= num_callees * 5  # Penalize for more (non-junk) callees

    # 4: Call Graph distance, penalizes for higher degrees
    candidate['score'] -= (candidate.get('degree', 0)-1) * 10  # TODO: needed if we even iterate only in degree classes?
    
    # 5: Token size, punishes larger functions
    c_token_count = candidate.get('token_count', 0)
    candidate['score'] -= c_token_count / 100  # Slightly penalize larger functions

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
    # Not enough budget for the whole degree: prioritize within this degree
    # TODO: Iterate over degree groups or all candidates? TODO: REMOVE DEGREE OR ALSO BREAK RETURN VALUE?
    # prioritized = sorted(
    #     degree_group,
    #     key=lambda x: ((0 if x.get('is_leaf') else 1), x.get('token_count', float('inf')))
    # )
    prioritized = remaining_candidates
    added_any = False
        
    # sort the prioritized list based on score (higher is better)
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
            # signal the caller that no further progress is possible
            return current_budget, True

    return current_budget, False

def estimate_c_token_complexity(func):
    """
    Estimates the expected C code token count based on CFG complexity.
    Returns a numeric score (higher = more complex/more tokens).
    """
    if not func:
        return float('inf') # Expection: very complex if no function provided

    function_cfg = func.graph
    
    if not function_cfg:
        return 1 # Expection: easy function if there is no graph

    # estimation heuristic:
    # We estimate complexity based on number of nodes and edges in the CFG. 
    # We weight the number of nodes and edges.
    # Edges are often a better indicator of complexity (if/else, loops).

    num_nodes = function_cfg.number_of_nodes()
    num_edges = function_cfg.number_of_edges()

    # Cyclomatic complexity: a classic metric for code complexity
    # Formula: E - N + 2P (edges - nodes + 2 * number of exits)
    # Simplified for our purposes:
    complexity_score = (num_edges * 1.5) + (num_nodes * 1.0)

    # Scaling factor: you would need to determine this factor empirically on your dataset,
    # but we can start with a simple assumption.
    # E.g.: 1 complexity point ≈ 5 C-tokens
    estimated_tokens = complexity_score * 5.0
    
    return estimated_tokens

def real_c_code_for_training(func_obj, project):
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

# TODO: 
def decompile_context_function_to_c(func_obj, project): 
    """
    Decompiles the given function object to C code using the project's decompiler.
    """
    pass

# TODO: 
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

def apply_heuristic(target_func_data, context_candidates_data, budget, callgraph, all_functions_map, target_addr, project):
    """
    Choses context functions based on the heuristic strategy within a token budget.
    """
    current_budget = budget - target_func_data['token_count']
    if current_budget <= 0: # TODO: what if target_func_tokens exceed budget?
        return []
    
    try:
        total_context_tokens = context_candidates_data['total_token_count', 0]
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
        # 3. If token size exceeds threshold 2 (80/90% of max tokens), then reduce the context amount.. not sure how yet. 
        # 3a. Possible would be to split the target function into multiple !!decompilable!! parts.
        pass
    elif REDUCTION_LEVEL == 1:
        # 2. If token size exceeds threshold 1 (40% of max tokens), then decompile some context functions first
        print("INFO: Target function is large. Applying 'Hybrid Context' strategy.")

        # TODO: implement the hybrid-context-strategy here:
        # 1. score all candidate functions based on existing scoring system
        context_funcs = []
        remaining_candidates = context_candidates_data['all_functions'].copy()
        
        for candidate in remaining_candidates:
            candidate['score'] = _calculate_candidate_score(candidate, callgraph, all_functions_map, target_addr)

        # 2. estimate c token size for first five important candidates (check if decompilation is possible without reduction first)
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
                candidate['reduced_mode'] = 'assembly'
                current_budget = add_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget)
                continue

            estimated_c_token_size = estimate_c_token_complexity(candidate['function_obj'])
            #TODO: c_token count broken!!
            candidate['estimated_c_token_count'] = estimated_c_token_size

            if estimated_c_token_size <= current_budget:
                candidate['reduced_mode'] = 'decompiled_c'
                # TODO access the current mode from project or pass as parameter??
                # if project.mode == "train":
                percentage = random.randint(0,100)
                if percentage < 101: # TODO später umstellen auf 25/75 
                    c_approx = real_c_code_for_training(candidate['function_obj'], project)
                    if c_approx is None:
                        c_approx = decompile_context_function_to_c(candidate['function_obj'], project)
                else:
                    c_approx = decompile_context_function_to_c(candidate['function_obj'], project)

                candidate['c_approx'] = c_approx
                add_decompiled_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget)

                # elif project.mode == "infer":
                #     c_approx = decompile_context_function_to_c(candidate['function_obj'], project)
                # TODO: store c_approx in candidate data, e.g. candidate['decompiled_c_approx'] = c_approx, 
                candidate['token_count'] = estimated_c_token_size  # temporarily set token count to estimated c token count
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
            
            # TODO: Process all candidates OR prioritize first within lower degree levels?
            degree_group = [c for c in remaining_candidates if c.get('degree') == current_degree]
            if not degree_group:
                remaining_candidates = [c for c in remaining_candidates if c.get('degree') != current_degree]
                continue

            # if current_budget >= total_tokens_current_degree:
            #     process_degree_group(degree_group, context_funcs, remaining_candidates, current_budget)

            # Prioritize: Attempts to add candidates from this degree_group, returning the updated budget and a flag (True=stop) if no further progress is possible.
            for candidate in remaining_candidates:
                candidate['score'] = _calculate_candidate_score(candidate, callgraph, all_functions_map)
            current_budget, should_break = add_remaining_candidates_to_context(degree_group, remaining_candidates, context_funcs, current_budget, callgraph, all_functions_map)

            if should_break:
                break

        return context_funcs