import angr
import logging
from transformers import AutoTokenizer
import copy
# test
# Set logging level to be less verbose
logging.getLogger('cle').setLevel('ERROR')
logging.getLogger('pyvex').setLevel('ERROR')
# Set angr's main logger to WARNING to see important messages but not debug info
logging.getLogger('angr').setLevel('WARNING')

# configurations
TARGET_BINARY_PATH = "./sourceCode/multiply"
TARGET_FUNCTION_NAME = "complex_multiply"
TARGET_FUNC_ADDR = None  # will be set in main
CONTEXT_THRESHOLD_TOKENS = 1024 # TODO: substract puffer for label tokens later in post processing
MYTOKENIZER = AutoTokenizer.from_pretrained("EleutherAI/gpt-neo-1.3B") # TODO: dummy,.. replace with actual tokenizer
JUNK_FUNCTIONS = {"printf", "malloc", "free", "scanf", "puts", "gets", "exit"}
BASIC_SCORE = 100

def load_project(binary_path):
    # takes a path to a binary and loads an angr project
    # returns the loaded angr.project object and the cfg-object
    # failures have to be handled as file not found or invalid binary
    try:
        project = angr.Project(binary_path, auto_load_libs=False)
    except Exception as e:
        print(f"Failed to load project: {e}")
        return None
    
    try:
        cfg = project.analyses.CFGEmulated(
            normalize=True,
            context_sensitivity_level=2,  # Wichtig für genaue Call-Site-Analyse
            resolve_indirect_jumps=True
        )
    except Exception as e:
        print(f"Failed to generate CFG: {e}")
        return None
    
    return project, cfg

def get_all_functions(cfg):
    # takes a cfg-object
    # returns a list of all function objects in the program
    functions = set()
    for func in cfg.functions.values():
        functions.add(func)

    return list(functions)

def get_context_candidates(target_func, cfg):
    # takes a target function and the cfg
    # returns a dictionary with callers and callees of the target function
    if not target_func:
        return {'callers': set(), 'callees': set()}

    callgraph = cfg.functions.callgraph
    callers = set()
    callees = set()

    try:
        for succ_addr in callgraph.successors(target_func.addr):
            caller_func = cfg.functions.get_by_addr(succ_addr)
            if caller_func:
                callers.add(caller_func)
    except Exception as e:
        pass

    try:
        for pred_addr in callgraph.predecessors(target_func.addr):
            callee_func = cfg.functions.get_by_addr(pred_addr)
            if callee_func:
                callees.add(callee_func)
    except Exception as e:
        pass

    return {'callers': callers, 'callees': callees}

def get_context_candidates_with_degrees(target_func, cfg, degrees=2): # TODO: here we use degrees=2 as default
    # takes a target function and the cfg
    # returns a dictionary with callers and callees mapped to their minimum degree distance

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

def get_function_assembly(func):
    if func is None:
        return ""

    lines = []
    for block in func.blocks:
        try:
            capstone_block = block.capstone  # CapstoneBlock
        except Exception:
            continue  # skip blocks we can’t lift

        lines.append(f";;; Block @ {hex(block.addr)}")
        insns = getattr(capstone_block, "insns", [])
        if insns:
            for insn in insns:
                lines.append(str(insn))
        else:
            lines.append(str(capstone_block))
    return "\n".join(lines)

def get_token_count(assembly_code, tokenizer):
    # takes assembly code as string and a tokenizer
    # returns the token count of the assembly code
    try:
        token_ids = tokenizer(assembly_code, add_special_tokens=False).input_ids
    except Exception as e:
        return 0
    
    return len(token_ids)

def get_function_data(func, project, tokenizer):
    # takes a function object, angr.project and tokenizer
    # returns a dictionary with all relevant data {'name': func.name, 'assembly': '...', 'token_count': 123}
    if func is None:
        return {'name': None, 'assembly': '', 'token_count': 0}
    
    try:
        assembly_code = get_function_assembly(func)
    except Exception as e:
        assembly_code = ""
    
    try:
        token_count = get_token_count(assembly_code, tokenizer)
    except Exception as e:
        token_count = 0
    
    return {'name': func.name, 'assembly': assembly_code, 'token_count': token_count}

def is_leaf_function(func, callgraph):
    return callgraph.out_degree(func.addr) == 0

def add_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget):
    token_count = candidate.get('token_count', 0)
    if token_count <= current_budget:
        context_funcs.append(candidate)
        try:
            remaining_candidates.remove(candidate)
        except ValueError:
            pass
        current_budget -= token_count
    return current_budget

def token_degree_level_check(remaining_candidates):
    # compute total token count of current degree level and check if it fits in the budget otherwise find prioritization inside degree level
    # find current lowest degree level and sum up token counts of all candidates with that degree
    if not remaining_candidates:
        return None, 0

    # find the lowest degree among remaining candidates
    min_degree = min((c.get('degree', float('inf')) for c in remaining_candidates))

    # sum token counts for all candidates that have that lowest degree
    total_tokens_current_degree = sum(
        c.get('token_count', 0) for c in remaining_candidates if c.get('degree') == min_degree
    )

    return min_degree, total_tokens_current_degree

def remove_junk_functions(funcs):
    # removes junk functions from the list of function entries
    return [func for func in funcs if func[0].name not in JUNK_FUNCTIONS]

def _count_non_junk_callees(func_obj, callgraph, all_program_funcs, junk_set=JUNK_FUNCTIONS):
    """Return the number of outgoing call edges whose destination is not in junk_set."""
    if not func_obj:
        return 0

    try:
        # Hole die Adressen aller direkt aufgerufenen Funktionen
        successor_addrs = callgraph.successors(func_obj.addr)
        
        non_junk_count = 0
        for addr in successor_addrs:
            # Schlage den Namen der aufgerufenen Funktion nach
            callee_func = all_program_funcs.get(addr)
            if callee_func and callee_func.name not in junk_set:
                # Wenn wir die Funktion finden und ihr Name nicht in der Junk-Liste ist, zählen wir sie.
                non_junk_count += 1
        
        return non_junk_count
        
    except Exception:
        # Wenn etwas schiefgeht (z.B. Funktion nicht im Graphen), nehmen wir an, sie ist ein Blatt.
        return 0

def _candidate_func_has_udt_pointer(candidate_addr, cg):
    return TARGET_FUNC_ADDR in cg.successors(candidate_addr)

def _calculate_candidate_score(candidate, callgraph, all_program_funcs):
    # if current_budget <= 0:
        #     break

    # 1: semantical similarity (RAG-Idee) 
    # similarity = calculate_embedding_similarity(candidate['name'], target_func.name, vector_db)
    # score += similarity * 30  # Max +30 Punkte

    # 2: direct udt-data pointer sharing
    if _candidate_func_has_udt_pointer(candidate['function_obj'].addr, callgraph):
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

def add_remaining_candidates_to_context(degree_group, remaining_candidates, context_funcs, current_budget, callgraph, all_program_funcs):
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
        # if a candidate doesn't fit, skip to next candidate in same degree

    # if we couldn't add any from this degree, check if any remaining candidate fits at all;
    # if none fit, indicate the caller to stop to avoid infinite loop
    if not added_any:
        any_fittable = any(c.get('token_count', 0) <= current_budget for c in remaining_candidates)
        if not any_fittable:
            # signal the caller that no further progress is possible
            return current_budget, True

    # otherwise indicate that processing can continue
    return current_budget, False

def process_degree_group(degree_group, context_funcs, remaining_candidates, current_budget):
    for candidate in degree_group:
        if current_budget <= 0:
            break
        if candidate in context_funcs:
            try:
                remaining_candidates.remove(candidate)
            except ValueError:
                pass
            continue
        token_count = candidate.get('token_count', 0)
        if token_count <= current_budget:
            current_budget = add_candidate_to_context(context_funcs, candidate, current_budget)
        try:
            remaining_candidates.remove(candidate)
        except ValueError:
            pass

def estimate_c_token_complexity(func, cfg):
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
    estimated_tokens = complexity_score * 5
    
    return estimated_tokens

def apply_heuristic(target_func_data, context_candidates_data, budget, callgraph, all_functions_map):
    # takes the target function data and the data of the context candidates
    # implements the scoring system (leaf functions bonus etc.)
    # implements the greedy selection algorithm to select the best context functions within the budget
    # returns a final sorted list of the selected context functions
    current_budget = budget - target_func_data['token_count']
    if current_budget <= 0: # TODO: what if target_func_tokens exceed budget?
        return []
    
    try:
        if current_budget > context_candidates_data['total_token_count', 0]:
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
            candidate['score'] = _calculate_candidate_score(candidate, callgraph, all_functions_map)

        # 2. estimate c token size for first five important candidates (check if decompilation is possible without reduction first)
        important_candidates = sorted(
            remaining_candidates,
            key=lambda x: -x.get('score', 0)
        )[:5]

        for candidate in important_candidates:
            if candidate.get('token_count', 0) > 0.5 * budget:
                important_candidates.remove(candidate)
                continue
            else:
                estimated_c_token_size = estimate_c_token_complexity(candidate['function_obj'], callgraph)
                candidate['estimated_c_token_count'] = estimated_c_token_size

        # 3. try to add candidates with assembly, if not enough budget, try with estimated c token size (only first 5 important candidates)
        for candidate in important_candidates:
            token_count = candidate.get('token_count', 0)
            estimated_c_token_count = candidate.get('estimated_c_token_count', float('inf'))
            if token_count <= current_budget:
                current_budget = add_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget)
            elif estimated_c_token_count <= current_budget:
        # 4. decompile it with a baseline model and with no reduction applied 
        #    `decompiled_c = decompile_function(candidate_assembly)`
                print(f"--> (TODO: Decompilation logic not yet implemented, using assembly token count for now)")
        # 5. Calculate the token count of the decompiled C code.
        #    `c_token_count = len(tokenizer(decompiled_c).input_ids)`
                true_c_token_count = estimated_c_token_count  # placeholder for actual c token count
                candidate['estimated_c_token_count'] = true_c_token_count  # update token count to c token
                current_budget = add_candidate_to_context(remaining_candidates, context_funcs, candidate, current_budget)
            else:
                continue
        
        current_budget, should_break = add_remaining_candidates_to_context(remaining_candidates, context_funcs, current_budget, callgraph, all_functions_map)

        return context_funcs
    elif REDUCTION_LEVEL == 0:
        context_funcs = []
        remaining_candidates = context_candidates_data['all_functions'].copy()

        # level 0: selection based on degree level -> then their leaf status -> then token size
        # # TODO implement sorting here? candidate is already sorted based on degree 

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

def main():
    project, cfg = load_project(TARGET_BINARY_PATH)
    target_func = next(cfg.functions.get_by_name(TARGET_FUNCTION_NAME), None)
    if target_func is None:
        print(f"Function '{TARGET_FUNCTION_NAME}' not found.")
        exit()
    global TARGET_FUNC_ADDR
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

    candidate_funcs = remove_junk_functions(candidate_funcs)

    print(f"\nAfter filtering junk functions, {len(candidate_funcs)} candidate functions remain for context consideration.")


    print("\n--- Extracting Assembly Code ---")

    target_func_data = get_function_data(target_func, project, MYTOKENIZER)
    with open("target_assembly.txt", "w", encoding="utf-8") as f:
        f.write(target_func_data['assembly'])

    candidate_func_data = {
        'func_names': [],
        'all_functions': [],
        'total_token_count': 0
    }

    with open("context_candidate_assembly.txt", "w", encoding="utf-8") as f:
        for func, degree, role in candidate_funcs:
            func_data = get_function_data(func, project, MYTOKENIZER)
            name = func_data['name'] or 'unknown_function'

            f.write(f";;; Function: {name} (degree {degree})\n")
            f.write(func_data['assembly'])
            f.write("\n\n")

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



    # Heuristic Algorithms for Context Reduction
    # done -- 1. Identify all unique callers of the target function.
    # done -- 2. For each caller, analyze its call sites to the target function.
    # TODO: in work -- 3. Group call sites by their calling context (e.g., argument values, call stack).
    # done -- 4. Select representative call sites from each group to minimize redundancy.
    # TODO: will not do -- 5. Re-run the analysis with the reduced set of contexts if necessary.
    # done -- 6. Find the best balance of importance and size of context to fit within token limits.
    # TODO: !!! -- 7. If context is too important but too large, but also as c code is smaller than assembly, then decompile context functions first and use their c code as context for the target function.

    ## TODO: refactor from here ongoing
    context_funcs = apply_heuristic(target_func_data, candidate_func_data, CONTEXT_THRESHOLD_TOKENS, cfg.functions.callgraph, all_functions_map)
    with open("selected_context_functions.txt", "w", encoding="utf-8") as f:
        for entry in context_funcs:
            f.write(f";;; Function: {entry.get('name', 'unknown_function')} (degree {entry.get('degree', 'n/a')}, role {entry.get('role', 'context')})\n")
            f.write(entry.get('assembly', '') + "\n\n")

    context_segments = []
    for entry in context_funcs:
        code = entry.get('assembly') or ""
        if not code:
            continue
        name = entry.get('name') or 'unknown_function'
        degree = entry.get('degree', 'n/a')
        role = entry.get('role', 'context')
        header = f";;; Context: {name} (degree {degree}, role {role})"
        context_segments.append(header + "\n" + code)

    target_segment = target_func_data.get('assembly', '')
    target_name = target_func_data.get('name', TARGET_FUNCTION_NAME)
    target_header = f";;; Target: {target_name}"

    final_context_input_string = "\n<SEP>\n".join(context_segments)
    final_context_input_string += "\n<TARGET_SEP>\n" + target_header + "\n" + target_segment

    with open("final_model_input.txt", "w", encoding="utf-8") as outf:
        outf.write(final_context_input_string)

    print("\n--- Final Transformer Input ---")
    print(f"Context segments included: {len(context_segments)}")
    print("Combined input saved to 'final_model_input.txt'")


if __name__ == "__main__":
    main()
    