import angr
import logging
from transformers import AutoTokenizer
import copy

# Set logging level to be less verbose
logging.getLogger('cle').setLevel('ERROR')
logging.getLogger('pyvex').setLevel('ERROR')
# Set angr's main logger to WARNING to see important messages but not debug info
logging.getLogger('angr').setLevel('WARNING')

# configurations
TARGET_BINARY_PATH = "./sourceCode/multiply"
TARGET_FUNCTION_NAME = "complex_multiply"
CONTEXT_THRESHOLD_TOKENS = 1028
MYTOKENIZER = AutoTokenizer.from_pretrained("EleutherAI/gpt-neo-1.3B") # TODO: dummy,.. replace with actual tokenizer

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

def add_candidate_to_context(context_funcs, candidate, current_budget):
    token_count = candidate.get('token_count', 0)
    if token_count <= current_budget:
        context_funcs.append(candidate)
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

def prioritize_and_add_candidates(degree_group, remaining_candidates, context_funcs, current_budget):
    # Not enough budget for the whole degree: prioritize within this degree
    prioritized = sorted(
        degree_group,
        key=lambda x: ((0 if x.get('is_leaf') else 1), x.get('token_count', float('inf')))
    )

    added_any = False
    for candidate in prioritized:
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

def apply_heuristic(target_func_data, context_candidates_data, budget, callgraph):
    # takes the target function data and the data of the context candidates
    # implements the scoring system (leaf functions bonus etc.)
    # implements the greedy selection algorithm to select the best context functions within the budget
    # returns a final sorted list of the slected context functions
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
    elif current_budget <= 0.55 * budget:
        REDUCTION_LEVEL = 1
    else:
        REDUCTION_LEVEL = 0

    if REDUCTION_LEVEL == 0:
        context_funcs = []
        remaining_candidates = context_candidates_data['all_functions'].copy()

        # first round: choose all leaf functions # TODO not needed in REDUCTION_LEVEL=0?
        # for candidate in list(remaining_candidates):
        #     if current_budget <= 0:
        #         return context_funcs
            
        #     token_count = candidate.get('token_count', 0)
        #     if token_count <= current_budget and candidate not in context_funcs:
        #         func_obj = candidate.get('function_obj', None)

        #         if candidate.is_leaf: #TODO access wrong
        #             context_funcs.append(candidate)
        #             current_budget -= func['token_count']
        #             try:
        #                 remaining_candidates.remove(candidate)
        #             except ValueError:
        #                 pass
        
        # # second round: greedy selection based on token size
        # remaining_candidates.sort(key=lambda x: x.get('token_count', float('inf')))

        # for candidate in remaining_candidates:
        #     if current_budget <= 0:
        #         break
        #     token_count = candidate.get('token_count', 0)
        #     if token_count <= current_budget and candidate not in context_funcs:
        #         context_funcs.append(candidate)
        #         current_budget -= token_count
        #         remaining_candidates.remove(candidate) # not strictly necessary here

        # return context_funcs

        # round x: selection based on degree level 
        # # TODO implement sorting here? candidate is already sorted based on degree 


        # TODO: following: 1. if current budget doesnt hold all candidates with current degree, then always find priorization in those
        # iterate degrees: at each step pick the lowest-degree group, prioritize it,
        # add prioritized candidates one-by-one until budget exhausted or group exhausted,
        # then re-evaluate remaining candidates (next degree)
        remaining_candidates = remaining_candidates  # already present above

        while remaining_candidates and current_budget > 0:
            current_degree, total_tokens_current_degree = token_degree_level_check(remaining_candidates)
            if current_degree is None:
                break

            # collect candidates for this degree
            degree_group = [c for c in remaining_candidates if c.get('degree') == current_degree]
            if not degree_group:
                # remove this degree and continue
                remaining_candidates = [c for c in remaining_candidates if c.get('degree') != current_degree]
                continue

            # If we have enough budget to include the entire current degree group,
            if current_budget >= total_tokens_current_degree:
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
                # proceed to next degree
                continue

            # try to prioritize and add candidates within this degree;
            # the function returns the updated budget and a flag that indicates whether
            # the caller should stop because no further progress is possible.
            current_budget, should_break = prioritize_and_add_candidates(degree_group, remaining_candidates, context_funcs, current_budget)
            if should_break:
                break

        return context_funcs
                
    elif REDUCTION_LEVEL == 1:
        # 2. If token size exceeds threshold 1 (50/60% of max tokens), then decompile the context functions first
        # 2a. Start cfgAnalyzer for the context functions.
        # 2b. Use the reduced token size of decompiled context functions to help decompile the target function. (assembly has more tokens than decompiled code) 
        pass
    elif REDUCTION_LEVEL == 2:
        # 3. If token size exceeds threshold 2 (80/90% of max tokens), then reduce the context amount.. not sure how yet. 
        # 3a. Possible would be to split the target function into multiple !!decompilable!! parts.
        pass

def main():
    project, cfg = load_project(TARGET_BINARY_PATH)

    target_func = next(cfg.functions.get_by_name(TARGET_FUNCTION_NAME), None)
    if target_func is None:
        print(f"Function '{TARGET_FUNCTION_NAME}' not found.")
        exit()

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

    # extract and save assembly code of target function and its relevant context
    print("\n--- Extracting Assembly Code ---")

    target_func_data = get_function_data(target_func, project, MYTOKENIZER)
    with open("target_assembly.txt", "w", encoding="utf-8") as f:
        f.write(target_func_data['assembly'])

    candidate_func_data = {
        'func_names': [],
        'all_functions': [],
        'total_token_count': 0
    }

    with open("context_assembly.txt", "w", encoding="utf-8") as f:
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
                'score': 0, # Placeholder for scoring
            }
            candidate_func_data['all_functions'].append(entry)
            candidate_func_data['func_names'].append(entry['name'])
            candidate_func_data['total_token_count'] += func_data['token_count']
    #sorted candidate func data with degree level ascending # TODO maybe sort it also based on the token size
    # sort candidate_func_data['all_functions'] ascending by degree (preserve the dict structure)
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
    context_funcs = apply_heuristic(target_func_data, candidate_func_data, CONTEXT_THRESHOLD_TOKENS, cfg.functions.callgraph)
    
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
    