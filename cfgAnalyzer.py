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
    # returns a dictiornary with callers and callees

    all_functions = get_all_functions(cfg)
    context_candidates = {'callers': set(), 'callees': set()}

    callgraph = cfg.functions.callgraph
    for func in all_functions:
        try:
            for succ_addr in callgraph.successors(func.addr):
                if succ_addr == target_func.addr:
                    context_candidates['callers'].add(func)
        except Exception as e:
            pass

        try:
            for pred_addr in callgraph.predecessors(func.addr):
                if pred_addr == target_func.addr:
                    context_candidates['callees'].add(func)
        except Exception as e:
            pass
    
    context_candidates['callers'].discard(None)
    context_candidates['callees'].discard(None)

    return context_candidates

def get_function_assembly(func):
    # takes a function object
    # returns the assembly code as a string
    assembly_lines = []
    try:
        for block in func.blocks:
            assembly_lines.append(block.disassembly.insns_string)
    except Exception as e:
        return ""
    
    return "\n".join(assembly_lines)

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

def apply_heuristic(target_func_data, context_candidates_data, budget, callgraph):
    # takes the target function data and the data of the context candidates
    # implements the scoring system (leaf functions bonus etc.)
    # implements the greedy selection algorithm to select the best context functions within the budget
    # returns a final sorted list of the slected context functions
    current_budget -= target_func_data['token_count', 0]
    if current_budget <= 0:
        return []
    
    try:
        if current_budget > context_candidates_data['total_token_count', 0]:
            return context_candidates_data['all_functions', []].copy()
    except Exception as e:
        pass

    if current_budget <= 0.2 * budget:
        REDUCTION_LEVEL = 2
    elif current_budget <= 0.4 * budget:
        REDUCTION_LEVEL = 1
    else:
        REDUCTION_LEVEL = 0

    if REDUCTION_LEVEL == 0:
        used_candidates = []
        remaining_candidates = context_candidates_data['all_functions'].copy()

        # first round: choose all leaf functions
        for candidate in list(remaining_candidates):
            if current_budget <= 0:
                return used_candidates
            
            token_count = candidate.get('token_count', 0)
            if token_count <= current_budget and candidate not in used_candidates:
                func_obj = candidate.get('function_obj', None)
                try: 
                    is_leaf = is_leaf_function(func_obj, callgraph) if func_obj is not None else candidate.get('is_leaf', False)
                except Exception:
                    is_leaf = candidate.get('is_leaf', False)

                if is_leaf:
                    used_candidates.append(candidate)
                    current_budget -= func['token_count']
                    try:
                        remaining_candidates.remove(candidate)
                    except ValueError:
                        pass
        
        # second round: greedy selection based on token size
        remaining_candidates.sort(key=lambda x: x.get('token_count', float('inf')))

        for candidate in remaining_candidates:
            if current_budget <= 0:
                break
            token_count = candidate.get('token_count', 0)
            if token_count <= current_budget and candidate not in used_candidates:
                used_candidates.append(candidate)
                current_budget -= token_count
                remaining_candidates.remove(candidate) # not strictly necessary here

        return used_candidates
                
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

    target_func = cfg.functions.get_by_name(TARGET_FUNCTION_NAME)
    if target_func is None:
        print(f"Function '{TARGET_FUNCTION_NAME}' not found.")
        exit()

    print(f"\n--- Target function identified: '{TARGET_FUNCTION_NAME}' at {hex(target_func.addr)} ---")

    context_candidates = get_context_candidates(target_func, cfg)

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
    

    context_assembly = []
    for func in context_candidates:
        func_data = get_function_data(func, project, MYTOKENIZER)
        context_assembly.append(func_data['assembly'])

    with open("context_assembly.txt", "w", encoding="utf-8") as f:
        for func_data in context_assembly:
            name = func_data.get('name', 'unknown_function')
            f.write(f";;; Function: {name}\n")
            f.write(func_data['assembly'] or "" + "\n\n")

    context_func_data = {
        'func_names': [],
        'all_functions': [],
        'total_token_count': 0
    }

    for i, func in enumerate(context_candidates):
        func_data = context_assembly[i]
        try:
            is_leaf = is_leaf_function(func, cfg.functions.callgraph)
        except Exception as e:
            is_leaf = func.data('is_leaf', False)

        entry = {
            'function_obj': func,
            'name': func_data.get('name'),
            'assembly': func_data['assembly'],
            'token_count': func_data['token_count'],
            'is_leaf': is_leaf,
            score: 0, # Placeholder for scoring
        }
        context_func_data['all_functions'].append(entry)
        context_func_data['func_names'].append(entry['name'])
        context_func_data['total_token_count'] += func_data['token_count']

    # Heuristic Algorithms for Context Reduction
    # done -- 1. Identify all unique callers of the target function.
    # done -- 2. For each caller, analyze its call sites to the target function.
    # TODO: in work -- 3. Group call sites by their calling context (e.g., argument values, call stack).
    # done -- 4. Select representative call sites from each group to minimize redundancy.
    # TODO: will not do -- 5. Re-run the analysis with the reduced set of contexts if necessary.
    # done -- 6. Find the best balance of importance and size of context to fit within token limits.
    # TODO: !!! -- 7. If context is too important but too large, but also as c code is smaller than assembly, then decompile context functions first and use their c code as context for the target function.

    ## TODO: refactor from here ongoing
    used_canidates = apply_heuristic(target_func_data, context_func_data, CONTEXT_THRESHOLD_TOKENS, cfg.functions.callgraph)
    assembly_map = {}
    for func in used_canidates + [target_func]:
        if func.assembly:
            assembly_map.append({func.assembly})

    ### from here heurisitc override with upper functions
    if target_func.name not in assembly_map:
        print("Coult not retrieve assembly for target function. Aborting.")
        return
    
    target_token_count = assembly_map[target_func.name]['tokens']
    context_token_budget = CONTEXT_THRESHOLD_TOKENS - target_token_count

    scored_candidates = []
    for func in context_functions:
        if func.name not in assembly_map: continue
        score = 0
        if is_leaf_function(func, callgraph): score += 20
        # TODO: Add more scoring criteria here

        scored_candidates.append({
            'name': func.name,
            'score': score,
            'tokens': assembly_map[func.name]['tokens']
        })

    scored_candidates.sort(key=lambda x: x['score'], reverse=True)

    selected_context_assembly = []
    current_context_tokens = 0
    print("\n--- Heuristic Context Selection ---")
    print(f"Target function token count: {target_token_count}")
    print(f"Available context token budget: {context_token_budget}")

    for item in scored_candidates:
        if current_context_tokens + item['tokens'] <= context_token_budget:
            selected_context_assembly.append(assembly_map[item['name']]['code'])
            current_context_tokens += item['tokens']
            print(f"Included context function '{item['name']}' (Tokens: {item['tokens']}, Score: {item['score']})")
        else:
            print(f"Skipped context function '{item['name']}' (Tokens: {item['tokens']}, Score: {item['score']}) - would exceed budget")
    
    final_context_input_string = "\n<SEP>\n".join(selected_context_assembly) + \
                                 "\n<TARGET_SEP>\n" + assembly_map[target_func.name]['code']
    
    with open("final_model_input.txt", "w") as f:
        f.write(final_context_input_string)

    print("\n--- Final Results ---")
    print(f"Total context functions selected: {len(selected_context_assembly)}")
    print(f"Total context tokens used: {current_context_tokens} / {context_token_budget}")
    print("The final, combined assembly input for the model has been saved to 'final_model_input.txt'")


if __name__ == "__main__":
    main()  
    