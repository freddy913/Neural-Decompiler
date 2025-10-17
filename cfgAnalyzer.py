import angr
import logging
from transformers import AutoTokenizer

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

def get_assembly_and_token_count(func, project, tokenizer):
    """ Extract the assembly code and count tokens using the provided tokenizer. """
    if not func or not func.is_simprocedure and not func.is_plt:
        try:
            assembly_text = "\n".join(block.dissasembly.insns_string for block in func.blocks)
            if not assembly_text:
                return None, 0
            token_ids = tokenizer(assembly_text, add_special_tokens=False).input_ids
            return assembly_text, len(token_ids)
        except Exception as e:
            return None, 0
    return None, 0

def is_leaf_function(func, callgraph):
    return callgraph.out_degree(func.addr) == 0

def test_target_function_to_decompile(func, project):
    """ """
    ## Algorithm for long consuming target functions
    # 1. Identify target functions token size
    # 2. If token size exceeds threshold 1 (50/60% of max tokens), then decompile the context functions first
    # 2a. Start cfgAnalyzer for the context functions.
    # 2b. Use the reduced token size of decompiled context functions to help decompile the target function. (assembly has more tokens than decompiled code) 
    # 3. If token size exceeds threshold 2 (80/90% of max tokens), then reduce the context amount.. not sure how yet. 
    # 3a. Possible would be to split the target function into multiple !!decompilable!! parts.


def main():
    try:
        project = angr.Project(TARGET_BINARY_PATH, auto_load_libs=False)
    except Exception as e:
        print(f"Failed to load project: {e}")
        exit()

    print("Starting comprehensive CFG analysis to build the call graph...")
    cfg = project.analyses.CFGEmulated(
        normalize=True,
        context_sensitivity_level=2,  # Wichtig für genaue Call-Site-Analyse
        resolve_indirect_jumps=True
    )

    target_func = cfg.functions.get_by_name(TARGET_FUNCTION_NAME)
    if target_func is None:
        print(f"Function '{TARGET_FUNCTION_NAME}' not found.")
        exit()

    print(f"\n--- Target function identified: '{TARGET_FUNCTION_NAME}' at {hex(target_func.addr)} ---")

    callers = set()
    callgraph = cfg.functions.callgraph
    try:
        for pred_addr in callgraph.predecessors(target_func.addr):
            callers.add(cfg.functions.get_by_addr(pred_addr))
    except Exception as e:
        pass

    callees = set()
    try:
        for succ_addr in callgraph.successors(target_func.addr):
            callees.add(cfg.functions.get_by_addr(succ_addr))
    except Exception as e:
        pass

    callers.discard(None), callees.discard(None)

    print("\n--- Context Analysis (Generation 1) ---")
    print(f"Found {len(callers)} unique calling function(s):")
    for caller in sorted(list(callers), key=lambda f: f.name):
        print(f"  - '{caller.name}'")
        
    print(f"\nFound {len(callees)} unique called function(s):")
    for callee in sorted(list(callees), key=lambda f: f.name):
        print(f"  - '{callee.name}'")

    # extract and save assembly code of target function and its relevant context
    print("\n--- Extracting Assembly Code ---")

    target_assembly = get_assembly_and_token_count(target_func, project)
    with open(f"{TARGET_FUNCTION_NAME}_assembly.txt", "w") as f:
        f.write(target_assembly)
    print(f"Assembly code of target function '{TARGET_FUNCTION_NAME}' written to '{TARGET_FUNCTION_NAME}_assembly.txt'")

    context_functions = list(callers) + list(callees)
    for func in context_functions:
        context_assembly = get_assembly_and_token_count(func, project, MYTOKENIZER)
        with open(f"{func.name}_assembly.txt", "w") as f:
            f.write(context_assembly)
        print(f"Assembly code of context function '{func.name}' written to '{func.name}_assembly.txt'")

    # Heuristic Algorithms for Context Reduction
    # done -- 1. Identify all unique callers of the target function.
    # done -- 2. For each caller, analyze its call sites to the target function.
    # TODO: in work -- 3. Group call sites by their calling context (e.g., argument values, call stack).
    # done -- 4. Select representative call sites from each group to minimize redundancy.
    # TODO: will not do -- 5. Re-run the analysis with the reduced set of contexts if necessary.
    # done -- 6. Find the best balance of importance and size of context to fit within token limits.
    # TODO: !!! -- 7. If context is too important but too large, but also as c code is smaller than assembly, then decompile context functions first and use their c code as context for the target function.
    assembly_map = {}
    for func in list(callers) + list(callees) + [target_func]:
        assembly, token_count = get_assembly_and_token_count(func, project, MYTOKENIZER)
        if assembly:
            assembly_map[func.name] = {'code': assembly, 'tokens': token_count}

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
    