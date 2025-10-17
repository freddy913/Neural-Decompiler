import angr
import logging

# Set logging level to be less verbose
logging.getLogger('cle').setLevel('ERROR')
logging.getLogger('pyvex').setLevel('ERROR')
# Set angr's main logger to WARNING to see important messages but not debug info
logging.getLogger('angr').setLevel('WARNING')

# configurations
TARGET_BINARY_PATH = "./sourceCode/multiply"
TARGET_FUNCTION_NAME = "complex_multiply"
CONTEXT_THRESHOLD_TOKENS = 1028

def get_full_function_assembly(func, project):
    """ Extract the complete assembly code of the function """
    if not func or not func.block_addrs:
        return ""
    
    lines = []
    # Sortiere die Blöcke nach Adresse, um eine logische Reihenfolge zu gewährleisten
    sorted_blocks = sorted(list(func.blocks), key=lambda b: b.addr)
    for block in sorted_blocks:
        lines.append(f"--- Block at {hex(block.addr)} ---")
        for insn in block.capstone.insns:
            lines.append(f"{hex(insn.address)}\t{insn.mnemonic}\t{insn.op_str}")
    return "\n".join(lines)

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

    target_assembly = get_full_function_assembly(target_func, project)
    with open(f"{TARGET_FUNCTION_NAME}_assembly.txt", "w") as f:
        f.write(target_assembly)
    print(f"Assembly code of target function '{TARGET_FUNCTION_NAME}' written to '{TARGET_FUNCTION_NAME}_assembly.txt'")

    context_functions = list(callers) + list(callees)
    for func in context_functions:
        context_assembly = get_full_function_assembly(func, project)
        with open(f"{func.name}_assembly.txt", "w") as f:
            f.write(context_assembly)
        print(f"Assembly code of context function '{func.name}' written to '{func.name}_assembly.txt'")

    ## Algorithm for long consuming target functions
    # 1. Identify target functions token size
    # 2. If token size exceeds threshold 1 (50/60% of max tokens), then decompile the context functions first
    # 2a. Start cfgAnalyzer for the context functions.
    # 2b. Use the reduced token size of decompiled context functions to help decompile the target function. (assembly has more tokens than decompiled code) 
    # 3. If token size exceeds threshold 2 (80/90% of max tokens), then reduce the context amount.. not sure how yet. 
    # 3a. Possible would be to split the target function into multiple !!decompilable!! parts.


    ## After Analysis: Heuristic Algorithm to reduce context amount
    # 1. Identify all unique callers of the target function.
    # 2. For each caller, analyze its call sites to the target function.
    # 3. Group call sites by their calling context (e.g., argument values, call stack).
    # 4. Select representative call sites from each group to minimize redundancy.
    # 5. Re-run the analysis with the reduced set of contexts if necessary.
    # 6. Find the best balance of importance and size of context to fit within token limits.
    # 7. If context is too important but too large, but also as c code is smaller than assembly, then decompile context functions first and use their c code as context for the target function.