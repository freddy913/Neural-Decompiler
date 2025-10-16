import angr
import logging

# Set logging level to be less verbose
logging.getLogger('cle').setLevel('ERROR')
logging.getLogger('pyvex').setLevel('ERROR')
# Set angr's main logger to WARNING to see important messages but not debug info
logging.getLogger('angr').setLevel('WARNING')

try:
    project = angr.Project("./sourceCode/multiply", auto_load_libs=False)
except Exception as e:
    print(f"Failed to load project: {e}")
    exit()

print("Starting comprehensive CFG analysis to build the call graph...")
# CFG-Analyse mit XRefs
cfg = project.analyses.CFGEmulated(
    normalize=True,
    context_sensitivity_level=2,  # Wichtig für genaue Call-Site-Analyse
    resolve_indirect_jumps=True
)
print("Analysis complete.")

target_func_name = "complex_multiply"
func_candidates= cfg.functions.get_by_name(target_func_name)
target_func = next(func_candidates, None)
if target_func is None:
    print(f"Function '{target_func_name}' not found.")
    exit()

print(f"\n--- Analyzing Callers for '{target_func_name}' at {hex(target_func.addr)} ---")

callers = []
callgraph = cfg.functions.callgraph
try:
    for pred_addr in callgraph.predecessors(target_func.addr):
        caller_func = project.kb.functions.get_by_addr(pred_addr)
        if caller_func is not None:
            callers.append(caller_func)
except Exception as e:
    pass

unique_callers = sorted(list(set(callers)), key=lambda f: f.addr)

if not unique_callers:
    print("No callers found for this function.")
else:
    print(f"Found {len(unique_callers)} unique calling function(s):")
    for caller in unique_callers:
        print(f"  - '{caller.name}'")

print("\n--- End of Analysis ---")

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

contextReduction = True  # Placeholder for context reduction logic

# 3. Extract assembly code 
print("\nAssembly code of the target function:")
try:
    print("\nPretty-printed version (visual control flow):")
    target_func.pp()

    lines = []
    for block_addr in target_func.block_addrs:
        block = project.factory.block(block_addr)
        lines.append(f"--- Block at {hex(block.addr)} ---")
        for insn in block.capstone.insns:
            lines.append(str(insn))

    file_name = f"{target_func_name}_assembly.txt"
    with open(file_name, "w") as f:
        f.write("\n".join(lines))
    print(f"\nFull assembly code written to {file_name}")


except Exception as e:
    print(f"Could not extract assembly. Error: {e}")
