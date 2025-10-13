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
    print("Please make sure the binary file exists at './sourceCode/multiply' relative to your execution directory.")
    exit()

print("Starting comprehensive CFG analysis to build the call graph...")
# DER ENTSCHEIDENDE SCHRITT: Wir konfigurieren die CFG-Analyse so,
# dass sie auch Querverweise (xrefs) sammelt.
cfg = project.analyses.CFGEmulated(
    normalize=True,
    context_sensitivity_level=2,  # Wichtig für genaue Call-Site-Analyse
    resolve_indirect_jumps=True
)
print("Analysis complete.")

target_func_name = "complex_multiply"
target_func = project.kb.functions.function(name=target_func_name)
if target_func is None:
    print(f"Function '{target_func_name}' not found.")
    exit()

print(f"Running XRefs analysis for '{target_func_name}'...")
project.analyses.XRefs(func=target_func)

print(f"\n--- Analyzing Callers for '{target_func_name}' at {hex(target_func.addr)} ---")

callers = []
callgraph = project.kb.functions.callgraph
for caller_addr, _, edge_data in callgraph.in_edges(target_func.addr, data=True):
    if edge_data.get("type") != "call":
        continue
    caller_func = project.kb.functions.get_by_addr(caller_addr)
    if caller_func is not None:
        callers.append(caller_func)

unique_callers = sorted(list(set(callers)), key=lambda f: f.addr)

if not unique_callers:
    print("No callers found for this function.")
else:
    print(f"Found {len(unique_callers)} unique calling function(s):")
    for caller in unique_callers:
        print(f"  - '{caller.name}'")

print("\n--- End of Analysis ---")

print("\nAssembly code of the target function:")
try:
    target_func.pp()
except Exception:
    print("Could not pretty-print the function.")