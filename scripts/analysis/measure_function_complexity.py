"""
Measures and exports cyclomatic complexity metrics for compiled binary functions.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import csv
import logging
from tqdm import tqdm

logging.getLogger('angr').setLevel('ERROR')
logging.getLogger('cle').setLevel('ERROR')

from pipeline.AsmToInput import load_project
from pipeline.Heuristic import is_relevant_user_like_function

SOURCE_DIR = "../COMPILED/TESTER"
OUTPUT_FILE = "function_complexity.csv"

def get_complexity(func_obj):
    """
    Calculates basic block count and cyclomatic complexity for function.
    Args:
        :param func_obj: Angr function object.
        :return: Tuple of (block_count, cyclomatic_complexity) or (None, None).
    """
    if not func_obj:
        return None, None
    
    try:
        block_count = len(func_obj.blocks)
        num_nodes = func_obj.graph.number_of_nodes()
        num_edges = func_obj.graph.number_of_edges()
        cyclomatic_complexity = num_edges - num_nodes + 2
        
        return block_count, cyclomatic_complexity
    except Exception:
        return None, None

def main():
    """
    Scans binaries and exports complexity metrics to CSV.
    Args:
        :return: None. Writes results to OUTPUT_FILE.
    """
    print(f"=== Starting complexity analysis for {SOURCE_DIR} ===")
    
    results = []
    binaries = [os.path.join(root, f) for root, _, files in os.walk(SOURCE_DIR) for f in files if f.startswith("executable") or f.endswith(".o")]

    for bin_path in tqdm(binaries, desc="Analyzing binaries"):
        proj, cfg = load_project(bin_path)
        if not proj or not cfg:
            continue

        target_functions = [f for f in cfg.functions.values() if is_relevant_user_like_function(f) and not f.is_plt]

        for func in target_functions:
            block_count, complexity = get_complexity(func)
            if block_count is not None:
                results.append({
                    "binary": os.path.basename(bin_path),
                    "function": func.name,
                    "basic_blocks": block_count,
                    "cyclomatic_complexity": complexity
                })

    if results:
        with open(OUTPUT_FILE, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"\nAnalysis completed. Results saved to {OUTPUT_FILE}")
    else:
        print("No functions found for analysis.")

if __name__ == "__main__":
    main()