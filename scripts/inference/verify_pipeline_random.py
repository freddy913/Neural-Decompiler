"""
Verifies pipeline output against objdump for random batch of test samples.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import subprocess
import re
import argparse
import random
import glob
from pipeline.AsmToInput import _generate_input_from_binary

COMPILED_ROOT = "COMPILED"
INPUT_DIR = "INPUT"

def get_objdump_output(binary_path, func_name):
    """
    Extracts ground truth assembly code using objdump.
    Args:
        :param binary_path: Path to binary file.
        :param func_name: Function name to disassemble.
        :return: List of assembly instruction strings.
    """
    if not os.path.exists(binary_path):
        return [f"Error: Binary not found at {binary_path}"]

    try:
        # -d: disassemble, -M intel: Intel syntax, --no-show-raw-insn: Nur mnemonics
        cmd = ["objdump", "-d", "-M", "intel", "--no-show-raw-insn", binary_path]
        output = subprocess.check_output(cmd, text=True, errors="ignore")
    except Exception as e:
        return [f"Error running objdump: {e}"]

    lines = output.splitlines()
    func_lines = []
    in_func = False
    
    start_pattern = re.compile(rf"^[0-9a-fA-F]+\s+<{re.escape(func_name)}>:")
    
    for line in lines:
        if start_pattern.search(line):
            in_func = True
            continue
        
        if in_func:
            if not line.strip(): 
                continue
            if re.match(r"^[0-9a-fA-F]+\s+<.*>:", line):
                break
                
            parts = line.split(":", 1)
            if len(parts) > 1:
                asm = parts[1].strip()
                asm = asm.split("#")[0].strip()
                if asm:
                    func_lines.append(asm)
                    
    return func_lines

def get_pipeline_output(binary_path, func_name):
    """
    Extracts normalized assembly from pipeline for comparison.
    Args:
        :param binary_path: Path to binary file.
        :param func_name: Function name.
        :return: List of normalized instruction strings.
    """
    try:
        raw_input = _generate_input_from_binary(binary_path, func_name, UseContext="false")
    except Exception as e:
        return [f"Pipeline Exception: {e}"]
    
    if not raw_input:
        return ["Pipeline returned None"]

    match = re.search(r"TARGET:func;(.*?)(\s+CALLERS:|\s+CALLEES:|$)", raw_input)
    if not match:
        return ["Could not parse TARGET section"]
    
    asm_block = match.group(1)
    instructions = [i.strip() for i in asm_block.split(";") if i.strip()]
    
    cleaned_instr = []
    for instr in instructions:
        cleaned_instr.append(instr)
        
    return cleaned_instr

def print_side_by_side(objdump_lines, pipeline_lines):
    """
    Displays objdump and pipeline outputs in parallel columns.
    Args:
        :param objdump_lines: List of objdump instructions.
        :param pipeline_lines: List of pipeline instructions.
        :return: None. Prints to console.
    """
    max_len = max(len(objdump_lines), len(pipeline_lines))
    
    print(f"{'OBJDUMP (Ground Truth)':<60} | {'PIPELINE (Normalized Input)':<60}")
    print("-" * 125)
    
    for i in range(max_len):
        left = objdump_lines[i] if i < len(objdump_lines) else ""
        right = pipeline_lines[i] if i < len(pipeline_lines) else ""
        
        print(f"{left:<60} | {right:<60}")

def parse_filename_info(filename):
    """
    Parses JSONL filename to extract binary path and function name.
    Args:
        :param filename: JSONL filename string.
        :return: Tuple of (binary_path, function_name, basename).
    """
    basename = os.path.basename(filename)
    
    match = re.search(r'^(.*)_(executable\d+)_(.*)_\d+\.jsonl$', basename)
    
    if not match:
        return None, None, None

    repo_name = match.group(1)
    executable_name = match.group(2)
    function_name = match.group(3)

    binary_path = os.path.join(COMPILED_ROOT, repo_name, executable_name)
    
    return binary_path, function_name, basename

def run_random_batch(count=10):
    """
    Tests random sample of JSONL files against objdump ground truth.
    Args:
        :param count: Number of samples to test.
        :return: None. Prints verification results.
    """
    print(f"Scanning {INPUT_DIR} for .jsonl files...")
    all_files = glob.glob(os.path.join(INPUT_DIR, "*.jsonl"))
    
    if not all_files:
        print(f"No .jsonl files found in {INPUT_DIR}")
        return

    num_samples = min(len(all_files), count)
    print(f"Selecting {num_samples} random samples from {len(all_files)} files...\n")
    
    samples = random.sample(all_files, num_samples)

    for i, filepath in enumerate(samples):
        print(f"\n{'='*40} SAMPLE {i+1}/{num_samples} {'='*40}")
        
        binary_path, func_name, filename = parse_filename_info(filepath)
        
        if not binary_path:
            print(f"WARNING: Could not parse filename: {filename}")
            continue
            
        print(f"File:   {filename}")
        print(f"Binary: {binary_path}")
        print(f"Func:   {func_name}")
        
        if not os.path.exists(binary_path):
            print(f"Binary not found at calculated path: {binary_path}")
            continue

        print("-" * 30)
        gt = get_objdump_output(binary_path, func_name)
        pl = get_pipeline_output(binary_path, func_name)
        
        print_side_by_side(gt, pl)
        
        diff = abs(len(gt) - len(pl))
        print("-" * 125)
        print(f"Lines: Objdump={len(gt)}, Pipeline={len(pl)} | Diff={diff}")
        
        if diff > 10 and len(gt) > 0:
             print("WARN: Significant length mismatch.")
        elif len(gt) == 0:
             print("WARN: Objdump found no code (Function name mismatch or stripping?)")
        else:
             print("OK: Structure looks consistent.")

def main():
    """
    Entry point for random batch verification or single manual test.
    Args:
        :return: None.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", type=int, default=10, help="Number of random samples to test")
    parser.add_argument("--binary", help="Optional: Test specific binary manually")
    parser.add_argument("--func", default="main", help="Function name for manual test")
    args = parser.parse_args()

    if args.binary:
        print(f"Verifying SINGLE: {args.binary} :: {args.func}\n")
        gt = get_objdump_output(args.binary, args.func)
        pl = get_pipeline_output(args.binary, args.func)
        print_side_by_side(gt, pl)
    else:
        run_random_batch(args.batch)

if __name__ == "__main__":
    main()