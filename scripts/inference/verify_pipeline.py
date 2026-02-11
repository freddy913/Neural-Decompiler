"""
Verifies pipeline output against objdump ground truth for single binary/function.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import subprocess
import re
import argparse
from pipeline.AsmToInput import _generate_input_from_binary

def get_objdump_output(binary_path, func_name):
    """
    Extracts ground truth assembly code using objdump.
    Args:
        :param binary_path: Path to binary file.
        :param func_name: Function name to disassemble.
        :return: List of assembly instruction strings.
    """
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
                # remove comments
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
    raw_input = _generate_input_from_binary(binary_path, func_name, UseContext="false")
    
    if not raw_input:
        return ["Pipeline returned None"]

    match = re.search(r"TARGET:func;(.*?)(\s+CALLERS:|\s+CALLEES:|$)", raw_input)
    if not match:
        return ["Could not parse TARGET section"]
    
    asm_block = match.group(1)
    instructions = [i.strip() for i in asm_block.split(";") if i.strip()]
    
    cleaned_instr = []
    for instr in instructions:
        if instr.startswith("@jmp"):
            parts = instr.split(" ", 1)
            if len(parts) > 1:
                pass

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
    
    print(f"{'OBJDUMP (Ground Truth)':<50} | {'PIPELINE (Normalized Input)':<50}")
    print("-" * 105)
    
    for i in range(max_len):
        left = objdump_lines[i] if i < len(objdump_lines) else ""
        right = pipeline_lines[i] if i < len(pipeline_lines) else ""
        
        print(f"{left:<50} | {right:<50}")

def main():
    """
    Compares pipeline output with objdump for validation.
    Args:
        :return: None. Prints comparison results.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--func", default="main")
    args = parser.parse_args()

    print(f"Verifying: {args.binary} :: {args.func}\n")

    print("Fetching Objdump...")
    gt = get_objdump_output(args.binary, args.func)
    
    print("Running Pipeline...")
    pl = get_pipeline_output(args.binary, args.func)

    print("\nComparison:\n")
    print_side_by_side(gt, pl)
    
    print("\n" + "-"*30)
    print(f"Objdump Lines: {len(gt)}")
    print(f"Pipeline Lines: {len(pl)}")
    
    if abs(len(gt) - len(pl)) > 5:
        print("\n[WARNING] Significant length difference! Angr may have missed code or included wrong blocks.")
    else:
        print("\n[OK] Lengths seem plausible.")

if __name__ == "__main__":
    main()