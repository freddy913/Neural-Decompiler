import angr
from config import MYTOKENIZER

def load_project(binary_path):
    """
    takes a path to a binary and loads an angr project
    returns the loaded angr.project object and the cfg-object
    failures have to be handled as file not found or invalid binary
    """
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
    """
    takes a cfg-object
    returns a list of all function objects in the program
    """
    functions = set()
    for func in cfg.functions.values():
        functions.add(func)

    return list(functions)

def get_function_assembly(func):
    """
    takes an angr function object
    returns the assembly code of the function as a string
    """
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

def get_token_count(assembly_code, tokenizer=MYTOKENIZER):
    """
    tokenizes the assembly code and returns the token count
    """
    try:
        token_ids = tokenizer(assembly_code, add_special_tokens=False).input_ids
    except Exception as e:
        return 0
    
    return len(token_ids)

def get_function_data(func, project, tokenizer):
    """
    builds a compact dict with relevant data about the function
        { 'name': str, 'assembly': str, 'token_count': int }
    """
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