"""
Everything that touches the actual ELF binary lives here:
load_project() opens a binary with angr, builds a CFGFast, and caches both
so repeated calls for the same file are instant. get_function_assembly()
walks the basic blocks through Capstone and returns raw disassembly lines.
The second half of the file deals with the constant pool: we scan every
instruction for RIP-relative and immediate operands that point into .rodata,
read the zero-terminated bytes at that address, and classify them as
STR (plain string), FMT (printf-style format), CMD (shell command), or DAT
(non-printable blob). Each entry gets a placeholder like STRx4019e7 that
the normalizer and label generator will substitute into the model input.
"""
import os
import re
import string

import angr
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from typing import Optional, Tuple, Dict
from Config import MYTOKENIZER

STREAM_STDERR = "STREAM_STDERR"
STREAM_STDOUT = "STREAM_STDOUT"

_LABEL_DEBUG = os.environ.get("LABEL_DEBUG") == "1"

_PLT_SUFFIX_RE = re.compile(r'@plt$', re.IGNORECASE)
_LIBC_ALIAS_MAP_RAW = {
    "__printf_chk": "printf",
    "__fprintf_chk": "fprintf",
    "__sprintf_chk": "sprintf",
    "__snprintf_chk": "snprintf",
    "__puts_chk": "puts",
    "__putchar_chk": "putchar",
    "__fwrite_chk": "fwrite",
    "__fputs_chk": "fputs",
    "__libc_system": "system",
    "__libc_write": "write",
    "__libc_send": "send",
    "__libc_recv": "recv",
    "__libc_exit": "exit",
    "__libc_fwrite": "fwrite",
    "__libc_fputs": "fputs",
    "__libc_fprintf": "fprintf",
    "__libc_printf": "printf",
    "__libc_puts": "puts",
    "__libc_perror": "perror",
    "__libc_putc": "putchar",
    "__libc_putchar": "putchar",
    "__libc_exit_group": "exit",
    "_exit": "exit",
    "exit": "exit",
}
_LIBC_ALIAS_MAP = {k.lower(): v for k, v in _LIBC_ALIAS_MAP_RAW.items()}


def _normalize_symbol_generic(sym: str | None) -> str:
    """
    Normalizes library symbol names by removing version suffixes and aliases.
    Args:
        :param sym: Symbol name string or None.
        :return: Normalized symbol name as string.
    """
    if not sym:
        return ""
    base = sym.strip()
    base = base.split('@@', 1)[0]
    base = _PLT_SUFFIX_RE.sub("", base)
    if '@' in base:
        base = base.split('@', 1)[0]
    base = base.strip()
    if not base:
        return ""
    key = base.lower()
    return _LIBC_ALIAS_MAP.get(key, key)

_PROJECT_CACHE: dict[str, tuple[Optional[angr.Project], object]] = {}

def load_project(binary_path):
    """
    Loads an angr project and CFG with caching for performance.
    Args:
        :param binary_path: Absolute path to binary file.
        :return: Tuple of (project, cfg) or (None, None) on failure.
    """

    abs_path = os.path.abspath(binary_path)
    cached = _PROJECT_CACHE.get(abs_path)
    if cached is not None:
        return cached
    
    try:
        project = angr.Project(abs_path, auto_load_libs=False)
    except Exception as e:
        print(f"Failed to load project: {e}")
        _PROJECT_CACHE[abs_path] = (None, None)
        return (None, None)
    
    try:
        # cfg = project.analyses.CFGEmulated(
        #     normalize=True,
        #     context_sensitivity_level=2,  # Higher sensitivity improves call-site resolution.
        #     resolve_indirect_jumps=True
        # )
        cfg = project.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            data_references=True 
        )
    except Exception as e:
        print(f"Failed to generate CFG: {e}")
        return None
    
    _PROJECT_CACHE[abs_path] = (project, cfg)
    return project, cfg

def get_function_assembly(func):
    """
    Extracts assembly code from an angr function object.
    Args:
        :param func: Angr function object.
        :return: Multi-line assembly string.
    """
    if func is None:
        return ""

    lines = []

    sorted_blocks = sorted(list(func.blocks), key=lambda b: b.addr)

    for block in sorted_blocks:
        try:
            capstone_block = block.capstone
        except Exception:
            continue  # Skip blocks we cannot lift.

        lines.append(f"Block @ {hex(block.addr)}")
        insns = getattr(capstone_block, "insns", [])
        if insns:
            for insn in insns:
                row = f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}"
                lines.append(row.strip())
        else:
            lines.append(f"; Empty Block @ {hex(block.addr)}")

    return "\n".join(lines)

def get_token_count(assembly_code, tokenizer=MYTOKENIZER):
    """
    Tokenizes assembly code and returns token count.
    Args:
        :param assembly_code: Assembly code string.
        :param tokenizer: Huggingface tokenizer instance.
        :return: Integer token count.
    """
    try:
        token_ids = tokenizer(assembly_code, add_special_tokens=False).input_ids
    except Exception as e:
        return 0
    
    return len(token_ids)

def get_function_data(func, project, tokenizer):
    """
    Builds compact dictionary with function metadata including token count.
    Args:
        :param func: Angr function object.
        :param project: Angr project object.
        :param tokenizer: Huggingface tokenizer instance.
        :return: Dictionary with name, assembly, and token_count keys.
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


# Constant pool extraction.
def _is_printable_ascii(buf_bytes):
    """
    Heuristic to determine if byte buffer is printable ASCII text.
    Args:
        :param buf_bytes: Byte buffer.
        :return: True if >=70% bytes are printable as boolean.
    """
    printable = set(bytes(string.printable, "ascii"))
    score = sum((b in printable and b not in b"\x0b\x0c") for b in buf_bytes)
    return (len(buf_bytes) > 0) and (score / len(buf_bytes) >= 0.7)


_FORMAT_SPECIFIER_RE = re.compile(
    r'%(?:[-+ #0]*\d*(?:\.\d+)?[hlLzjt]*[diufFeEgGxXoscpaAn%])'
)

def _classify_blob(text_str):
    """
    Classifies string literal as CMD, FMT, or STR based on content heuristics.
    Args:
        :param text_str: Text string to classify.
        :return: Classification string: CMD, FMT, or STR.
    """
    lowered = text_str.lower()

    shell_keywords = [
        "iptables", "chmod", "chown", "wget", "curl", "rm ",
        "ifconfig", ";", "&&", "||"
    ]
    if any(kw in lowered for kw in shell_keywords):
        return "CMD"

    if _FORMAT_SPECIFIER_RE.search(text_str):
        return "FMT"

    return "STR"

def make_placeholder(kind_prefix, addr_int):
    """
    Builds placeholder token from kind and address.
    Args:
        :param kind_prefix: Prefix string like STR, CMD, FMT, or DAT.
        :param addr_int: Integer address.
        :return: Placeholder string like STRx4019e7.
    """
    hexaddr = format(addr_int, "x")
    return f"{kind_prefix}x{hexaddr}"

def _stream_symbol_addrs(project) -> dict[str, int]:
    """
    Determines rebased addresses for stdout and stderr symbols.
    Args:
        :param project: Angr project object.
        :return: Dictionary mapping symbol names to addresses.
    """
    out: dict[str, int] = {}
    loader = getattr(project, "loader", None)
    if loader is None:
        return out

    for nm in ("stdout", "stderr"):
        sym = None
        # angr Loader provides find_symbol; fall back to main_object.get_symbol
        find_symbol = getattr(loader, "find_symbol", None)
        if callable(find_symbol):
            try:
                sym = find_symbol(nm)
            except Exception:
                sym = None
        if sym is None:
            try:
                sym = loader.main_object.get_symbol(nm)
            except Exception:
                sym = None
        if sym is None and hasattr(loader, "main_object"):
            # search manual symbol table if available
            try:
                for candidate in loader.main_object.symbols:
                    if getattr(candidate, "name", "") == nm:
                        sym = candidate
                        break
            except Exception:
                sym = None
        if sym is not None:
            try:
                out[nm] = sym.rebased_addr
            except AttributeError:
                # fall back to resolved address if provided
                addr = getattr(sym, "resolved_addr", None)
                if isinstance(addr, int):
                    out[nm] = addr
    return out

def _function_symbol_addrs(project) -> dict[int, str]:
    """
    Builds mapping from GOT and PLT addresses to imported function names.
    Args:
        :param project: Angr project object.
        :return: Dictionary mapping addresses to symbol names.
    """
    out: dict[int, str] = {}
    loader = getattr(project, "loader", None)
    if loader is None:
        return out

    main_obj = getattr(loader, "main_object", None)
    if main_obj is None:
        return out

    def _record(addr: int | None, name: str | None):
        if not isinstance(addr, int) or addr <= 0 or not name:
            return
        base = _normalize_symbol_generic(name)
        if not base:
            return
        symbol = f"{base}@plt"
        out.setdefault(addr, symbol)

    try:
        imports = getattr(main_obj, "imports", {}) or {}
        for name, sym in imports.items():
            addr = getattr(sym, "rebased_addr", None)
            _record(addr, name)
    except Exception:
        pass

    try:
        plt = getattr(main_obj, "plt", {}) or {}
        for name, addr in plt.items():
            _record(addr, name)
    except Exception:
        pass

    try:
        rev = getattr(main_obj, "reverse_plt", {}) or {}
        for addr, name in rev.items():
            _record(addr, name)
    except Exception:
        pass

    return out

def read_zero_terminated(project, start_addr, maxlen=4096):
    """
    Reads zero-terminated byte sequence from binary memory at address.
    Args:
        :param project: Angr project object.
        :param start_addr: Starting address to read from.
        :param maxlen: Maximum bytes to read.
        :return: Bytes object terminated at null byte.
    """
    out = bytearray()
    for i in range(maxlen):
        try:
            chunk = project.loader.memory.load(start_addr + i, 1)
        except Exception:
            break
        if not chunk or len(chunk) == 0:
            break
        b = chunk[0]
        if b == 0:
            break
        out.append(b)
    return bytes(out)

def _get_capstone_insn(insn):
    """
    Extracts real Capstone instruction object from angr wrapper layers.
    Args:
        :param insn: Angr instruction wrapper or Capstone instruction.
        :return: Capstone CsInsn object or None.
    """
    if hasattr(insn, "operands") and hasattr(insn, "address") and hasattr(insn, "size"):
        return insn

    # case 2: wrapper.insn
    cand = getattr(insn, "insn", None)
    if cand is not None and hasattr(cand, "operands"):
        return cand

    # case 3: wrapper.capstone or wrapper.capstone.insn
    cap_attr = getattr(insn, "capstone", None)
    if cap_attr is not None:
        if hasattr(cap_attr, "operands") and hasattr(cap_attr, "address"):
            return cap_attr
        deep = getattr(cap_attr, "insn", None)
        if deep is not None and hasattr(deep, "operands"):
            return deep

    return None

def try_extract_rodata_addr_from_insn(insn):
    """
    Extracts constant address referenced by instruction operands.
    Args:
        :param insn: Angr instruction object.
        :return: Dictionary with address and rip_disp or None.
    """
    cs_insn = _get_capstone_insn(insn)
    if cs_insn is None:
        return None
    insn_addr = getattr(insn, "address", None)
    insn_size = getattr(insn, "size", None)
    if insn_addr is None and hasattr(cs_insn, "address"):
        insn_addr = cs_insn.address
    if insn_size is None and hasattr(cs_insn, "size"):
        insn_size = cs_insn.size

    for op in cs_insn.operands:
        # IMM
        if op.type == X86_OP_IMM:
            imm_val = getattr(op, "imm", None)
            if isinstance(imm_val, int) and imm_val > 0x1000:
                return {
                    "address": imm_val,
                    "rip_disp": None,
                }

        # MEM
        if op.type == X86_OP_MEM:
            base_reg = op.mem.base
            disp     = op.mem.disp

            if base_reg == X86_REG_RIP and insn_addr is not None and insn_size is not None:
                abs_addr = insn_addr + insn_size + disp
                if abs_addr > 0x1000:
                    return {
                        "address": abs_addr,
                        "rip_disp": disp,
                    }

            if base_reg == 0 and disp and disp > 0x1000:
                return {
                    "address": disp,
                    "rip_disp": None,
                }

    return None

def collect_constant_pool_for_function(func_obj, project):
    """
    Iterates function instructions to extract rodata constant references with classification.
    Args:
        :param func_obj: Angr function object.
        :param project: Angr project object.
        :return: Dictionary mapping addresses to constant metadata.
    """
    streams = _stream_symbol_addrs(project)
    func_symbols = _function_symbol_addrs(project)
    seen: dict[int, dict] = {}
    for block in getattr(func_obj, "blocks", []):
        cap = getattr(block, "capstone", None)
        if cap is None:
            continue

        for insn in getattr(cap, "insns", []):
            ref = try_extract_rodata_addr_from_insn(insn)
            if ref is None:
                continue

            addr_int = ref["address"]
            entry = seen.setdefault(addr_int, {
                "rip_offsets": set(),
                "address_int": addr_int,
            })

            rip_disp = ref.get("rip_disp")
            if rip_disp is not None:
                entry.setdefault("rip_offsets", set()).add(rip_disp)

            if addr_int == streams.get("stdout"):
                entry.update({
                    "bytes": b"",
                    "text": "",
                    "kind": "STREAM",
                    "placeholder": STREAM_STDOUT,
                    "finalized": True,
                })
                continue

            if addr_int == streams.get("stderr"):
                entry.update({
                    "bytes": b"",
                    "text": "",
                    "kind": "STREAM",
                    "placeholder": STREAM_STDERR,
                    "finalized": True,
                })
                continue

            func_sym = func_symbols.get(addr_int)
            if func_sym:
                entry.update({
                    "bytes": b"",
                    "text": "",
                    "kind": "FUNC",
                    "placeholder": func_sym,
                    "finalized": True,
                })
                continue

            if entry.get("finalized"):
                continue

            raw = read_zero_terminated(project, addr_int, maxlen=4096)

            if not raw:
                entry.update({
                    "bytes": b"",
                    "text": "",
                    "kind": "DAT",
                    "placeholder": make_placeholder("DAT", addr_int),
                    "finalized": True,
                })
                continue

            try:
                txt = raw.decode("utf-8", "ignore")
            except Exception:
                txt = ""

            if not _is_printable_ascii(raw):
                entry.update({
                    "bytes": raw,
                    "text": txt,
                    "kind": "DAT",
                    "placeholder": make_placeholder("DAT", addr_int),
                    "finalized": True,
                })
                continue

            kind = _classify_blob(txt)
            entry.update({
                "bytes": raw,
                "text": txt,
                "kind": kind,
                "placeholder": make_placeholder(kind, addr_int),
                "finalized": True,
            })

    final_pool = {}
    for addr_int, info in seen.items():
        rip_offsets = info.get("rip_offsets", set())
        if isinstance(rip_offsets, set):
            rip_offsets = sorted(rip_offsets)
        kind = info.get("kind", "DAT")
        placeholder = info.get("placeholder", make_placeholder(kind, addr_int))
        final_pool[f"0x{addr_int:x}"] = {
            "bytes": info.get("bytes", b""),
            "text": info.get("text", ""),
            "kind": kind,
            "placeholder": placeholder,
            "rip_offsets": rip_offsets,
            "address_int": addr_int,
        }

    if _LABEL_DEBUG:
        print(f"\n[CONST_POOL_DEBUG] Function: {getattr(func_obj, 'name', hex(getattr(func_obj, 'addr', 0)))}")
        if not final_pool:
            print("  -> No constants detected.")
        else:
            for addr, info in final_pool.items():
                print(f"  {addr}  {info['kind']:4}  {repr(info['text'][:60])}  ->  {info['placeholder']}")

    return final_pool
