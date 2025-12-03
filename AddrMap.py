import subprocess
import shutil
from Config import WRITE_DEBUG_FILES

def build_addr2line_resolver(binary_path):
    addr2line_path = shutil.which("addr2line")
    if not addr2line_path:
        if WRITE_DEBUG_FILES: print("[WARN] 'addr2line' executable not found in PATH. Source locations will be unavailable.")
        return lambda *_args, **_kwargs: None

    cache = {}

    def resolve(addr_int):
        # addr_int: 0x401234
        try:
            key = int(addr_int)
        except Exception:
            return None
        
        if key in cache:
            return cache[key]
        
        try:
            out = subprocess.check_output(
                [addr2line_path, "-e", binary_path, hex(int(addr_int))],
                text=True,
                errors="ignore"
            ).strip()
            # possible output : "src/foo.c:137"
        except Exception:
            out = None

        cache[key] = out
        return out
    
    return resolve
