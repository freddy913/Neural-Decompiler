import subprocess
import shutil

def build_addr2line_resolver(binary_path):
    addr2line_path = shutil.which("addr2line")
    if not addr2line_path:
        print("[WARN] 'addr2line' executable not found in PATH. Source locations will be unavailable.")
        return lambda *_args, **_kwargs: None

    def resolve(addr_int):
        # addr_int: 0x401234
        try:
            out = subprocess.check_output(
                [addr2line_path, "-e", binary_path, hex(int(addr_int))],
                text=True,
                errors="ignore"
            ).strip()
            # possible output : "src/foo.c:137"
            return out
        except Exception:
            return None
    return resolve
