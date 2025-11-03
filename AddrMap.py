import subprocess

def build_addr2line_resolver(binary_path):
    def resolve(addr_int):
        # addr_int: 0x401234
        try:
            out = subprocess.check_output(
                ["addr2line", "-e", binary_path, hex(addr_int)],
                text=True,
                errors="ignore"
            ).strip()
            # possible output : "src/foo.c:137"
            return out
        except Exception:
            return None
    return resolve
