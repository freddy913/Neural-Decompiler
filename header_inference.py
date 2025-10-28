import subprocess
import shutil

HEADER_MAP = {
    "<stdio.h>": [
        "printf", "fprintf", "sprintf", "snprintf",
        "puts", "putchar", "perror",
        "scanf", "fscanf", "sscanf",
        "fgets", "fputs",
        "fopen", "fclose", "fread", "fwrite",
    ],
    "<stdlib.h>": [
        "malloc", "calloc", "realloc", "free",
        "exit", "abort",
        "atoi", "atof", "strtol", "strtoul",
        "qsort", "rand", "srand",
        "abs", "labs",
    ],
    "<string.h>": [
        "strcpy", "strncpy", "strcat", "strncat",
        "strcmp", "strncmp", "strlen", "strstr",
        "memcpy", "memmove", "memcmp", "memset",
        "strerror", "strtok", "strpbrk", "strrchr",
    ],
    "<math.h>": [
        "sin", "cos", "tan",
        "sqrt", "pow", "log",
        "exp", "log10", "ceil", "floor",
    ],
    "<unistd.h>": [
        "read", "write", "close",
        "sleep", "usleep",
        "fork", "execve",
        "pipe", "dup", "dup2",
        "getpid",
    ],
    "<pthread.h>": [
        "pthread_create", "pthread_join",
        "pthread_mutex_lock", "pthread_mutex_unlock",
        "pthread_cond_wait", "pthread_cond_signal",
        "pthread_rwlock_init", "pthread_rwlock_destroy",
        "pthread_rwlock_rdlock", "pthread_rwlock_wrlock",
    ],
    "<netinet/in.h>": [
        "socket", "bind", "listen", "accept",
        "inet_addr", "htons", "htonl", "ntohs", "ntohl",
    ],
    "<sys/types.h>": [
        "open", "close", "read", "write",
        "lseek", "stat", "fstat",
        "unlink", "rename",
    ],
    "<time.h>": [
        "clock", "time", "ctime",
        "difftime", "strftime", "localtime",
        "mktime", "gmtime", "asctime",
    ],
    "<fcntl.h>": [
        "open", "close", "read", "write",
        "fcntl", "ioctl", "pipe2", "dup2", "select",
    ],
}

def _strip_symbol_version(sym: str) -> str:
    """
    Removes ABI Version decorations from a symbol name as printf@@GLIBC_2.2.5 becomes printf
    """
    if '@@' in sym:
        return sym.split('@@')[0]
    elif '@' in sym:
        return sym.split('@')[0]
    return sym

def _readelf_symbols(binary_path: str) -> list[str]:
    """
    
    """
    if shutil.which("readelf") is None:
        return [] # readelf not available

    try:
        out = subprocess.check_output(
            ["readelf", "-s", binary_path],
            text=True,
            errors="ignore"
        )
    except Exception:
        return []
    
    # parsing similar to FSC: undefined symbols appear as GLOBAL DEFAULT  UND <name>
    symbols = []
    for line in out.splitlines():
        if "UND" not in line and "UND " not in line and "UNDEF" not in line:
            continue

        parts = line.strip().split()
        if not parts:
            continue

        cand = parts[-1] # often the last part is the symbol name

        # filter out common decorations
        if cand in ("UND", "UNDEF"):
            continue

        symbols.append(cand)

    return symbols

def extract_external_symbols(binary_path: str) -> set[str]:
    """
    Delivers a set of external, undefined symbol names without GLIBC version,
    e.g. { "printf", "socket", "htons" }.
    """
    raw_syms = _readelf_symbols(binary_path)
    clean = set()

    for sym in raw_syms:
        base = _strip_symbol_version(sym)

        # skip internal or compiler-generated symbols
        if base.startswith("__"):
            continue

        clean.add(base)

    return clean

def map_symbols_to_headers(symbols: set[str]) -> list[str]:
    """
    Uses HEADER_MAP to determine which #includes are necessary.
    Returns a sorted, unique list.
    """
    needed_headers = []
    for header, sym_list in HEADER_MAP.items():
        for s in symbols:
            if s in sym_list:
                needed_headers.append(header)
                break # header import once is enough

    # de-duplication while preserving order while dict.fromkeys() preserves insertion order in Python 3.7+
    needed_headers = list(dict.fromkeys(needed_headers))
    return needed_headers

def build_header_block_from_angr_subset(project, func_objs): # TODO
    # collect external symbols via angr, maps them to headers
    ...
    pass
def build_header_block_from_binary(binary_path: str) -> str:
    """
    Main-Entry:
    - collects external symbols via readelf
    - maps them to headers
    - builds a string block like:
        HEADERS:
        #include <stdio.h>
        #include <sys/socket.h>
        ...
    If no headers are found, returns an empty string.
    """
    symbols = extract_external_symbols(binary_path)
    headers = map_symbols_to_headers(symbols)

    if not headers:
        return ""

    lines = ["HEADERS:"]
    for h in headers:
        lines.append(f"#include {h}")

    return "\n".join(lines) + "\n"