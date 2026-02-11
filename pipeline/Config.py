import logging
from transformers import AutoTokenizer

logging.getLogger('cle').setLevel('ERROR')
logging.getLogger('pyvex').setLevel('ERROR')
logging.getLogger('angr').setLevel('WARNING')

TARGET_BINARY_PATH = "./Neural-Decompiler/COMPILED/repository/executable"
TARGET_FUNCTION_NAME = "function"

CONTEXT_THRESHOLD_TOKENS = 8192 
MYTOKENIZER = AutoTokenizer.from_pretrained("google/long-t5-tglobal-base") 
JUNK_FUNCTIONS = {"printf", "malloc", "free", "scanf", "puts", "gets", "exit", "socket", "sendto", "close", "setuid", "setsockopt",
    "strlen", "perror", "getpid", "inet_aton", "gethostbyname", "strtol"}
RUNTIME_ENTRY_FUNCTIONS = {
    "_start",
    "start",
    "__libc_start_main",
    "__libc_csu_init",
    "__libc_csu_fini",
}
BASIC_SCORE = 100
DEGREE = 4  # Default degree for context candidate selection
WRITE_DEBUG_FILES = True
VERBOSE = True
FUNCTION_TXT = "function.txt"
ASSEMBLY_TXT = "assembly.txt"
PAIR_JSON = "pair.json"

# Global switch: if True, build samples/context strictly from assembly (no C code approximations).
USE_ASSEMBLY_ONLY = True
