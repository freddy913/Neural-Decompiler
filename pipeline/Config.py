"""
This file holds all the knobs and constants that the rest of the pipeline reads.
The most important one is CONTEXT_THRESHOLD_TOKENS = 8192, which caps how many
tokens a single model input may contain (target + context + header combined).
We load the LongT5 tokenizer here once so every other module can just import it
instead of re-instantiating. JUNK_FUNCTIONS and RUNTIME_ENTRY_FUNCTIONS list
libc / CRT symbols that should never be treated as user-written code.
DEGREE controls how many hops in the call graph we consider for context.
Set WRITE_DEBUG_FILES = True to dump human-readable artifacts into DEBUG/.
"""
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
