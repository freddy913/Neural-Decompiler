import logging
from transformers import AutoTokenizer

# Logging configuration to be less verbose
logging.getLogger('cle').setLevel('ERROR')
logging.getLogger('pyvex').setLevel('ERROR')
# Set angr's main logger to WARNING to see important messages but not debug info
logging.getLogger('angr').setLevel('WARNING')

# Global configs
TARGET_BINARY_PATH = "/home/freddy/dev/neural-decompiler/Neural-Decompiler/COMPILED/fenglyu_algorithm-c/executable0"
TARGET_FUNCTION_NAME = "list_init"
# TARGET_BINARY_PATH = "/home/freddy/dev/neural-decompiler/Neural-Decompiler/COMPILED/2dango_Custom-UDP-packet/executable0"
# TARGET_FUNCTION_NAME = "main"
# TARGET_BINARY_PATH = "/home/freddy/dev/neural-decompiler/Neural-Decompiler/COMPILED/00test_preproc/executable0"
# TARGET_FUNCTION_NAME = "main"

CONTEXT_THRESHOLD_TOKENS = 10000 # TODO: substract puffer for label tokens later in post processing
MYTOKENIZER = AutoTokenizer.from_pretrained("EleutherAI/gpt-neo-1.3B") # TODO: dummy,.. replace with actual tokenizer
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
DEGREE = 2  # Default degree for context candidate selection
WRITE_DEBUG_FILES = False
FUNCTION_TXT = "function.txt"
ASSEMBLY_TXT = "assembly.txt"
PAIR_JSON = "pair.json"

# Global switch: if True, build samples/context strictly from assembly (no C code approximations).
USE_ASSEMBLY_ONLY = True
