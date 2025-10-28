import logging
from transformers import AutoTokenizer

# Logging configuration to be less verbose
logging.getLogger('cle').setLevel('ERROR')
logging.getLogger('pyvex').setLevel('ERROR')
# Set angr's main logger to WARNING to see important messages but not debug info
logging.getLogger('angr').setLevel('WARNING')

# Global configs
TARGET_BINARY_PATH = "/home/freddy/dev/neural-decompiler/Neural-Decompiler/COMPILED/2dango_Custom-UDP-packet/executable0"
TARGET_FUNCTION_NAME = "CheckSum"
CONTEXT_THRESHOLD_TOKENS = 2048 # TODO: substract puffer for label tokens later in post processing
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