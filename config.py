import logging
from transformers import AutoTokenizer

# Logging configuration to be less verbose
logging.getLogger('cle').setLevel('ERROR')
logging.getLogger('pyvex').setLevel('ERROR')
# Set angr's main logger to WARNING to see important messages but not debug info
logging.getLogger('angr').setLevel('WARNING')

# Global configs
TARGET_BINARY_PATH = "/home/freddy/dev/neural-decompiler/Neural-Decompiler/COMPILED/2dango_Custom-UDP-packet/executable0"
TARGET_FUNCTION_NAME = "UdpPacketSend"
CONTEXT_THRESHOLD_TOKENS = 7000 # TODO: substract puffer for label tokens later in post processing
MYTOKENIZER = AutoTokenizer.from_pretrained("EleutherAI/gpt-neo-1.3B") # TODO: dummy,.. replace with actual tokenizer
JUNK_FUNCTIONS = {"printf", "malloc", "free", "scanf", "puts", "gets", "exit"}
BASIC_SCORE = 100
