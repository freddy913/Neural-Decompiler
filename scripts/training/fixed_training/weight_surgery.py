"""
One-time repair script for checkpoint epoch 27 which was trained with the
broken tokenizer. Loads the base google/long-t5-tglobal-base model, rebuilds
the tokenizer with our special C tokens, resizes the embedding matrix to match,
copies over the trained weights that still have the right shape, and re-ties
encoder/decoder/lm_head embeddings. Output goes to LongT5_Clean_Start/.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

import torch
import shutil
from transformers import AutoTokenizer, LongT5ForConditionalGeneration, LongT5Config

BASE_MODEL = "google/long-t5-tglobal-base"
BAD_CHECKPOINT = "./LongT5Snapshot/consolidated_epoch27.bin/pytorch_model.bin"
OUTPUT_DIR = "./LongT5_Clean_Start"

# even if some (like #) are already present, HuggingFace will handle it correctly.
FINAL_SPECIAL_TOKENS = [
    "{", "}", "->", "\\", "#", 
    "<", ">", "<=", ">=", "==", "!=", 
    "&&", "||", "&", "|", "^", "~", "<<", ">>",
    "++", "--",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=",
    ";", ".", "[", "]"
]

def main():
    """
    Repairs checkpoint with missing embeddings through weight tying and token resize.
    Args:
        :return: None. Saves repaired model to OUTPUT_DIR.
    """
    print(f"--- MODEL FIXER & CLEANER (FINAL) ---")
    checkpoint_path = BAD_CHECKPOINT    
    if not os.path.exists(BAD_CHECKPOINT):
        print(f"ERROR: File not found: {BAD_CHECKPOINT}")
        alt_path = "./LongT5Snapshot/model_epoch27/fp32_from_zero/pytorch_model.bin"
        if os.path.exists(alt_path):
            print(f"Found file at: {alt_path}")
            checkpoint_path = alt_path
        else:
            return

    print("1. Creating final tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    num_added = tokenizer.add_tokens(FINAL_SPECIAL_TOKENS)
    print(f"Added {num_added} new tokens.")
    print(f"New vocabulary size: {len(tokenizer)}")

    print("2. Loading config...")
    config = LongT5Config.from_pretrained(BASE_MODEL)
    config.vocab_size = 32100 
    
    config.eos_token_id = tokenizer.eos_token_id
    config.pad_token_id = tokenizer.pad_token_id
    config.decoder_start_token_id = tokenizer.pad_token_id
    
    print("3. Initializing model (RAM)...")
    model = LongT5ForConditionalGeneration(config)
    
    print(f"4. Loading weights from {BAD_CHECKPOINT}...")
    state_dict = torch.load(checkpoint_path, map_location="cpu")
    
    missing, unexpected = model.load_state_dict(state_dict, strict=False)
    print(f"Missing keys before repair: {len(missing)}")

    print("5. Performing weight tying (fix for missing embeddings)...")
    model.tie_weights()
    
    print(f"6. Resizing embeddings to {len(tokenizer)}...")
    model.resize_token_embeddings(len(tokenizer))
    
    model.config.vocab_size = len(tokenizer)

    print(f"7. Saving clean checkpoint to {OUTPUT_DIR}...")
    if os.path.exists(OUTPUT_DIR): shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    
    print("\nDONE! Model has been repaired.")
    print(f"Use in training: MODEL_NAME = '{OUTPUT_DIR}'")

if __name__ == "__main__":
    main()
