"""
After training finishes we have a DeepSpeed ZeRO-3 checkpoint which consists of
sharded optimizer states and model partitions — not something you can upload
to the HuggingFace Hub directly. This script consolidates the shards into
a single pytorch_model.bin, copies the tokenizer config from the clean start
directory, and writes the model card so the result is a standard HF repo
that can be loaded with AutoModelForSeq2SeqLM.from_pretrained().
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

import re
import torch
import shutil
from transformers import AutoTokenizer, AutoConfig, LongT5ForConditionalGeneration

SNAPSHOT_DIR = "./LongT5Snapshot" 

TOKENIZER_CONFIG_SOURCE = "./LongT5_Clean_Start_Uni" 

OUTPUT_DIR = "A_NeuralDecomp_Upload_35"

def find_latest_epoch(path):
    """
    Finds highest epoch number in checkpoint directory.
    Args:
        :param path: Path to checkpoint directory.
        :return: Epoch number as integer or -1 if not found.
    """
    if not os.path.exists(path): return -1
    best = -1
    for name in os.listdir(path):
        m = re.match(r"model_epoch(\d+)$", name)
        if m:
            best = max(best, int(m.group(1)))
    return best

def find_weights_file_recursive(start_dir):
    """
    Recursively searches for largest .bin weights file in directory tree.
    Args:
        :param start_dir: Root directory to search.
        :return: Path to largest .bin file or None.
    """
    largest_file, largest_size = None, 0
    for root, _, files in os.walk(start_dir):
        for f in files:
            if f.endswith(".bin"):
                full_path = os.path.join(root, f)
                size = os.path.getsize(full_path)
                if size > largest_size:
                    largest_size, largest_file = size, full_path
    return largest_file

def main():
    """
    Converts DeepSpeed checkpoint to Hugging Face format for model upload.
    Args:
        :return: None. Saves bundle to OUTPUT_DIR.
    """
    print("=== Hugging Face Upload Bundle Creator ===")

    epoch = find_latest_epoch(SNAPSHOT_DIR)
    if epoch < 0:
        raise FileNotFoundError(f"No checkpoints found in {SNAPSHOT_DIR}")
    print(f"Using weights from epoch: {epoch}")

    ckpt_dir = os.path.join(SNAPSHOT_DIR, f"model_epoch{epoch}")
    
    print(f"[1] Loading correct tokenizer from '{TOKENIZER_CONFIG_SOURCE}'...")
    if not os.path.exists(TOKENIZER_CONFIG_SOURCE):
        raise FileNotFoundError(f"Clean Start folder '{TOKENIZER_CONFIG_SOURCE}' not found!")
        
    tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_CONFIG_SOURCE)
    config = AutoConfig.from_pretrained(TOKENIZER_CONFIG_SOURCE)

    out_dir = os.path.join(ckpt_dir, "fp32_from_zero")
    weights_path = find_weights_file_recursive(out_dir)
    
    if not weights_path:
        print("[2] Converting DeepSpeed checkpoint to FP32...")
        os.makedirs(out_dir, exist_ok=True)
        zero_script = os.path.join(ckpt_dir, "zero_to_fp32.py")
        target_path = os.path.join(out_dir, "pytorch_model.bin")
        
        cmd = f"python3 {zero_script} {ckpt_dir} {target_path}"
        os.system(cmd)
        
        weights_path = find_weights_file_recursive(out_dir)
    
    if not weights_path:
        raise RuntimeError("Conversion failed!")

    print(f"[3] Loading trained weights from: {weights_path}")
    state_dict = torch.load(weights_path, map_location="cpu")
    
    print("[4] Building final model...")
    config.vocab_size = state_dict['shared.weight'].shape[0]
    
    model = LongT5ForConditionalGeneration(config)
    model.load_state_dict(state_dict, strict=False)
    
    print("   -> Performing final weight-tying fix...")
    model.tie_weights()
    model.encoder.embed_tokens = model.shared
    model.decoder.embed_tokens = model.shared

    print(f"[5] Saving final bundle to '{OUTPUT_DIR}'...")
    if os.path.exists(OUTPUT_DIR): shutil.rmtree(OUTPUT_DIR)
    
    model.save_pretrained(OUTPUT_DIR, safe_serialization=True)
    tokenizer.save_pretrained(OUTPUT_DIR)

    print("\nDONE! Model is ready for upload.")

if __name__ == "__main__":
    main()
