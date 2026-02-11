"""
Decompiles functions from binaries using single model from Hugging Face.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import logging
import torch
import json
from tqdm import tqdm
from transformers import AutoTokenizer, LongT5ForConditionalGeneration

logging.getLogger('angr').setLevel('ERROR')
logging.getLogger('cle').setLevel('ERROR')

try:
    from pipeline.AsmToInput import build_sample, load_project
    from pipeline.Heuristic import is_relevant_user_like_function
except ImportError:
    print("Error: No pipeline scripts found.")
    exit(1)

MODEL_ID = "freddy913/FRDYV2_35"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(BASE_DIR, "COMPILED/TESTER")
OUTPUT_ROOT = os.path.join(BASE_DIR, "A_DECOMPILED_OUTPUT_V3_31")

# L4 GPU optimization
torch.backends.cuda.matmul.allow_tf32 = True
torch.backends.cudnn.allow_tf32 = True

def reconstruct_literals(c_code_with_placeholders, constant_pool):
    """
    Replaces placeholder tokens with original string literals.
    Args:
        :param c_code_with_placeholders: Generated C code with placeholders.
        :param constant_pool: Dictionary mapping placeholders to strings.
        :return: Reconstructed C code string.
    """
    if not c_code_with_placeholders or not constant_pool:
        return c_code_with_placeholders
    sorted_items = sorted(constant_pool.values(), key=lambda x: len(x.get("placeholder", "")), reverse=True)
    final_code = c_code_with_placeholders
    for item in sorted_items:
        ph = item.get("placeholder")
        txt = item.get("text")
        if ph and txt and ph in final_code:
            # json.dumps sorgt für korrektes C-Escaping
            final_code = final_code.replace(ph, json.dumps(txt))
    return final_code

def main():
    """
    Decompiles all functions in test binaries using loaded model.
    Args:
        :return: None. Saves outputs to OUTPUT_ROOT directory.
    """
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"=== Neural Decompiler Bulk Inference (HF-Model) ===")

    print(f"Loading model and tokenizer: {MODEL_ID}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    
    model = LongT5ForConditionalGeneration.from_pretrained(
        MODEL_ID, 
        torch_dtype=torch.bfloat16 if device == "cuda" else torch.float32,
        low_cpu_mem_usage=True
    ).to(device)

    model.tie_weights()
    model.encoder.embed_tokens = model.shared
    model.decoder.embed_tokens = model.shared
    model.eval()

    if model.encoder.embed_tokens.weight is model.shared.weight:
        print("Model weight tying is active.")

    binaries = []
    if not os.path.exists(SOURCE_DIR):
        print(f"ERROR: {SOURCE_DIR} not found.")
        return

    for root, _, files in os.walk(SOURCE_DIR):
        for f in files:
            if f.startswith("executable") or f.endswith(".o"):
                binaries.append(os.path.join(root, f))

    print(f"Found files: {len(binaries)}")

    for bin_path in binaries:
        rel_path = os.path.relpath(bin_path, SOURCE_DIR)
        file_out_dir = os.path.join(OUTPUT_ROOT, rel_path)
        os.makedirs(file_out_dir, exist_ok=True)

        print(f"\nAnalyzing: {rel_path}")
        proj, cfg = load_project(bin_path)
        if not proj or not cfg:
            continue

        target_functions = [f for f in cfg.functions.values() if is_relevant_user_like_function(f) and not f.is_plt]
        
        if not target_functions:
            target_functions = [f for f in cfg.functions.values() if not f.is_plt and not f.name.startswith("_")]

        print(f"   -> Decompiling {len(target_functions)} functions...")

        for func in tqdm(target_functions, desc="Progress", leave=False):
            try:
                sample = build_sample(bin_path, func.name, mode="test", UseContext="true")
                if not sample: continue

                inputs = tokenizer(
                    sample["model_input"], 
                    return_tensors="pt", 
                    max_length=8192, 
                    truncation=True
                ).to(device)

                with torch.no_grad():
                    outputs = model.generate(
                        **inputs, 
                        max_new_tokens=1024, 
                        num_beams=5,
                        no_repeat_ngram_size=5,
                        repetition_penalty=1.2, 
                        length_penalty=1.0, 
                        early_stopping=True
                    )
                    
                pred_text = tokenizer.decode(outputs[0], skip_special_tokens=False)
                pred_text = pred_text.replace("<pad>", "").replace("</s>", "").strip()

                final_c_code = reconstruct_literals(pred_text, sample.get("constant_pool"))

                out_name = f"{func.name}.c".replace("/", "_")
                with open(os.path.join(file_out_dir, out_name), "w", encoding="utf-8") as f:
                    f.write(f"// Decompiled from: {rel_path}\n")
                    f.write(f"// Function: {func.name}\n\n")
                    f.write(final_c_code)
                    
            except Exception as e:
                continue

    print(f"\nDONE! Results saved to: {OUTPUT_ROOT}")

if __name__ == "__main__":
    main()