"""
Loads a list of HuggingFace checkpoint directories (one per epoch),
runs each through every function in the test binaries, and appends
the predictions to a results file so we can compare epoch-by-epoch
which checkpoint produces the best decompilations.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import logging
import torch
import json
import gc
import re
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

MODELS_TO_EVAL = [
#    "freddy913/FRDYV4",
#    "freddy913/FRDYV3_31", 
#    "freddy913/FRDYV2_32",
#     "freddy913/FRDYV2_33",
#    "freddy913/FRDYV2_34",
    "freddy913/FRDYV2_35",
]

SOURCE_DIR = "./COMPILED/TESTER"
OUTPUT_ROOT = "./DECOMPILED_COMPARISON"

# L4 GPU Optimierung
torch.backends.cuda.matmul.allow_tf32 = True
torch.backends.cudnn.allow_tf32 = True

def get_epoch_label(model_id):
    """
    Extracts clean epoch label from model identifier.
    Args:
        :param model_id: Model identifier string.
        :return: Epoch label string like Epoch31.
    """
    # Sucht nach Zahlen am Ende, z.B. _31 oder V2 -> Epoch31 oder Epoch2
    match = re.search(r"(\d+)$", model_id)
    if match:
        return f"Epoch{match.group(1)}"
    return model_id.split("/")[-1]

def reconstruct_literals(c_code_with_placeholders, constant_pool):
    """
    Replaces placeholder tokens with original string literals in decompiled code.
    Args:
        :param c_code_with_placeholders: Generated C code with STRx tokens.
        :param constant_pool: Dictionary mapping placeholders to original strings.
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
            final_code = final_code.replace(ph, json.dumps(txt))
    return final_code

def main():
    """
    Iterates through model checkpoints and decompiles all test binaries.
    Args:
        :return: None. Writes decompiled outputs to OUTPUT_ROOT.
    """
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"=== Neural Decompiler Multi-Epoch Append Mode ===")

    binaries = []
    for root, _, files in os.walk(SOURCE_DIR):
        for f in files:
            if f.startswith("executable") or f.endswith(".o"):
                binaries.append(os.path.join(root, f))
    
    print(f"Found files: {len(binaries)}")

    for model_id in MODELS_TO_EVAL:
        epoch_label = get_epoch_label(model_id)
        print(f"\n\n>>> Loading {model_id} ({epoch_label})")
        
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        model = LongT5ForConditionalGeneration.from_pretrained(
            model_id, 
            torch_dtype=torch.bfloat16 if device == "cuda" else torch.float32,
            low_cpu_mem_usage=True
        ).to(device)

        # Weight Tying Fix
        model.tie_weights()
        model.encoder.embed_tokens = model.shared
        model.decoder.embed_tokens = model.shared
        model.eval()

        for bin_path in binaries:
            rel_path = os.path.relpath(bin_path, SOURCE_DIR)
            file_out_dir = os.path.join(OUTPUT_ROOT, os.path.dirname(rel_path))
            os.makedirs(file_out_dir, exist_ok=True)

            proj, cfg = load_project(bin_path)
            if not proj or not cfg: continue

            target_functions = [f for f in cfg.functions.values() if is_relevant_user_like_function(f)]

            for func in tqdm(target_functions, desc=f"[{epoch_label}] {os.path.basename(bin_path)}", leave=False):
                try:
                    sample = build_sample(bin_path, func.name, mode="test", UseContext="true")
                    if not sample: continue

                    inputs = tokenizer(sample["model_input"], return_tensors="pt", max_length=8192, truncation=True).to(device)
                    with torch.no_grad():
                        outputs = model.generate(
                            **inputs, 
                            max_new_tokens=1024, 
                            num_beams=5, 
                            repetition_penalty=1.2, 
                            no_repeat_ngram_size=5,
                            length_penalty=1.0,
                            early_stopping=True
                        )

                    pred_text = tokenizer.decode(outputs[0], skip_special_tokens=False)
                    pred_text = pred_text.replace("<pad>", "").replace("</s>", "").strip()
                    final_c_code = reconstruct_literals(pred_text, sample.get("constant_pool"))

                    out_file = os.path.join(file_out_dir, f"{os.path.basename(bin_path)}_{func.name}.c")
                    
                    file_exists = os.path.exists(out_file)
                    
                    with open(out_file, "a" if file_exists else "w", encoding="utf-8") as f:
                        if not file_exists:
                            f.write(f"// Decompiled by NeuralDecompiler Pipeline\n")
                            f.write(f"// Binary: {rel_path}\n")
                            f.write(f"// Function: {func.name}\n\n")
                            f.write("/* --- INPUT ASSEMBLY --------------------------------------------------\n")
                            f.write(sample["model_input"])
                            f.write("\n--------------------------------------------------------------------- */\n\n")
                        
                        f.write(f"{epoch_label}:\n")
                        f.write(f"{final_c_code}\n")
                        f.write("-" * 40 + "\n")
                        
                except Exception as e:
                    continue
        
        del model
        del tokenizer
        torch.cuda.empty_cache()
        gc.collect()

    print(f"\nDONE! Comparison files located in: {OUTPUT_ROOT}")

if __name__ == "__main__":
    main()
