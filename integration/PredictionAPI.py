#!/usr/bin/env python3

"""
DO NOT EXECUTE THIS SCRIPT YOURSELF.
Please implement the parts where it says "IMPLEMENT THIS PART".

This script is intended to be run by the C++ application llvm_tdeval.

0. The DecEvalSE framework will launch this script in order to get model inferences through IPC (Inter Process Communication).
1. The DecEvalSE framework provides the path to a binary with a function name in question and communicates it to this script
2. The script will load the model in advance trough the main function and will listen to delimited requests
3. On inference request the script makes an inference with the AI model, retrieve the prediction and communicate
the answer back to DecEvalSE via IPC.
4. The protocol finishes

Title: Simple IPC Protocol (DecEvalSE ↔ PredictionAPI.py ↔ Model)

Columns
-------
DecEvalSE                PredictionAPI.py                         Model
( C++ framework )        ( Python IPC server )                    ( inference )

Legend:  --> message/action     <END> frame delimiter

Flow (multi-round)
------------------

DecEvalSE                PredictionAPI.py                         Model
|                        |                                        |
| spawn PredictionAPI.py |                                        |
|----------------------->| main(): load tokenizer + model         |
|                        |--------------------------------------->|
|                        |                 initialize()           |
|                        |<---------------------------------------|
|                        | enter IPC listen loop                  |
|                        |                                        |
| load                   |                                        |
|----------------------->| write "ready"                          |
|<-----------------------|                                        |
|                        |                                        |
| request                |                                        |
|----------------------->| read until <END>                       |
| "<bin_path> <func_name>"                                        |
|----------------------->|                                        |
| <END>                  |                                        |
|----------------------->| build prompt / inputs                  |
|                        |--------------------------------------->|
|                        |                infer(prompt)           |
|                        |<---------------------------------------|
|                        | get prediction                         |
|<-----------------------| write "<prediction...>\n"              |
|<-----------------------| write "<END>\n"                        |
|                        | loop (next request)                    |
|                        |                                        |
| request                |                                        |
|----------------------->| ... repeat N rounds ...                |
|                        |                                        |
| terminate              |                                        |
|----------------------->| write "terminating" and exit           |
|<-----------------------|                                        |




Developed by Burhan Akin Yilmaz.
"""
import sys
import os
import time
import subprocess
import argparse
import json
import tempfile
import gc

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, LongT5ForConditionalGeneration, AutoModelForSeq2SeqLM

# Custom imports
from AsmToInput import build_sample

# FIFO (named pipes) paths
pipe_c2p = './tmp/cpp_to_py_fifo'
pipe_p2c = './tmp/py_to_cpp_fifo'



os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Global vars for custom model
MODEL = None
TOKENIZER = None
MODEL_CHECKPOINT_PATH = "freddy913/FRDYV2_35"
MAX_SOURCE_LENGTH = 8192
MAX_NEW_TOKENS = 1024

def reconstruct_literals(c_code_with_placeholders, constant_pool):
    """
    Replaces placeholders in generated C code with original string literals.
    Args:
        :param c_code_with_placeholders: C code containing placeholder tokens like STRx, FMTx, CMDx.
        :param constant_pool: Dictionary mapping placeholders to original text.
        :return: Reconstructed C code with literals restored as a string.
    """
    if not c_code_with_placeholders or not constant_pool:
        return c_code_with_placeholders
        
    sorted_items = sorted(
        constant_pool.values(), 
        key=lambda x: len(x.get("placeholder", "")), 
        reverse=True
    )
    
    reconstructed_code = c_code_with_placeholders
    for item in sorted_items:
        placeholder = item.get("placeholder")
        original_text = item.get("text")
        
        if placeholder and original_text and placeholder.startswith(("STR", "FMT", "CMD")):
            c_string_literal = json.dumps(original_text)
            
            reconstructed_code = reconstructed_code.replace(placeholder, c_string_literal)
            
    return reconstructed_code

def predict(functionName, programPath):
    """
    Makes prediction for a given function in a binary using the loaded model.
    Args:
        :param functionName: Name of the target function to decompile.
        :param programPath: Absolute path to the binary file.
        :return: Decompiled C code as a string or error message.
    """
    global MODEL, TOKENIZER

    if MODEL is None or TOKENIZER is None:
        return "Error: Model not loaded."

    try:
        sample = build_sample(
            binary_path=programPath, 
            function_name=functionName, 
            mode="test", 
            UseContext="true"
        )

        if sample is None or "model_input" not in sample:
            return f"Error: Pipeline failed to generate input for {functionName} in {programPath}"

        input_text = sample["model_input"]
        constant_pool = sample.get("constant_pool")

        #inputs = TOKENIZER(input_text, return_tensors="pt").to(MODEL.device)
        inputs = TOKENIZER(input_text, return_tensors="pt", truncation=True, max_length=MAX_SOURCE_LENGTH).to(MODEL.device)
        with torch.no_grad():
            outputs = MODEL.generate(
                **inputs, 
                max_new_tokens=MAX_NEW_TOKENS,
                num_beams=5, 
                no_repeat_ngram_size=5,
                repetition_penalty=1.2, 
                length_penalty=1.0, 
                early_stopping=True
            )

        c_code_with_placeholders = TOKENIZER.decode(outputs[0], skip_special_tokens=True)
        final_c_code = reconstruct_literals(c_code_with_placeholders, constant_pool)
        return final_c_code

    except Exception as e:
        return f"// Python Exception during prediction: {str(e)}"



def main():
    """
    Main entry point for the IPC prediction server.
    Args:
        :return: None. Runs an infinite loop for IPC communication until termination.
    """
    print("This script is not intended to be run by the user manually.")

    # ------------------------------------------------------------------------
    # 1) Load your necessary model here. IMPLEMENT THIS PART.
    # ------------------------------------------------------------------------
    global MODEL, TOKENIZER

    try:
        TOKENIZER = AutoTokenizer.from_pretrained(MODEL_CHECKPOINT_PATH)

        # model = LongT5ForConditionalGeneration.from_pretrained(BASE_MODEL_NAME)
        # model.resize_token_embeddings(len(TOKENIZER))
        # model = load_state_dict_from_zero_checkpoint(model, MODEL_CHECKPOINT_PATH)
        # model.to(device)
        # model.eval()
        # MODEL = model
        MODEL = LongT5ForConditionalGeneration.from_pretrained(MODEL_CHECKPOINT_PATH)

        # weight tying anwenden (fix für missing keys)
        MODEL.tie_weights()
        MODEL.encoder.embed_tokens = MODEL.shared
        MODEL.decoder.embed_tokens = MODEL.shared
        if torch.cuda.is_available():
            print("Moving model to GPU...")
            MODEL = MODEL.cuda()
        else:
            print("Warning: CUDA not available, using CPU.")
        
        MODEL.eval()
        print("Model loaded successfully.")
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        sys.exit(1)
    # ------------------------------------------------------------------------
    # 2) Listen to requests from the C++ side (via named pipes). DO NOT CHANGE THIS PART.
    # ------------------------------------------------------------------------
    delimiter = "<END>"
    message_buffer = []

    # Open the FIFOs
    with open(pipe_c2p, 'r') as cpp_to_py, open(pipe_p2c, 'w') as py_to_cpp:
        while True:
            # Read message from C++
            current_message = cpp_to_py.readline().strip()
            # If there's an EOF or an empty string, you may want to keep reading or break
            if not current_message:
                time.sleep(0.1)
                continue

            message_buffer.append(current_message)
            print(message_buffer)

            # "terminate" -> we send back "terminating" and break
            if message_buffer[0] == "terminate":
                message_buffer = []
                py_to_cpp.write("terminating\n")
                py_to_cpp.flush()
                torch.cuda.empty_cache()
                sys.exit()
                break

            # "load" -> we respond with "ready"
            elif message_buffer[0] == "load":
                message_buffer = []
                py_to_cpp.write("ready\n")
                py_to_cpp.flush()

            # "request" + data + <END> -> do inference, respond with result
            elif message_buffer[0] == "request" and current_message == delimiter:
                # The lines between "request" and "<END>" are the assembly
                # Example buffer: ["request", "<disassembly-line1>", "<disassembly-line2>", ..., "<END>"]
                # We combine them
                assembly_code = "".join(message_buffer[1:-1])

                functionName = assembly_code.split(" ")[0]  # Extract the function name
                programPath = assembly_code.split(" ")[1] # Extract the program path

                print(functionName, " ",programPath)
              

                # Send prediction followed by <END>
                py_to_cpp.write(predict(functionName, programPath) + "\n" + delimiter + "\n")
                py_to_cpp.flush()

                # Reset the buffer
                message_buffer = []

            # Sleep a bit to avoid busy-wait
            time.sleep(0.3)


if __name__ == '__main__':
    main()