# Neural-Decompiler

**Context-Aware Decompilation from Binary to C.**

<p align="left">
    <a href="https://huggingface.co/google/long-t5-tglobal-base">
        <img alt="Model" src="https://img.shields.io/badge/Model-LongT5%20(250M)-blueviolet">
    </a>
    <a href="https://angr.io/">
        <img alt="Powered By" src="https://img.shields.io/badge/Analysis-Angr-red">
    </a>
</p>

This repository contains the implementation of my Bachelor Thesis: **"Neural Decompilation with Program-Wide and Homogenized Context"**.

Most neural decompilers treat binary functions in isolation: translating one block of assembly into C code without looking left or right. We take a different approach. By using **call graph analysis** via `angr`, we inject the *context* of neighboring functions (callers and callees) into the model input. A multi-signal scoring heuristic decides which neighbors are worth the token budget.

The result: a relatively small model (LongT5-Base, 250M parameters) that can produce more structurally valid code than models 50x its size.


## Key Features

- **Context-Aware Generation:** The model doesn't just see the target function. A scoring heuristic selects the most informative caller/callee functions and packs them into an 8192-token window alongside the target.
- **CFG-Based Lifting:** Instead of linear disassembly (`objdump`), we reconstruct the Control-Flow Graph with angr to correctly handle compiler optimizations, tail calls, and inter-function padding.
- **Strict Normalization:**
  - **Constant Pooling:** RIP-relative memory references and string literals from `.rodata` are replaced with typed placeholders (e.g., `STRx402010`, `FMTx401a3c`) so the model learns structure rather than memorizing constants.
  - **Entropy Reduction:** We strip pointer-size qualifiers (`DWORD PTR`, `QWORD PTR`) and other noise, saving roughly 15% of token space without losing semantics.


## Benchmarks

We evaluated on the **ExeBench** benchmark using the **DecEvalSE** framework (execution-based testing with KLEE).

Despite being a small model, our context-driven approach achieves state-of-the-art results in structural validity, beating much larger models.

| Model | Parameters | Pass@1 (Func. Correctness) | Structural Correctness (KLEE) |
| :--- | :---: | :---: | :---: |
| SK2Decompiler | ~13B | 79% | 30.6% |
| LLM4Decompile | 6.7B | 69% | - |
| Ghidra + Grok API | Large | 55% | 28.8% |
| **Ours (With Context)** | **0.25B** | **20%** | **37.1%** |
| Ours (No Context) | 0.25B | 11.4% | 29.6% |

Larger models are better at guessing logic (higher Pass@1), but our pipeline produces code that is more compilable and structurally faithful to the original binary.


## Pipeline Architecture

The pipeline is not a simple text-to-text translation. It consists of several stages:

1. **Binary Loading** — angr loads the ELF, builds a CFGFast, and caches the result.
2. **Assembly Extraction** — Capstone disassembles each basic block; `.rodata` references are collected into a constant pool.
3. **Context Selection** — The call graph is traversed up to N hops. Candidates are scored on struct fingerprint overlap, CFG similarity, name semantics, shared API calls, and graph distance, then greedily packed within the remaining token budget.
4. **Normalization** — RIP-relative operands become constant pool placeholders, call targets are resolved to symbolic names, jumps get sequential labels, trailing padding is stripped.
5. **Input Formatting** — Everything is serialized into a flat string: `HEADER:<includes> TARGET:func;<asm> CALLERS:FN{<asm>} CALLEES:FN{<asm>}`
6. **Label Generation** (training only) — DWARF debug info from `.o` files is used to extract the original C source, which is annotated with the same constant pool placeholders.


## Project Structure

```
Neural-Decompiler/
├── pipeline/                  # Core decompilation pipeline
│   ├── Config.py              # Global constants (8192 token budget, tokenizer, flags)
│   ├── ElfFeatures.py         # angr/Capstone: CFG, assembly, constant pool extraction
│   ├── AsmNormalizer.py       # Operand normalization, call resolution, input formatting
│   ├── AsmToInput.py          # Main entry point: binary + function → model input
│   ├── Heuristic.py           # Context scoring and budget-constrained selection
│   └── HintsAndLabels.py      # DWARF-based training label generation
│
├── integration/
│   └── PredictionAPI.py       # IPC server for the DecEvalSE C++ evaluation framework
│
├── scripts/
│   ├── data_gen/              # Data pipeline: GitHub scraping → compilation → linking → JSONL
│   ├── training/              # Training scripts (legacy + fixed version with DeepSpeed ZeRO-3)
│   ├── inference/             # Prediction, multi-checkpoint evaluation, pipeline verification
│   └── analysis/              # Complexity metrics and loss curve visualization
│
└── tests/
    └── test_pipeline.py       # Unit tests for normalizer and budget logic
```


## Quick Start

### Requirements

Python >= 3.10, a CUDA-capable GPU for training/inference.

```bash
git clone https://github.com/freddy913/Neural-Decompiler.git
cd Neural-Decompiler
pip install -r requirements.txt
```

### Generate Training Data

First, compile C sources to object files with DWARF debug info (`SH2O.py`), link them into executables (`ObjectToBinary.py`), then generate JSONL training pairs:

```bash
python scripts/data_gen/generate_training_data.py \
    --compiled-root ./COMPILED \
    --workers 8
```

### Train the Model

Training uses Accelerate + DeepSpeed ZeRO-3 with bf16 mixed precision. The number of epochs and steps-per-epoch are configured inside the script (defaults: 40 epochs, 10417 steps/epoch).

```bash
accelerate launch scripts/training/fixed_training/train_final.py
```

Note: around epoch 27 we discovered that the base T5 tokenizer was missing tokens for C-specific syntax. The `weight_surgery.py` script repairs that checkpoint by rebuilding the tokenizer with the special tokens and re-tying the embeddings. If you're training from scratch with `train_final.py` this is already handled at startup.

### Inference

To decompile all functions from test binaries:

```bash
python scripts/inference/predict_single_function.py \
    --model-path ./checkpoints/final
```

Or use `AsmToInput.py` directly for a single function:

```bash
python pipeline/AsmToInput.py \
    --binary-path ./COMPILED/repo/executable0 \
    --function-name main \
    --mode test
```


## Challenges

Some lessons learned during this project:

- **The Semantic Gap:** A Levenshtein similarity of 0.60 looks decent on paper, but a single flipped operator (`&` vs `&&`) breaks execution. This is why our Pass@1 is lower than the structural scores.
- **Logic Errors:** The model sometimes hallucinates control flow on deeply nested loops (cyclomatic complexity > 20).
- **Decoding Strategy:** We settled on a repetition penalty of 1.2. Standard NLP values are too aggressive for C code, which naturally repeats keywords like `int`, `return`, `if`.


## Citation

If you use this code or findings in your research, please cite:

```bibtex
@thesis{Graewert2026NeuralDecompilation,
  author       = {Frederik Graewert},
  title        = {Neural Decompilation with Program-Wide and Homogenized Context},
  school       = {Ruprecht-Karls-Universit\"at Heidelberg},
  year         = {2026},
  month        = {February}
}
```

## Acknowledgments

Thanks to **Prof. Dr. Artur Andrzejak** for the supervision and **Burhan Akin Yilmaz** for the mentorship and initial data generation framework. Computing resources were provided by **bwHPC** (bwUniCluster).