"""
Final fixed training script with tokenizer and weight-tying corrections.
This is the production-ready version after resolving embedding issues.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

import re
import warnings
from datetime import timedelta
import torch
from torch.utils.data import DataLoader
from tqdm import tqdm
import matplotlib.pyplot as plt
from accelerate import Accelerator, DeepSpeedPlugin
from accelerate.utils import InitProcessGroupKwargs
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    LongT5ForConditionalGeneration,
    LongT5Config,
    get_scheduler,
    DataCollatorForSeq2Seq,
)

MODEL_NAME = "./LongT5_Clean_Start_Uni" 
SNAPSHOT_DIR = "./LongT5Snapshot"

g_a_steps = 12
batch_size = 2
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
warnings.filterwarnings("ignore")

ds_plugin = DeepSpeedPlugin(
    zero_stage=3,
    offload_optimizer_device="cpu",
    offload_param_device="cpu",
    gradient_accumulation_steps=g_a_steps
)
kwargs = InitProcessGroupKwargs(backend="nccl", timeout=timedelta(minutes=60))

accelerator = Accelerator(
    kwargs_handlers=[kwargs],
    mixed_precision="bf16", # L4 GPU
    deepspeed_plugin=ds_plugin,
    gradient_accumulation_steps=g_a_steps
)

if accelerator.state.deepspeed_plugin is not None:
    accelerator.state.deepspeed_plugin.deepspeed_config['train_micro_batch_size_per_gpu'] = batch_size

def find_last_epoch(directory):
    """
    Finds highest epoch number in snapshot directory.
    Args:
        :param directory: Path to snapshot directory.
        :return: Epoch number as integer or None if not found.
    """
    if not os.path.exists(directory): return None
    last = 0
    for fn in os.listdir(directory):
        m = re.search(r"model_epoch(\d+)", fn)
        if m:
            e = int(m.group(1))
            if e > last: last = e
    return last if last > 0 else None

last_epoch = find_last_epoch(SNAPSHOT_DIR)
START_EPOCH = 27 

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

if last_epoch is not None and last_epoch > START_EPOCH:
    if accelerator.is_main_process: 
        print(f"RESUME: Detected epoch {last_epoch}. Loading DeepSpeed state...")
    model = LongT5ForConditionalGeneration.from_pretrained(MODEL_NAME)
else:
    if accelerator.is_main_process: 
        print(f"NEW START: Loading clean model for epoch {START_EPOCH}")
    model = LongT5ForConditionalGeneration.from_pretrained(MODEL_NAME)
    last_epoch = START_EPOCH

model.tie_weights()
model.encoder.embed_tokens = model.shared
model.decoder.embed_tokens = model.shared

model.gradient_checkpointing_enable()
model.config.use_cache = False

if accelerator.is_main_process:
    print(f"Vocab Size: {len(tokenizer)}")
    print(f"Model Embeddings: {model.get_input_embeddings().num_embeddings}")


max_source_length, max_target_length = 8192, 1024
train_raw = load_dataset("json", data_files={"train": "TrainingDataModel/*.jsonl"}, streaming=True)["train"]
eval_raw = load_dataset("json", data_files={"eval": "EvalDataModel_test/*.jsonl"}, streaming=True)["eval"]

def preprocess(example):
    src, tgt = str(example["input"]), str(example["output"])
    enc = tokenizer(src, max_length=max_source_length, truncation=True)
    lab = tokenizer(tgt, max_length=max_target_length, truncation=True)["input_ids"]
    return {"input_ids": enc["input_ids"], "attention_mask": enc["attention_mask"], "labels": lab}

train_tok = train_raw.map(preprocess, remove_columns=["input", "output"])
eval_tok = eval_raw.map(preprocess, remove_columns=["input", "output"])

collator = DataCollatorForSeq2Seq(tokenizer=tokenizer, model=model, padding="longest", pad_to_multiple_of=8, label_pad_token_id=-100)
eval_loader = DataLoader(eval_tok, batch_size=batch_size, shuffle=False, collate_fn=collator, num_workers=0)

learning_rate = 2e-5
from deepspeed.ops.adam import DeepSpeedCPUAdam
optimizer = DeepSpeedCPUAdam(model.parameters(), lr=learning_rate)
scheduler = get_scheduler("constant_with_warmup", optimizer=optimizer, num_warmup_steps=2000, num_training_steps=None)

model, optimizer, scheduler = accelerator.prepare(model, optimizer, scheduler)

if last_epoch > START_EPOCH:
    try: accelerator.load_state(f"{SNAPSHOT_DIR}/model_epoch{last_epoch}")
    except: pass

train_losses, eval_losses = [], []
if accelerator.is_main_process and os.path.exists("loss_data.txt"):
    try:
        with open("loss_data.txt") as f:
            for line in f:
                p = line.strip().split(",")
                if len(p)>=2: train_losses.append(float(p[0])); eval_losses.append(float(p[1]))
    except: pass

steps_per_epoch, num_epochs_total = 10417, 40

for epoch in range(last_epoch + 1, num_epochs_total + 1):
    train_raw_loop = load_dataset("json", data_files={"train": "TrainingDataModel/*.jsonl"}, streaming=True)["train"]
    train_tok_loop = train_raw_loop.map(preprocess, remove_columns=["input", "output"])
    train_loader = DataLoader(train_tok_loop.shuffle(seed=epoch, buffer_size=50000), batch_size=batch_size, drop_last=True, collate_fn=collator, num_workers=4)
    train_loader = accelerator.prepare(train_loader)

    model.train()
    total_loss, batches = 0.0, 0
    if accelerator.is_main_process: print(f"\n=== Epoch {epoch} Start ===")
    progress_bar = tqdm(train_loader, disable=not accelerator.is_main_process, total=steps_per_epoch)

    for step, batch in enumerate(progress_bar, start=1):
        outputs = model(**batch)
        loss = outputs.loss
        accelerator.backward(loss)
        optimizer.step()
        scheduler.step()
        optimizer.zero_grad()
        
        loss_val = loss.detach().float().item()
        total_loss += loss_val
        batches += 1
        if accelerator.is_main_process: progress_bar.set_description(f"Loss: {loss_val:.4f}")
        if step >= steps_per_epoch: break
    
    progress_bar.close()
    avg_train = total_loss / max(1, batches)
    train_losses.append(avg_train)

    accelerator.wait_for_everyone()
    accelerator.save_state(f"{SNAPSHOT_DIR}/model_epoch{epoch}")
    if accelerator.is_main_process: print(f"Checkpoint {epoch} saved.")

    model.eval()
    total_val, vb = 0.0, 0
    try:
        with torch.no_grad():
            for step, batch in enumerate(eval_loader, start=1):
                batch = {k: v.to(accelerator.device) for k, v in batch.items()}
                out = model(**batch)
                total_val += out.loss.detach().float().item()
                vb += 1
                if step == 1 and accelerator.is_main_process:
                    unwrapped = accelerator.unwrap_model(model)
                    gen_ids = unwrapped.generate(batch["input_ids"][:1], max_length=512)
                    print(f"PRED: {tokenizer.decode(gen_ids[0], skip_special_tokens=False)[:200]}")
                if step >= 500: break
        avg_eval = total_val / max(1, vb)
    except Exception as e:
        if accelerator.is_main_process: print(f"Eval Error: {e}")
        avg_eval = 0.0
    
    eval_losses.append(avg_eval)
    if accelerator.is_main_process:
        print(f"Epoch {epoch} Done: Train={avg_train:.4f}, Eval={avg_eval:.4f}")
        with open("loss_data.txt", "w") as f:
            for t, v in zip(train_losses, eval_losses): f.write(f"{t},{v}\n")
