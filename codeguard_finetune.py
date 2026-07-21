#!/usr/bin/env python3
"""CodeGuard Security Model Fine-Tuning.
One command. Downloads Qwen2.5-7B, fine-tunes on security data, quantizes, saves.
Runs on any GPU (Colab free T4, RunPod, Lambda). ~2-4 hours on T4.

Usage:
  python3 codeguard_finetune.py

After training, upload to HuggingFace:
  from huggingface_hub import notebook_login
  notebook_login()
  model.push_to_hub("YOUR_USER/codeguard-security-7b")
  tokenizer.push_to_hub("YOUR_USER/codeguard-security-7b")
"""
import json
import re
import shutil
import subprocess
import sys
import gc
from pathlib import Path

print("=" * 60)
print("CODEGUARD SECURITY MODEL FINE-TUNING")
print("=" * 60)

# ── STEP 1: Install dependencies ──
print("\n[1/5] Installing dependencies...")
subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet",
    "transformers", "peft", "datasets", "accelerate", "bitsandbytes", "torch", "huggingface_hub"])
print("  Done.")

# ── STEP 2: Generate training dataset from CodeGuard patterns ──
print("\n[2/5] Building security dataset...")

def load_patterns(path="codeguard/patterns.json"):
    paths = [path, "patterns.json"]
    for p in paths:
        if Path(p).exists():
            return json.loads(Path(p).read_text())
    return {"patterns": []}

patterns = load_patterns().get("patterns", [])
print(f"  Found {len(patterns)} patterns")

training_data = []
for p in patterns:
    training_data.append({
        "instruction": f"Analyze this code for {p['type']} vulnerabilities.",
        "input": p.get("explanation", p.get("message", ""))[:200],
        "output": f"This code contains a {p['type']} vulnerability ({p.get('cwe', 'N/A')}). Severity: {p.get('severity', 'medium')}. Fix: {p.get('fix', 'N/A')[:200]}"
    })

# Synthetic safe/unsafe pairs (16 examples)
examples = [
    {"code": 'query = "SELECT * FROM users WHERE id = " + user_id', "label": "VULNERABLE: SQL Injection (CWE-89). Use parameterized queries."},
    {"code": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))', "label": "SAFE: Parameterized query."},
    {"code": 'API_KEY = os.environ.get("API_KEY")', "label": "SAFE: Environment variable. No hardcoded secret."},
    {"code": 'password = "admin123"', "label": "VULNERABLE: Hardcoded secret (CWE-798). Move to env var."},
    {"code": 'element.innerHTML = DOMPurify.sanitize(userHTML)', "label": "SAFE: Sanitized HTML. XSS prevented."},
    {"code": 'element.innerHTML = user_comment', "label": "VULNERABLE: XSS (CWE-79). Use textContent or DOMPurify."},
    {"code": 'subprocess.run(["ls", "-l", user_path])', "label": "SAFE: Argument list. No shell injection."},
    {"code": 'os.system("rm -rf " + user_input)', "label": "VULNERABLE: Command injection (CWE-78). Use argument arrays."},
    {"code": 'hashlib.sha256(data).hexdigest()', "label": "SAFE: SHA-256 for data integrity."},
    {"code": 'hashlib.md5(password).hexdigest()', "label": "VULNERABLE: Weak crypto (CWE-327). Use bcrypt for passwords."},
    {"code": 'pickle.loads(user_data)', "label": "VULNERABLE: Deserialization (CWE-502). Use JSON instead."},
    {"code": 'data = json.loads(user_input)', "label": "SAFE: JSON deserialization."},
    {"code": 'open("/var/data/" + filename)', "label": "VULNERABLE: Path traversal (CWE-22). Validate filename."},
    {"code": 'path = os.path.join("/var/data", os.path.basename(filename))', "label": "SAFE: Basename prevents traversal."},
    {"code": 'eval(user_input)', "label": "VULNERABLE: Code execution (CWE-95). Never eval user input."},
    {"code": 'res.redirect(request.query.next_url)', "label": "VULNERABLE: Open redirect (CWE-601). Validate against whitelist."},
]

for ex in examples:
    training_data.append({
        "instruction": "Analyze this code for security vulnerabilities.",
        "input": ex["code"],
        "output": ex["label"]
    })

print(f"  Total examples: {len(training_data)}")

# ── STEP 3: Load model with QLoRA ──
print("\n[3/5] Loading Qwen2.5-7B-Instruct with QLoRA...")
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainingArguments
from peft import LoraConfig, get_peft_model, TaskType
from datasets import Dataset

model_name = "Qwen/Qwen2.5-7B-Instruct"

gc.collect()
torch.cuda.empty_cache()

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
)

tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    model_name,
    quantization_config=bnb_config,
    device_map="cuda:0",
    trust_remote_code=True,
)

lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type=TaskType.CAUSAL_LM,
)

model = get_peft_model(model, lora_config)
model.gradient_checkpointing_enable()
model.print_trainable_parameters()

# ── STEP 4: Fine-tune ──
print("\n[4/5] Fine-tuning...")

def format_example(ex):
    return f"<|im_start|>user\n{ex['instruction']}\n\nCode:\n{ex['input']}<|im_end|>\n<|im_start|>assistant\n{ex['output']}<|im_end|>"

def tokenize_fn(x):
    tok = tokenizer(x["text"], truncation=True, padding="max_length", max_length=256)
    tok["labels"] = tok["input_ids"].copy()
    return tok

dataset = Dataset.from_list(training_data)
dataset = dataset.map(lambda x: {"text": format_example(x)})
dataset = dataset.map(tokenize_fn, batched=True, remove_columns=dataset.column_names)

args = TrainingArguments(
    output_dir="./codeguard-model",
    per_device_train_batch_size=1,
    gradient_accumulation_steps=4,
    num_train_epochs=3,
    learning_rate=2e-4,
    fp16=True,
    optim="adamw_8bit",
    logging_steps=5,
    save_strategy="epoch",
    report_to="none",
)

from transformers import Trainer
trainer = Trainer(
    model=model,
    args=args,
    train_dataset=dataset,
    processing_class=tokenizer,
)
trainer.train()

# ── STEP 5: Save ──
print("\n[5/5] Saving fine-tuned model...")
output = "./niffyhunt/codeguard-security-7b"
model.save_pretrained(output)
tokenizer.save_pretrained(output)
print(f"  Saved to {output}")
print(f"\nUPLOAD TO HUGGINGFACE:")
print(f"  from huggingface_hub import notebook_login")
print(f"  notebook_login()")
print(f"  model.push_to_hub('YOUR_USER/codeguard-security-7b')")
print(f"  tokenizer.push_to_hub('YOUR_USER/codeguard-security-7b')")
print("\nDONE — Model ready for CodeGuard integration.")
