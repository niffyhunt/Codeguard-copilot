"""WraithCore — Fine-tuned security intelligence model.

Loads Qwen2.5-7B-Instruct + LoRA adapter from HuggingFace.
3 analysis methods: attacker classification, phishing detection, CVE scoring.

Auto-detects GPU/CPU. Uses 4-bit quantization for 8GB VRAM compatibility.
"""
import json
import os
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

MODEL_ID = "Ezmcyber890/wraithcore-7b"
BASE_MODEL_ID = "Qwen/Qwen2.5-7B-Instruct"

SYSTEM_PROMPT = """You are a security intelligence model. Respond ONLY with valid JSON. No explanations."""


class WraithCore:
    _instance: Optional["WraithCore"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, device: str = "auto", max_length: int = 512):
        if self._initialized:
            return
        self._initialized = True
        self.device = device
        self.max_length = max_length
        self.model = None
        self.tokenizer = None
        self._load_model()

    def _load_model(self):
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
            from peft import PeftModel

            device_map = "auto"
            if self.device == "cpu":
                device_map = "cpu"
            elif self.device == "cuda" and not torch.cuda.is_available():
                logger.warning("CUDA requested but not available, falling back to CPU")
                device_map = "cpu"

            quant_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",
            )

            logger.info(f"Loading base model {BASE_MODEL_ID}...")
            base = AutoModelForCausalLM.from_pretrained(
                BASE_MODEL_ID,
                quantization_config=quant_config,
                device_map=device_map,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                trust_remote_code=True,
            )

            logger.info(f"Loading LoRA adapter from {MODEL_ID}...")
            self.model = PeftModel.from_pretrained(base, MODEL_ID)
            self.model.eval()

            self.tokenizer = AutoTokenizer.from_pretrained(
                BASE_MODEL_ID,
                trust_remote_code=True,
                padding_side="left",
            )
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            logger.info("WraithCore model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load WraithCore model: {e}")
            self.model = None
            self.tokenizer = None

    def is_ready(self) -> bool:
        return self.model is not None and self.tokenizer is not None

    def _infer(self, user_content: str) -> str:
        if not self.is_ready():
            return '{"error": "model_not_loaded"}'

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]
        prompt = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )

        import torch
        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=self.max_length)
        inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=256,
                temperature=0.1,
                do_sample=False,
                top_p=0.9,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id,
            )

        response = self.tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        response = response.strip()

        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            return json_match.group(0)

        first = response.find("{")
        last = response.rfind("}")
        if first != -1 and last != -1 and last > first:
            return response[first:last+1]

        return response

    def _parse_json(self, raw: str) -> dict:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"error": "parse_failed", "raw": raw[:200]}

    def classify_attacker(self, session_json: dict) -> dict:
        ip = session_json.get("src_ip", "unknown")
        duration = session_json.get("duration", 0)
        commands = session_json.get("commands", [])
        downloads = session_json.get("downloads", [])
        login_attempts = session_json.get("login_attempts", [])

        user_content = (
            f"[HONEYPOT] IP={ip} duration={duration} "
            f"commands={json.dumps(commands[:10])} "
            f"downloads={json.dumps(downloads[:3])}"
        )
        raw = self._infer(user_content)
        result = self._parse_json(raw)
        required = {"attacker_class", "ttp", "confidence"}
        if not required.intersection(result.keys()):
            result["attacker_class"] = self._rule_fallback(ip, duration, commands, login_attempts)
            result["ttp"] = {"scanner": "T1046", "brute_forcer": "T1110", "interactive_attacker": "T1059",
                             "ransomware_dropper": "T1204.002", "script_based_attacker": "T1059.006"}.get(
                result["attacker_class"], "T1046")
            result["confidence"] = 0.85
        result["_source"] = "wraithcore"
        return result

    def _rule_fallback(self, ip, duration, commands, login_attempts):
        if duration == 0 and not commands:
            return "scanner"
        if sum(1 for a in login_attempts if not a.get("success", False)) > 10:
            return "brute_forcer"
        if duration > 30 and len(commands) > 0:
            cmd_text = " ".join(commands).lower()
            if any(kw in cmd_text for kw in ["wget", "curl", "chmod +x", "./", "chmod 777"]):
                return "ransomware_dropper"
            return "interactive_attacker"
        if len(commands) > 0:
            return "script_based_attacker"
        return "scanner"

    def detect_phishing(self, content: str) -> dict:
        user_content = f"[PHISHING] {content[:500]}"
        raw = self._infer(user_content)
        result = self._parse_json(raw)
        required = {"is_phishing", "confidence", "technique"}
        if not required.intersection(result.keys()):
            result["is_phishing"] = "phish" in content.lower() or "login" in content.lower()
            result["confidence"] = 0.5
            result["technique"] = "unknown"
        result["_source"] = "wraithcore"
        return result

    def score_cve(self, cve_id: str, description: str, patch_diff: str = "") -> dict:
        diff_part = f" patch_diff={patch_diff[:200]}" if patch_diff else ""
        user_content = f"[CVE] {cve_id} description={description[:300]}{diff_part}"
        raw = self._infer(user_content)
        result = self._parse_json(raw)
        required = {"exploited_in_wild", "difficulty", "attack_vector"}
        if not required.intersection(result.keys()):
            result["exploited_in_wild"] = False
            result["difficulty"] = 5
            result["attack_vector"] = "network"
            result["kev"] = False
        result["_source"] = "wraithcore"
        return result


def get_wraithcore() -> WraithCore:
    return WraithCore()
