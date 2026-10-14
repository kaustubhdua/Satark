from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Opt-in LoRA SFT for reviewed SATARK prompt/completion pairs.")
    parser.add_argument("--model", required=True, help="Reviewed Hugging Face model ID or local path")
    parser.add_argument("--input", default="data/train/examples.jsonl")
    parser.add_argument("--output", default="artifacts/satark-lora")
    parser.add_argument("--max-steps", type=int, default=100)
    args = parser.parse_args()

    source = Path(args.input)
    if not source.is_file():
        parser.error(f"dataset not found: {source}; do not train on the evaluation set")
    if args.max_steps < 1 or args.max_steps > 100_000:
        parser.error("--max-steps must be between 1 and 100000")

    rows = []
    seen_ids: set[str] = set()
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            parser.error(f"invalid JSON at line {line_number}")
        if not isinstance(row, dict):
            parser.error(f"invalid row at line {line_number}: expected object")
        row_id = row.get("id")
        prompt = row.get("prompt")
        completion = row.get("completion")
        if not isinstance(row_id, str) or not row_id.strip() or row_id in seen_ids:
            parser.error(f"invalid or duplicate id at line {line_number}")
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 12_000:
            parser.error(f"invalid prompt at line {line_number}")
        if not isinstance(completion, str) or not completion.strip() or len(completion) > 6_000:
            parser.error(f"invalid completion at line {line_number}")
        seen_ids.add(row_id)
        rows.append({"prompt": prompt, "completion": completion})
    if len(rows) < 10:
        parser.error("at least 10 reviewed training examples are required; the eval set is not training data")

    # Imports are delayed so normal service installs do not require a GPU/training stack.
    try:
        from datasets import Dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from trl import SFTConfig, SFTTrainer
    except ImportError as exc:
        parser.error(f"training dependencies missing; install training/requirements.txt ({exc})")

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(args.model)
    config = LoraConfig(
        r=8,
        lora_alpha=16,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules="all-linear",
    )
    training = SFTConfig(
        output_dir=args.output,
        max_steps=args.max_steps,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        learning_rate=2e-4,
        logging_steps=5,
        save_steps=25,
        report_to="none",
        fp16=False,
        completion_only_loss=True,
    )
    trainer = SFTTrainer(
        model=model,
        args=training,
        train_dataset=Dataset.from_list(rows),
        peft_config=config,
        processing_class=tokenizer,
    )
    trainer.train()
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)
    print(f"Saved adapter to {args.output}. Run held-out evaluation before deployment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
