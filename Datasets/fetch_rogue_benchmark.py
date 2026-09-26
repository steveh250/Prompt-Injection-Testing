#!/usr/bin/env python3
## Author: Steve Harris
# Purpose: Download the rogue-security/prompt-injections-benchmark dataset from
# Hugging Face (5,000 prompts labelled jailbreak / benign; formerly
# qualifire/prompt-injections-benchmark) and convert it to the same JSONL
# format as security_agent-Prompt_INJECTION_And_Benign_DATASET.jsonl, so every
# test harness in this repository can run it with --dataset.
#
# Usage:
#   pip install datasets
#   python fetch_rogue_benchmark.py
#   # If the dataset is gated: accept its terms on huggingface.co, then
#   export HF_TOKEN=hf_...

import argparse
import json
import os
import random
import sys
from collections import Counter

DATASET_ID = "rogue-security/prompt-injections-benchmark"
DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "rogue-security-prompt-injections-benchmark.jsonl",
)

# Column names to look for, in order of preference.
TEXT_COLUMNS = ["text", "prompt", "content", "input", "sentence"]
LABEL_COLUMNS = ["label", "labels", "class", "category", "target"]

# Label values that mean malicious / benign. Integers follow the usual
# convention of 1 = attack, 0 = benign; the script prints the mapping it used
# so it can be checked against the dataset card.
MALICIOUS_LABELS = {"jailbreak", "injection", "prompt_injection", "prompt-injection",
                    "malicious", "attack", "unsafe", "1", "true"}
BENIGN_LABELS = {"benign", "safe", "legit", "legitimate", "normal", "0", "false"}


def _pick_column(columns: list[str], candidates: list[str], kind: str) -> str:
    """Return the first candidate column present, or exit with a helpful message."""
    for name in candidates:
        if name in columns:
            return name
    sys.exit(f"Could not find a {kind} column. Columns in the dataset: {columns}. "
             f"Re-run with --{kind}-column <name>.")


def _label_names(split_dataset, label_column: str) -> list[str] | None:
    """Return ClassLabel names if the label column is a ClassLabel feature."""
    feature = split_dataset.features.get(label_column)
    return getattr(feature, "names", None)


def normalise_label(raw, class_names: list[str] | None) -> str:
    """Map a raw label value to "malicious" or "benign"."""
    if class_names is not None and isinstance(raw, int):
        raw = class_names[raw]
    value = str(raw).strip().lower()
    if value in MALICIOUS_LABELS:
        return "malicious"
    if value in BENIGN_LABELS:
        return "benign"
    raise ValueError(f"Unrecognised label value: {raw!r}")


def convert(rows: list[dict], seed: int) -> list[dict]:
    """
    Convert (text, label, split) rows to the repository's dataset format.

    Entries are shuffled with a fixed seed so that --limit in the harnesses
    takes a mix of both classes rather than one block of a single label.
    """
    entries = []
    for text, label, split in rows:
        entries.append({
            "prompt": text,
            "label": label,
            "attack_type": "jailbreak" if label == "malicious" else "none",
            "context": f"{DATASET_ID} ({split} split)",
            "response": "",
        })
    random.Random(seed).shuffle(entries)
    for i, entry in enumerate(entries, 1):
        entry["id"] = f"rs-{i:04d}"
    # Match the key order of the Kaggle dataset
    return [{k: e[k] for k in ("id", "prompt", "label", "attack_type", "context", "response")}
            for e in entries]


def main():
    parser = argparse.ArgumentParser(description=f"Download {DATASET_ID} and convert it to JSONL")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output JSONL path")
    parser.add_argument("--dataset-id", default=DATASET_ID, help="Hugging Face dataset id")
    parser.add_argument("--text-column", default=None, help="Override the detected text column")
    parser.add_argument("--label-column", default=None, help="Override the detected label column")
    parser.add_argument("--seed", type=int, default=42, help="Shuffle seed (default: 42)")
    args = parser.parse_args()

    try:
        from datasets import load_dataset
    except ImportError:
        sys.exit("The 'datasets' package is required: pip install datasets")

    print(f"Downloading {args.dataset_id} ...")
    try:
        dataset = load_dataset(args.dataset_id, token=os.environ.get("HF_TOKEN"))
    except Exception as e:
        sys.exit(f"Download failed: {e}\nIf the dataset is gated, accept its terms on "
                 f"huggingface.co and export HF_TOKEN=hf_... before re-running.")

    rows = []
    label_counts = Counter()
    for split_name, split in dataset.items():
        columns = split.column_names
        text_col = args.text_column or _pick_column(columns, TEXT_COLUMNS, "text")
        label_col = args.label_column or _pick_column(columns, LABEL_COLUMNS, "label")
        class_names = _label_names(split, label_col)
        print(f"  split '{split_name}': {len(split)} rows, columns {columns}")
        print(f"    using text='{text_col}', label='{label_col}'"
              + (f", class names {class_names}" if class_names else ""))

        for record in split:
            text = record[text_col]
            if not isinstance(text, str) or not text.strip():
                continue
            raw = record[label_col]
            label = normalise_label(raw, class_names)
            shown = f"{raw} ({class_names[raw]})" if class_names and isinstance(raw, int) else str(raw)
            label_counts[(shown, label)] += 1
            rows.append((text, label, split_name))

    print("\nLabel mapping used (raw value -> label: count):")
    for (raw, label), n in sorted(label_counts.items()):
        print(f"  {raw!r:>14} -> {label:9s}: {n}")

    entries = convert(rows, args.seed)
    totals = Counter(e["label"] for e in entries)
    lengths = sorted(len(e["prompt"]) for e in entries)

    with open(args.output, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"\nWrote {len(entries)} entries to {args.output}")
    print(f"  malicious: {totals['malicious']}, benign: {totals['benign']}")
    print(f"  prompt length (chars): median {lengths[len(lengths) // 2]}, "
          f"max {lengths[-1]}")


if __name__ == "__main__":
    main()
