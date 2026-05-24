#!/usr/bin/env python3
## Author: Steve Harris
# Purpose: Test harness for the FIDES Security Agent
# Processes prompts from the shared injection/benign dataset and evaluates
# how well the FIDES approach identifies malicious vs benign prompts.
# Structured to be directly comparable with Ollama/test_security_agent.py.

import json
import sys
import os
import time
import logging
import argparse
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fides_security_agent import (
    FIDESAgent, ContentLabel, Integrity, Confidentiality, OLLAMA_MODEL_ID,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Look for the dataset in the same directory as this script first,
# then fall back to the repository root (one level up) for repo-based runs.
_script_dir = os.path.dirname(os.path.abspath(__file__))
_local = os.path.join(_script_dir, "security_agent-Prompt_INJECTION_And_Benign_DATASET.jsonl")
_repo_root = os.path.join(os.path.dirname(_script_dir), "security_agent-Prompt_INJECTION_And_Benign_DATASET.jsonl")
DATASET_FILE = _local if os.path.exists(_local) else _repo_root


def load_dataset(dataset_path: str) -> list[dict]:
    """Load the JSONL dataset and return a list of entries."""
    entries = []
    with open(dataset_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping invalid JSON on line {line_num}: {e}")
    return entries


def test_prompt(agent: FIDESAgent, entry: dict) -> dict:
    """
    Test a single dataset entry against the FIDES security agent.

    All prompts from the dataset are treated as UNTRUSTED external input —
    which is what FIDES does by default for any content not originating from
    a verified system source.  The FIDES pipeline hides the content, routes
    it through quarantined_llm, and returns the classification.
    """
    prompt_id = entry["id"]
    prompt_text = entry["prompt"]
    expected_label = entry["label"]          # "malicious" or "benign"
    attack_type = entry.get("attack_type", "unknown")
    context = entry.get("context", "")

    expected_malicious = expected_label == "malicious"

    # FIDES: all dataset prompts originate from an external/untrusted source
    source_label = ContentLabel(
        integrity=Integrity.UNTRUSTED,
        confidentiality=Confidentiality.PRIVATE,
    )

    try:
        result = agent.analyze_content(prompt_text, source_label)
        detected_malicious = result.get("is_malicious", False)
        confidence = result.get("confidence_score", 0.0)
        severity = result.get("severity", "NONE")
        detected_attack_types = result.get("attack_types", [])
        fides_metadata = result.get("fides_metadata", {})
    except Exception as e:
        logger.error(f"  [{prompt_id}] FIDES analysis error: {e}")
        detected_malicious = False
        confidence = 0.0
        severity = "ERROR"
        detected_attack_types = []
        fides_metadata = {"processing": "error", "error": str(e)}

    correct = detected_malicious == expected_malicious

    if expected_malicious and detected_malicious:
        outcome = "TRUE_POSITIVE"
    elif expected_malicious and not detected_malicious:
        outcome = "FALSE_NEGATIVE"
    elif not expected_malicious and not detected_malicious:
        outcome = "TRUE_NEGATIVE"
    else:
        outcome = "FALSE_POSITIVE"

    return {
        "id": prompt_id,
        "prompt": prompt_text[:100] + ("..." if len(prompt_text) > 100 else ""),
        "expected_label": expected_label,
        "expected_malicious": expected_malicious,
        "detected_malicious": detected_malicious,
        "correct": correct,
        "outcome": outcome,
        "confidence": confidence,
        "severity": severity,
        "attack_type": attack_type,
        "detected_attack_types": detected_attack_types,
        "context": context,
        "fides_metadata": fides_metadata,
    }


def print_summary(results: list[dict], elapsed: float) -> None:
    """Print a formatted summary comparable to the Ollama test harness output."""
    total = len(results)
    if total == 0:
        print("No results to summarise.")
        return

    correct = sum(1 for r in results if r["correct"])
    incorrect = total - correct

    tp = sum(1 for r in results if r["outcome"] == "TRUE_POSITIVE")
    tn = sum(1 for r in results if r["outcome"] == "TRUE_NEGATIVE")
    fp = sum(1 for r in results if r["outcome"] == "FALSE_POSITIVE")
    fn = sum(1 for r in results if r["outcome"] == "FALSE_NEGATIVE")

    total_malicious = sum(1 for r in results if r["expected_malicious"])
    total_benign = total - total_malicious

    sensitivity = (tp / total_malicious * 100) if total_malicious > 0 else 0.0
    specificity = (tn / total_benign * 100) if total_benign > 0 else 0.0
    accuracy = (correct / total * 100) if total > 0 else 0.0
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
    f1 = (2 * tp / (2 * tp + fp + fn) * 100) if (2 * tp + fp + fn) > 0 else 0.0

    total_hidden = sum(
        1 for r in results if r.get("fides_metadata", {}).get("content_hidden", False)
    )

    missed_by_type: dict[str, list[str]] = {}
    for r in results:
        if r["outcome"] == "FALSE_NEGATIVE":
            missed_by_type.setdefault(r["attack_type"], []).append(r["id"])

    detected_by_type: dict[str, int] = {}
    for r in results:
        if r["outcome"] == "TRUE_POSITIVE":
            detected_by_type[r["attack_type"]] = detected_by_type.get(r["attack_type"], 0) + 1

    print(f"\n{'='*70}")
    print("  FIDES SECURITY AGENT TEST RESULTS SUMMARY")
    print(f"{'='*70}")
    print(f"  Test Run:           {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Approach:           FIDES — Content Labelling + Quarantine Isolation")
    print(f"  Model:              {OLLAMA_MODEL_ID}")
    print(f"  Elapsed Time:       {elapsed:.1f}s ({elapsed / 60:.1f} minutes)")
    print(f"  Prompts Tested:     {total}")
    print()
    print(f"  --- FIDES Security Mechanics ---")
    print(f"  Items Hidden (UNTRUSTED):   {total_hidden}/{total} ({total_hidden / total * 100:.0f}%)")
    print(f"  Main LLM sees raw content:  Never (all input is UNTRUSTED)")
    print(f"  Processing mode:            Quarantine Isolation (no tool access)")
    print()
    print(f"  --- Dataset Composition ---")
    print(f"  Malicious Prompts:  {total_malicious}")
    print(f"  Benign Prompts:     {total_benign}")
    print()
    print(f"  --- Classification Results ---")
    print(f"  Correct:            {correct}/{total} ({accuracy:.1f}%)")
    print(f"  Incorrect:          {incorrect}/{total}")
    print()
    print(f"  --- Confusion Matrix ---")
    print(f"  True Positives  (malicious correctly detected):  {tp}")
    print(f"  True Negatives  (benign correctly passed):       {tn}")
    print(f"  False Positives (benign wrongly flagged):        {fp}")
    print(f"  False Negatives (malicious missed):              {fn}")
    print()
    print(f"  --- Performance Metrics ---")
    print(f"  Accuracy:           {accuracy:.1f}%")
    print(f"  Precision:          {precision:.1f}%")
    print(f"  Sensitivity/Recall: {sensitivity:.1f}%  (malicious detection rate)")
    print(f"  Specificity:        {specificity:.1f}%  (benign pass-through rate)")
    print(f"  F1 Score:           {f1:.1f}%")

    if detected_by_type or total_malicious > 0:
        print(f"\n  --- Detection by Attack Type ---")
        type_totals: dict[str, int] = {}
        for r in results:
            if r["expected_malicious"]:
                type_totals[r["attack_type"]] = type_totals.get(r["attack_type"], 0) + 1
        for at in sorted(type_totals.keys()):
            detected = detected_by_type.get(at, 0)
            total_at = type_totals[at]
            pct = (detected / total_at * 100) if total_at > 0 else 0
            print(f"  {at:20s}: {detected}/{total_at} detected ({pct:.0f}%)")

    if missed_by_type:
        print(f"\n  --- Missed Threats (False Negatives) ---")
        for at, ids in sorted(missed_by_type.items()):
            print(f"  {at}: {', '.join(ids)}")

    false_positives = [r for r in results if r["outcome"] == "FALSE_POSITIVE"]
    if false_positives:
        print(f"\n  --- False Positives (Benign Flagged as Malicious) ---")
        for r in false_positives:
            print(f"  {r['id']}: {r['prompt']}")

    print(f"\n{'='*70}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test the FIDES Security Agent against the prompt injection dataset"
    )
    parser.add_argument(
        "--dataset",
        default=DATASET_FILE,
        help="Path to the JSONL dataset file (default: repo root dataset)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to save detailed results as JSON (auto-named if omitted)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit the number of prompts to test (0 = all)",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=0,
        help="Start from this entry index — 0-based (for batch runs)",
    )
    args = parser.parse_args()

    # --- Load dataset ---
    logger.info(f"Loading dataset from: {args.dataset}")
    if not os.path.exists(args.dataset):
        logger.error(f"Dataset file not found: {args.dataset}")
        sys.exit(1)

    entries = load_dataset(args.dataset)
    logger.info(f"Loaded {len(entries)} entries")

    if args.start > 0:
        entries = entries[args.start:]
    if args.limit > 0:
        entries = entries[: args.limit]

    logger.info(f"Testing {len(entries)} prompts through the FIDES pipeline...")

    # --- Initialise FIDES agent ---
    agent = FIDESAgent(auto_hide_untrusted=True)

    # --- Run tests ---
    results: list[dict] = []
    start_time = time.time()

    for i, entry in enumerate(entries):
        prompt_id = entry["id"]
        label = entry["label"]
        attack_type = entry.get("attack_type", "none")
        preview = entry["prompt"][:60] + ("..." if len(entry["prompt"]) > 60 else "")

        logger.info(
            f"[{i + 1}/{len(entries)}] {prompt_id} ({label}/{attack_type}): {preview}"
        )

        result = test_prompt(agent, entry)
        results.append(result)

        status = "CORRECT" if result["correct"] else "WRONG"
        logger.info(
            f"  -> {status} | expected={label}, "
            f"detected={'malicious' if result['detected_malicious'] else 'benign'} "
            f"| confidence={result['confidence']:.2f} | severity={result['severity']} "
            f"| hidden={result['fides_metadata'].get('var_id', 'n/a')}"
        )

    elapsed = time.time() - start_time

    # --- Print summary ---
    print_summary(results, elapsed)

    # --- Save detailed results ---
    output_path = args.output or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        f"fides_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
    )

    total = len(results)
    correct = sum(1 for r in results if r["correct"])

    report = {
        "test_run": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "approach": "FIDES (Content Labelling + Quarantine Isolation)",
        "model": OLLAMA_MODEL_ID,
        "dataset": args.dataset,
        "total_prompts": total,
        "elapsed_seconds": round(elapsed, 2),
        "accuracy": round(correct / total * 100, 2) if total > 0 else 0,
        "fides_stats": {
            "auto_hide_untrusted": True,
            "variables_created": agent.variable_store.variable_count,
            "middleware_events": agent.middleware.events,
        },
        "results": results,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Detailed results saved to: {output_path}")


if __name__ == "__main__":
    main()
