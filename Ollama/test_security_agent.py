#!/usr/bin/env python3
## Author: Steve Harris
# Purpose: Test harness for the Security Agent (Agent-Sec-01)
# Processes prompts from the injection/benign dataset and evaluates
# how well the security agent identifies malicious vs benign prompts.

import json
import sys
import os
import time
import logging
import argparse
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_agent import _get_llm_client, _analyze_with_llm

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Path to the dataset file
DATASET_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "security_agent-Prompt_INJECTION_And_Benign_DATASET.jsonl",
)


def load_dataset(dataset_path: str) -> list[dict]:
    """Load the JSONL dataset file and return a list of entries."""
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


def test_prompt(client, entry: dict) -> dict:
    """
    Test a single prompt against the security agent.

    Wraps the prompt in a JSON structure and sends it to the LLM
    for security analysis, then compares the result with the expected label.

    Returns a result dict with classification details.
    """
    prompt_id = entry["id"]
    prompt_text = entry["prompt"]
    expected_label = entry["label"]  # "malicious" or "benign"
    attack_type = entry.get("attack_type", "unknown")
    context = entry.get("context", "")

    # Expected boolean based on label
    expected_malicious = expected_label == "malicious"

    # Wrap the prompt as a JSON payload (simulating an RFP requirement node)
    json_payload = json.dumps({"user_input": prompt_text}, indent=2)
    analysis_context = "This is a single input field from an RFP requirements document."

    try:
        result = _analyze_with_llm(client, json_payload, analysis_context)
        detected_malicious = result.get("is_malicious", False)
        confidence = result.get("confidence_score", 0.0)
        severity = result.get("severity", "NONE")
        detected_attack_types = result.get("attack_types", [])
    except Exception as e:
        logger.error(f"  [{prompt_id}] Error during analysis: {e}")
        detected_malicious = False
        confidence = 0.0
        severity = "ERROR"
        detected_attack_types = []

    # Determine correctness
    correct = detected_malicious == expected_malicious

    # Classify the outcome
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
    }


def print_summary(results: list[dict], elapsed: float):
    """Print a formatted summary of the test results."""
    total = len(results)
    correct = sum(1 for r in results if r["correct"])
    incorrect = total - correct

    # Confusion matrix counts
    tp = sum(1 for r in results if r["outcome"] == "TRUE_POSITIVE")
    tn = sum(1 for r in results if r["outcome"] == "TRUE_NEGATIVE")
    fp = sum(1 for r in results if r["outcome"] == "FALSE_POSITIVE")
    fn = sum(1 for r in results if r["outcome"] == "FALSE_NEGATIVE")

    # Dataset composition
    total_malicious = sum(1 for r in results if r["expected_malicious"])
    total_benign = total - total_malicious

    # Detection rates
    sensitivity = (tp / total_malicious * 100) if total_malicious > 0 else 0.0
    specificity = (tn / total_benign * 100) if total_benign > 0 else 0.0
    accuracy = (correct / total * 100) if total > 0 else 0.0
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
    f1 = (2 * tp / (2 * tp + fp + fn) * 100) if (2 * tp + fp + fn) > 0 else 0.0

    # Breakdown by attack type (for misclassified malicious prompts)
    missed_by_type = {}
    for r in results:
        if r["outcome"] == "FALSE_NEGATIVE":
            at = r["attack_type"]
            missed_by_type.setdefault(at, []).append(r["id"])

    detected_by_type = {}
    for r in results:
        if r["outcome"] == "TRUE_POSITIVE":
            at = r["attack_type"]
            detected_by_type.setdefault(at, 0)
            detected_by_type[at] += 1

    print(f"\n{'='*70}")
    print("  SECURITY AGENT TEST RESULTS SUMMARY")
    print(f"{'='*70}")
    print(f"  Test Run:           {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Elapsed Time:       {elapsed:.1f}s ({elapsed/60:.1f} minutes)")
    print(f"  Prompts Tested:     {total}")
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

    if detected_by_type:
        print(f"\n  --- Detection by Attack Type ---")
        # Count totals per attack type
        type_totals = {}
        for r in results:
            if r["expected_malicious"]:
                at = r["attack_type"]
                type_totals.setdefault(at, 0)
                type_totals[at] += 1
        for at in sorted(type_totals.keys()):
            detected = detected_by_type.get(at, 0)
            total_at = type_totals[at]
            pct = (detected / total_at * 100) if total_at > 0 else 0
            print(f"  {at:20s}: {detected}/{total_at} detected ({pct:.0f}%)")

    if missed_by_type:
        print(f"\n  --- Missed Threats (False Negatives) ---")
        for at, ids in sorted(missed_by_type.items()):
            print(f"  {at}: {', '.join(ids)}")

    # Show false positives
    false_positives = [r for r in results if r["outcome"] == "FALSE_POSITIVE"]
    if false_positives:
        print(f"\n  --- False Positives (Benign Flagged as Malicious) ---")
        for r in false_positives:
            print(f"  {r['id']}: {r['prompt']}")

    print(f"\n{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Test the Security Agent against the prompt injection dataset"
    )
    parser.add_argument(
        "--dataset",
        default=DATASET_FILE,
        help="Path to the JSONL dataset file",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to save detailed results as JSON",
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
        help="Start from this entry index (0-based)",
    )
    args = parser.parse_args()

    # Load dataset
    logger.info(f"Loading dataset from: {args.dataset}")
    entries = load_dataset(args.dataset)
    logger.info(f"Loaded {len(entries)} entries")

    # Apply start/limit
    if args.start > 0:
        entries = entries[args.start:]
    if args.limit > 0:
        entries = entries[: args.limit]

    logger.info(f"Testing {len(entries)} prompts against the security agent...")

    # Initialize LLM client
    client = _get_llm_client()

    # Process each prompt
    results = []
    start_time = time.time()

    for i, entry in enumerate(entries):
        prompt_id = entry["id"]
        label = entry["label"]
        attack_type = entry.get("attack_type", "none")
        prompt_preview = entry["prompt"][:60] + ("..." if len(entry["prompt"]) > 60 else "")

        logger.info(f"[{i+1}/{len(entries)}] {prompt_id} ({label}/{attack_type}): {prompt_preview}")

        result = test_prompt(client, entry)
        results.append(result)

        status = "CORRECT" if result["correct"] else "WRONG"
        logger.info(
            f"  -> {status} | expected={label}, detected={'malicious' if result['detected_malicious'] else 'benign'} "
            f"| confidence={result['confidence']:.2f} | severity={result['severity']}"
        )

    elapsed = time.time() - start_time

    # Print summary
    print_summary(results, elapsed)

    # Save detailed results if requested
    output_path = args.output
    if output_path is None:
        output_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"security_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )

    report = {
        "test_run": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": args.dataset,
        "total_prompts": len(results),
        "elapsed_seconds": round(elapsed, 2),
        "accuracy": round(sum(1 for r in results if r["correct"]) / len(results) * 100, 2) if results else 0,
        "results": results,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Detailed results saved to: {output_path}")


if __name__ == "__main__":
    main()

