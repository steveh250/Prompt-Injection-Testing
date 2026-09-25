#!/usr/bin/env python3
## Author: Steve Harris
# Purpose: Test harness for the Jev Security Agent (Agent-Sec-01, Jev edition)
# Processes prompts from the injection/benign dataset and evaluates
# how well the security agent identifies malicious vs benign prompts.
# Mirrors Ollama/test_security_agent.py so results are directly comparable.

import json
import sys
import os
import time
import logging
import argparse
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_agent import (
    _get_jev_client, _analyze_with_jev, JevAPIError,
    JEV_MODEL_ID, MALICIOUS_THRESHOLD,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Path to the dataset file (shared by all harnesses, in the repository root)
DATASET_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "security_agent-Prompt_INJECTION_And_Benign_DATASET.jsonl",
)

# Same wrapper context as the Ollama harness, so the two are directly comparable.
DEFAULT_ANALYSIS_CONTEXT = "This is a single input field from an RFP requirements document."

# Thresholds re-scored from the saved probabilities, without calling Jev again.
SWEEP_THRESHOLDS = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]


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


def _outcome(expected_malicious: bool, detected_malicious: bool) -> str:
    """Classify a verdict against its expected label."""
    if expected_malicious and detected_malicious:
        return "TRUE_POSITIVE"
    if expected_malicious and not detected_malicious:
        return "FALSE_NEGATIVE"
    if not expected_malicious and not detected_malicious:
        return "TRUE_NEGATIVE"
    return "FALSE_POSITIVE"


def test_prompt(client, entry: dict, threshold: float = MALICIOUS_THRESHOLD,
                analysis_context: str = DEFAULT_ANALYSIS_CONTEXT) -> dict:
    """
    Test a single prompt against the security agent.

    Wraps the prompt in a JSON structure and sends it to Jev
    for security analysis, then compares the result with the expected label.

    Returns a result dict with classification details. If Jev cannot be
    reached the outcome is "ERROR": the prompt is excluded from the metrics
    and listed separately, instead of being counted as benign.
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

    record = {
        "id": prompt_id,
        "prompt": prompt_text[:100] + ("..." if len(prompt_text) > 100 else ""),
        "expected_label": expected_label,
        "expected_malicious": expected_malicious,
        "attack_type": attack_type,
        "context": context,
    }

    try:
        result = _analyze_with_jev(client, json_payload, analysis_context, threshold=threshold)
    except JevAPIError as e:
        logger.error(f"  [{prompt_id}] Error during analysis: {e}")
        record.update({
            "detected_malicious": None,
            "correct": False,
            "outcome": "ERROR",
            "confidence": 0.0,
            "severity": "ERROR",
            "detected_attack_types": [],
            "error": str(e),
        })
        return record

    detected_malicious = result["is_malicious"]
    record.update({
        "detected_malicious": detected_malicious,
        "correct": detected_malicious == expected_malicious,
        "outcome": _outcome(expected_malicious, detected_malicious),
        "confidence": result["confidence_score"],
        "severity": result["severity"],
        "detected_attack_types": result["attack_types"],
        "malicious_probability": result["malicious_probability"],
        "severity_score": result["severity_score"],
        "attack_type_probabilities": result["attack_type_probabilities"],
        "usage": result["usage"],
        "latency_ms": result["latency_ms"],
    })
    return record


def _roc_auc(scored: list[dict]) -> float | None:
    """ROC-AUC of malicious_probability: the chance a random attack outranks a random benign prompt."""
    positives = [r["malicious_probability"] for r in scored if r["expected_malicious"]]
    negatives = [r["malicious_probability"] for r in scored if not r["expected_malicious"]]
    if not positives or not negatives:
        return None
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0
               for p in positives for n in negatives)
    return wins / (len(positives) * len(negatives))


def print_summary(results: list[dict], elapsed: float, threshold: float):
    """Print a formatted summary of the test results."""
    errors = [r for r in results if r["outcome"] == "ERROR"]
    scored = [r for r in results if r["outcome"] != "ERROR"]

    total = len(scored)
    correct = sum(1 for r in scored if r["correct"])
    incorrect = total - correct

    # Confusion matrix counts
    tp = sum(1 for r in scored if r["outcome"] == "TRUE_POSITIVE")
    tn = sum(1 for r in scored if r["outcome"] == "TRUE_NEGATIVE")
    fp = sum(1 for r in scored if r["outcome"] == "FALSE_POSITIVE")
    fn = sum(1 for r in scored if r["outcome"] == "FALSE_NEGATIVE")

    # Dataset composition
    total_malicious = sum(1 for r in scored if r["expected_malicious"])
    total_benign = total - total_malicious

    # Detection rates
    sensitivity = (tp / total_malicious * 100) if total_malicious > 0 else 0.0
    specificity = (tn / total_benign * 100) if total_benign > 0 else 0.0
    accuracy = (correct / total * 100) if total > 0 else 0.0
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
    f1 = (2 * tp / (2 * tp + fp + fn) * 100) if (2 * tp + fp + fn) > 0 else 0.0

    # Breakdown by attack type (for misclassified malicious prompts)
    missed_by_type = {}
    for r in scored:
        if r["outcome"] == "FALSE_NEGATIVE":
            at = r["attack_type"]
            missed_by_type.setdefault(at, []).append(r["id"])

    detected_by_type = {}
    for r in scored:
        if r["outcome"] == "TRUE_POSITIVE":
            at = r["attack_type"]
            detected_by_type.setdefault(at, 0)
            detected_by_type[at] += 1

    # Cost and latency
    total_cost = sum(float(r.get("usage", {}).get("cost") or 0.0) for r in scored)
    latencies = sorted(r["latency_ms"] for r in scored)

    print(f"\n{'='*70}")
    print("  SECURITY AGENT TEST RESULTS SUMMARY (Jev)")
    print(f"{'='*70}")
    print(f"  Test Run:           {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Model:              {JEV_MODEL_ID}")
    print(f"  Threshold:          {threshold:.2f}")
    print(f"  Elapsed Time:       {elapsed:.1f}s ({elapsed/60:.1f} minutes)")
    print(f"  Prompts Tested:     {len(results)}")
    print(f"  Scored:             {total}")
    print(f"  Errors (unscored):  {len(errors)}")
    print()
    print(f"  --- Dataset Composition (scored) ---")
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
    auc = _roc_auc(scored)
    if auc is not None:
        print(f"  ROC-AUC:            {auc:.4f}  (threshold independent)")

    if latencies:
        p50 = latencies[len(latencies) // 2]
        p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
        print()
        print(f"  --- Cost and Latency ---")
        print(f"  Total Cost:         ${total_cost:.6f}")
        print(f"  Latency p50/p95:    {p50} ms / {p95} ms")

    if detected_by_type:
        print(f"\n  --- Detection by Attack Type ---")
        # Count totals per attack type
        type_totals = {}
        for r in scored:
            if r["expected_malicious"]:
                at = r["attack_type"]
                type_totals.setdefault(at, 0)
                type_totals[at] += 1
        for at in sorted(type_totals.keys()):
            detected = detected_by_type.get(at, 0)
            total_at = type_totals[at]
            pct = (detected / total_at * 100) if total_at > 0 else 0
            print(f"  {at:20s}: {detected}/{total_at} detected ({pct:.0f}%)")

    if scored:
        print(f"\n  --- Threshold Sweep (re-scored from saved probabilities) ---")
        print(f"  {'threshold':>9}  {'accuracy':>8}  {'recall':>6}  {'FP':>4}  {'FN':>4}")
        for t in SWEEP_THRESHOLDS:
            s_tp = sum(1 for r in scored if r["expected_malicious"] and r["malicious_probability"] >= t)
            s_fp = sum(1 for r in scored if not r["expected_malicious"] and r["malicious_probability"] >= t)
            s_fn = total_malicious - s_tp
            s_acc = (total - s_fp - s_fn) / total * 100
            s_rec = (s_tp / total_malicious * 100) if total_malicious > 0 else 0.0
            print(f"  {t:>9.1f}  {s_acc:>7.1f}%  {s_rec:>5.1f}%  {s_fp:>4}  {s_fn:>4}")

    if missed_by_type:
        print(f"\n  --- Missed Threats (False Negatives) ---")
        for at, ids in sorted(missed_by_type.items()):
            print(f"  {at}: {', '.join(ids)}")

    # Show false positives
    false_positives = [r for r in scored if r["outcome"] == "FALSE_POSITIVE"]
    if false_positives:
        print(f"\n  --- False Positives (Benign Flagged as Malicious) ---")
        for r in false_positives:
            print(f"  {r['id']}: {r['prompt']}")

    if errors:
        print(f"\n  --- Errors (not scored; re-run with --start/--limit) ---")
        for r in errors:
            print(f"  {r['id']}: {r['error']}")

    print(f"\n{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Test the Jev Security Agent against the prompt injection dataset"
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
    parser.add_argument(
        "--threshold",
        type=float,
        default=MALICIOUS_THRESHOLD,
        help=f"Malicious probability threshold (default: {MALICIOUS_THRESHOLD})",
    )
    parser.add_argument(
        "--context",
        default=DEFAULT_ANALYSIS_CONTEXT,
        help="Analysis context sent with each prompt (default: same as the Ollama harness)",
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

    logger.info(f"Testing {len(entries)} prompts against the security agent ({JEV_MODEL_ID})...")

    # Initialize Jev client
    try:
        client = _get_jev_client()
    except JevAPIError as e:
        logger.error(str(e))
        sys.exit(1)

    # Process each prompt
    results = []
    start_time = time.time()

    for i, entry in enumerate(entries):
        prompt_id = entry["id"]
        label = entry["label"]
        attack_type = entry.get("attack_type", "none")
        prompt_preview = entry["prompt"][:60] + ("..." if len(entry["prompt"]) > 60 else "")

        logger.info(f"[{i+1}/{len(entries)}] {prompt_id} ({label}/{attack_type}): {prompt_preview}")

        result = test_prompt(client, entry, threshold=args.threshold,
                             analysis_context=args.context)
        results.append(result)

        if result["outcome"] == "ERROR":
            logger.info(f"  -> ERROR | expected={label} | {result['error']}")
            continue
        status = "CORRECT" if result["correct"] else "WRONG"
        logger.info(
            f"  -> {status} | expected={label}, detected={'malicious' if result['detected_malicious'] else 'benign'} "
            f"| p(malicious)={result['malicious_probability']:.3f} | severity={result['severity']}"
        )

    elapsed = time.time() - start_time

    # Print summary
    print_summary(results, elapsed, args.threshold)

    # Save detailed results if requested
    output_path = args.output
    if output_path is None:
        output_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"security_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}-{JEV_MODEL_ID.split('/')[-1]}.json",
        )

    scored = [r for r in results if r["outcome"] != "ERROR"]
    report = {
        "test_run": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "model": JEV_MODEL_ID,
        "threshold": args.threshold,
        "analysis_context": args.context,
        "dataset": args.dataset,
        "total_prompts": len(results),
        "scored_prompts": len(scored),
        "errors": len(results) - len(scored),
        "elapsed_seconds": round(elapsed, 2),
        "accuracy": round(sum(1 for r in scored if r["correct"]) / len(scored) * 100, 2) if scored else 0,
        "roc_auc": round(_roc_auc(scored), 4) if _roc_auc(scored) is not None else None,
        "results": results,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Detailed results saved to: {output_path}")


if __name__ == "__main__":
    main()
