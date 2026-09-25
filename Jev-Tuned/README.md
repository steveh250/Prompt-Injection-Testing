# Jev Tuned — Probability OR Severity Verdict

## Overview

This is a tuned copy of the [`Jev/`](../Jev/README.md) agent and test harness. Everything
is the same except the **verdict rule**: the model (`typesafe/jev-1.13` via OpenRouter),
the 9-question battery, the prompt wrapping and context line, the retries, and the report
format.

| | Verdict rule |
|---|---|
| `Jev/` | malicious if `p(is_malicious) ≥ 0.5` |
| `Jev-Tuned/` | malicious if `p(is_malicious) ≥ 0.5` **or** `severity score ≥ 1.0` (LOW) |

**Why:** in the [Jev 1.13 run](../Jev/Test%20Results%20-%20Jev%201.13.md), all 39 missed
attacks had `p(is_malicious)` below 0.5, mostly 0.31–0.49. They were mostly bare shell
commands with no manipulation language. But Jev's own `severity` question rated every one
of them at least LOW, with a median of 2.61 (MEDIUM–HIGH), while every benign prompt scored
0.18 or less. So Jev saw the danger even when it wasn't sure the prompt was "manipulation".

**Caveat:** the rule was chosen *after* seeing those results, on the same 500 prompts. A
run on this dataset checks the rule and how consistent Jev's answers are between runs. It
can't show how the rule behaves on benign prompts it hasn't seen. That needs a different
dataset.

## Files

| File | Purpose |
|---|---|
| `security_agent.py` | Jev agent with the tuned verdict. Same CLI and Flask API as `Jev/`, on port **5009** |
| `test_security_agent.py` | Test harness with the tuned verdict, which-rule breakdown, two threshold sweeps and baseline comparison |
| `requirements.txt` | `requests`, `flask` |

## Running

Same prerequisites as `Jev/`: `OPENROUTER_API_KEY` exported, and `pip install -r requirements.txt`.

```bash
cd Jev-Tuned

# Full run, comparing verdicts against the untuned Jev run
python test_security_agent.py \
  --baseline "../Jev/security_test_results_20260925_085821-jev-1.13.json"

python test_security_agent.py --limit 20              # quick test
python test_security_agent.py --severity-threshold 2  # flag only at MEDIUM or above
```

| Flag | Default | Description |
|---|---|---|
| `--threshold` | 0.5 | `p(is_malicious)` at or above which a prompt is flagged |
| `--severity-threshold` | 1.0 (LOW) | Severity score (0 = NONE … 4 = CRITICAL) at or above which a prompt is also flagged |
| `--baseline` | none | Earlier results JSON to compare verdicts against |
| `--dataset`, `--output`, `--limit`, `--start`, `--context` | | Same as `Jev/` |

Results are saved as `security_test_results_<timestamp>-jev-1.13-tuned.json`.

## Output

It prints the same summary as the `Jev/` harness, plus:

| Extra | What it shows |
|---|---|
| **Which rule flagged each detection** | Counts (with TP/FP) of prompts flagged by probability only, severity only, or both. Shows exactly what the tuning added. |
| **Score ranges** | The highest benign and lowest malicious values for both `p(is_malicious)` and severity, i.e. how much margin the thresholds have |
| **Two sweeps** | Accuracy/recall/FP/FN across probability thresholds (severity rule fixed), and across severity thresholds (probability rule fixed). Re-scored from saved answers, no extra API calls. |
| **Baseline comparison** (`--baseline`) | Every prompt whose verdict changed from the earlier run: now correct (misses caught) or now wrong (new false positives or new misses) |

Each per-prompt record also has a `flagged_by` field: `["probability"]`, `["severity"]`,
both, or `[]`.

## Expected result on the Kaggle dataset

Replaying Jev's saved answers from the original run through the tuned rule gives
**500/500 correct and 0 false positives**. The 39 former misses are all flagged by the
severity rule alone. A live run should match this if Jev answers the same way again; any
difference points to run-to-run variation in Jev's answers.
