# Jev — Inline Security Agent using a Decision Model

## Overview

This folder is the **Jev version** of the [`Ollama/`](../Ollama/README.md) security agent and
test harness. The pipeline role is the same: an inline fire break that scans content and aborts
on a prompt injection. So are the functions, the CLI, the Flask API and the report format.
Only the model changes. Instead of a local chat LLM, the agent uses **Jev**
(`typesafe/jev-1.13`), TypeSafe AI's "System One" decision model, through OpenRouter.

Jev is not a chat model. It does not generate text. It receives a `state` and a set of typed
questions, and returns a **probability** for each question:

```
content ──► Jev Decisions API ──► p(is_malicious), p(each threat vector), severity score
                                        │
                              threshold in code (default 0.5)
                                        ├── malicious ──► ABORT
                                        └── benign    ──► pass through
```

## Files

| File | Purpose |
|---|---|
| `security_agent.py` | Jev client, question battery, analysis logic, two-phase JSON scan, Flask API server (port 5008) |
| `test_security_agent.py` | Test harness: runs the shared 500-prompt dataset and reports classification metrics |
| `requirements.txt` | `requests`, `flask` |

## Prerequisites

- An **OpenRouter API key** with credit: `export OPENROUTER_API_KEY=sk-or-...`
- Python 3.11+
- `pip install -r requirements.txt`

Optional environment overrides:

| Variable | Default |
|---|---|
| `JEV_MODEL_ID` | `typesafe/jev-1.13` (pinned; `jev-latest` can be re-calibrated without notice) |
| `JEV_DECISIONS_URL` | `https://openrouter.ai/api/alpha/decisions` |

### Smoke test first

The Decisions endpoint is still **alpha**, and this code was written from TypeSafe's API
and open-source Jev clients. It has not been run against the live endpoint. Before a full
run, test it on a few prompts:

```bash
python test_security_agent.py --limit 4
```

If every prompt comes back as `ERROR`, check the logged HTTP status and body. The request
and response handling lives in `_call_jev()`, `_noul_value()` and `_score_value()` in
`security_agent.py`.

## Running the Test Harness

```bash
cd Jev

python test_security_agent.py                      # all 500 prompts
python test_security_agent.py --limit 20           # quick test
python test_security_agent.py --start 100 --limit 50
python test_security_agent.py --output results.json
python test_security_agent.py --threshold 0.7      # stricter verdict threshold
```

| Flag | Default | Description |
|---|---|---|
| `--dataset` | repo root JSONL | Path to the dataset file |
| `--output` | auto-named JSON in this folder | Path to save the detailed results report |
| `--limit` | 0 (all) | Maximum number of prompts to test |
| `--start` | 0 | Entry index to start from (0-based) |
| `--threshold` | 0.5 | Malicious probability at or above which a prompt is flagged |
| `--context` | Ollama harness wording | Analysis context sent with every prompt |

Each prompt is sent exactly as in the Ollama harness: wrapped as `{"user_input": "<prompt>"}`,
with the context *"This is a single input field from an RFP requirements document."*
This keeps the results directly comparable. Use `--context` to try other wording.

A full run costs a few cents (~$0.042 per million input tokens, output free) and takes a few minutes.

## Output Metrics

The harness reports the same metrics as the Ollama and FIDES harnesses: accuracy,
precision, recall, specificity, F1, the confusion matrix, detection by attack type,
missed threats and false positives. It also reports:

| Extra | Why |
|---|---|
| **ROC-AUC** | How well Jev's probabilities separate attacks from benign prompts, independent of any threshold |
| **Threshold sweep** | Accuracy / recall / FP / FN at thresholds 0.1–0.9, re-scored from saved probabilities without calling Jev again |
| **Cost and latency** | Total `usage.cost`, p50/p95 latency |
| **Errors** | Prompts Jev could not answer are listed and **excluded** from the metrics, never counted as benign. Re-run them with `--start/--limit` |

Each per-prompt record in the JSON report also carries `malicious_probability`,
`severity_score`, `attack_type_probabilities` and `usage`.

## How the Ollama system prompt maps onto Jev

A single request per piece of content asks all of these questions. They are answered
independently, for the cost of one call:

| Question id | Type | Becomes |
|---|---|---|
| `is_malicious` | noul (probability) | `is_malicious` (≥ threshold), `confidence_score` |
| `severity` | score (NONE, LOW, MEDIUM, HIGH, CRITICAL) | `severity` (nearest level) |
| `direct_instruction_override`, `roleplay_virtualization`, `obfuscation_smuggling`, `payload_splitting`, `context_window_escape`, `indirect_injection`, `many_shot_flooding` | noul each | `attack_types` (those ≥ 0.5) |

The seven threat vectors are the ones in the Ollama agent's `SECURITY_SYSTEM_PROMPT`.

Differences from the Ollama agent:

- **No reasoning.** Jev returns probabilities only, so `internal_analysis_scratchpad` records
  them instead of step-by-step reasoning.
- **No JSON parsing or repair.** Answers are typed, so `--force-json` and the layered parser
  are gone.
- **`confidence_score`** is the confidence in the verdict given: `p` for a malicious verdict,
  `1 − p` for a benign one. The raw probability is in `malicious_probability`.
- **`flagged_paths`.** Jev cannot point at a location, so the agent reports the node path
  that was scanned.
- **Errors fail closed.** In agent mode, content Jev could not scan is treated as malicious
  (attack type `Scan Error`). The Ollama agent treats an analysis error as benign.

## Running the Agent as a Server / Standalone

The interface is the same as the Ollama agent, apart from the port (5008) and the dropped
`--force-json` / `force_json` option:

```bash
python security_agent.py                                   # Flask on port 5008
curl -X POST http://localhost:5008/scan -H "Content-Type: application/json" \
  -d '{"requirements_json": "/path/to/requirements.json"}'

python security_agent.py /path/to/requirements.json [output_audit.json]
# Exit code 0 = clean; 2 = malicious content detected or scan failed (abort)
```

## Things to be aware of

- **Data leaves the machine.** Content is sent to OpenRouter and TypeSafe, unlike the local
  Ollama models.
- **Jev can be steered too.** TypeSafe notes that adversarial text can move its answers,
  so false negatives are worth reviewing.
- **Question wording is the main tuning lever.** It lives in `_build_questions()` and
  `THREAT_VECTORS`. Keep it fixed between runs you want to compare.
