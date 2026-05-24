# Ollama — Inline LLM Security Agent

## Overview

This folder contains an **inline LLM-based security agent** that detects prompt injection attacks by sending content directly to a locally-hosted Ollama model (Granite 4) and asking it to classify the payload.

The agent is designed as a drop-in component for the **RFP Responder** multi-agent pipeline: extracted requirements pass through the security sentinel before reaching any downstream LLM, blocking malicious payloads at the gate.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for a full architectural diagram and design description.

---

## Files

| File | Purpose |
|---|---|
| `security_agent.py` | Core security agent — LLM client, analysis logic, Flask API server |
| `test_security_agent.py` | Test harness — runs the full dataset and reports classification metrics |

---

## Prerequisites

- **Ollama** running locally at `http://localhost:11434`
- **Granite 4** model available: `ollama pull granite4:latest`
  - The agent currently references `prompt-classifier:latest`; update `OLLAMA_MODEL_ID` in `security_agent.py` to match your pulled model name
- Python 3.11+
- `pip install openai flask`

---

## Running the Test Harness

The test harness loads the shared dataset from the repository root and evaluates the agent against all 500 labelled prompts.

```bash
cd Ollama

# Run against all 500 prompts
python test_security_agent.py

# Quick smoke test — first 20 prompts only
python test_security_agent.py --limit 20

# Start from a specific entry (useful for resuming interrupted runs)
python test_security_agent.py --start 100 --limit 50

# Save detailed per-prompt results to a JSON file
python test_security_agent.py --output results.json
```

**CLI options:**

| Flag | Default | Description |
|---|---|---|
| `--dataset` | repo root JSONL | Path to the dataset file |
| `--output` | auto-named JSON | Path to save the detailed results report |
| `--limit` | 0 (all) | Maximum number of prompts to test |
| `--start` | 0 | Entry index to start from (0-based) |

---

## Running the Agent as a Server

The agent also runs as a Flask API for agent-to-agent (A2A) communication:

```bash
python security_agent.py          # starts Flask on port 5007

# Health check
curl http://localhost:5007/health

# Scan a requirements JSON file
curl -X POST http://localhost:5007/scan \
  -H "Content-Type: application/json" \
  -d '{"requirements_json": "/path/to/requirements.json"}'
```

**Standalone mode** (no server):

```bash
python security_agent.py /path/to/requirements.json [output_audit.json]
# Exit code 2 = malicious content detected
```

---

## Output Metrics

The test harness reports the following metrics, matching the FIDES harness for direct comparison:

| Metric | Description |
|---|---|
| **Accuracy** | % of prompts correctly classified |
| **Precision** | % of malicious predictions that were correct |
| **Sensitivity / Recall** | % of malicious prompts detected |
| **Specificity** | % of benign prompts correctly passed |
| **F1 Score** | Harmonic mean of precision and recall |
| **Confusion Matrix** | TP / TN / FP / FN counts |
| **By Attack Type** | Detection rate broken down by `code_execution`, `obfuscation`, etc. |

---

## Detection Approach

The agent uses a two-phase scan:

1. **Phase 1 — Per-node analysis:** Each JSON field is analysed individually. Catches targeted single-field attacks.
2. **Phase 2 — Full-structure analysis:** The complete JSON is scanned holistically. Catches **payload splitting** — attacks fragmented across multiple keys that are benign in isolation but malicious when concatenated.

Each analysis call returns:

```json
{
  "internal_analysis_scratchpad": "step-by-step reasoning...",
  "is_malicious": true,
  "confidence_score": 0.97,
  "attack_types": ["Direct Instruction Override"],
  "flagged_paths": ["user_input"],
  "severity": "CRITICAL"
}
```
