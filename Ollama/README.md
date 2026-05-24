# Ollama — Inline LLM Security Agent

## Overview

This folder contains an **inline LLM fire break** — a security agent that sits between document-extraction and execution in the **RFP Responder** multi-agent pipeline. Every piece of extracted content is scanned before it is passed to any downstream LLM. If a prompt injection attack is detected, the pipeline is **aborted immediately**. The malicious payload never reaches an agent that could act on it.

```
RFP document
    └─► extract requirements
            └─► [Security Agent — Agent-Sec-01]
                    ├── malicious detected ──► ABORT (pipeline halted, exit code 2)
                    └── benign verdict     ──► pass through to downstream LLM agent
```

The agent uses a local Ollama-hosted model (Granite 4) and communicates via an OpenAI-compatible API. It exposes both a standalone CLI mode (for scripted pipelines) and a Flask REST API for agent-to-agent (A2A) communication.

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
# Exit code 0 = clean, pipeline may continue
# Exit code 2 = malicious content detected, pipeline should abort
```

In a scripted pipeline, the caller checks the exit code to decide whether to proceed:

```bash
python security_agent.py requirements.json
if [ $? -eq 2 ]; then
    echo "SECURITY ALERT: aborting pipeline"
    exit 1
fi
# safe to continue
python downstream_agent.py requirements.json
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

## Fire Break Behaviour

The security agent is a **hard gate**: a `true` result from `is_malicious` causes the pipeline to stop. In A2A mode the calling orchestrator receives the full audit report and is responsible for honouring the abort signal. In standalone/CLI mode, exit code 2 signals abort to the shell.

There is no partial pass-through. If any node in the scanned JSON is flagged as malicious, the entire payload is treated as compromised.

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
