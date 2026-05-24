# MAF-FIDES — Content Labelling + Quarantine Isolation

## Overview

This folder implements Microsoft's **FIDES** (Foundational Integration Defense for Execution Security) approach to prompt injection defence, adapted for testing against the shared prompt injection dataset.

Reference implementation: [microsoft/agent-framework — security sample](https://github.com/microsoft/agent-framework/tree/main/python/samples/02-agents/security)

Both approaches share the same goal — stopping a prompt injection before it reaches an agent that would execute it — but they work differently:

- The **Ollama approach** is an inline fire break: it scans content directly with an LLM and **aborts the entire pipeline** if a threat is detected. The downstream agent is never called.
- The **FIDES approach** acts at the middleware level: untrusted content is **hidden from the main LLM** before it can cause harm, and policy enforcement **blocks specific downstream tool calls** if the quarantine verdict is malicious. The isolation is structural rather than relying solely on LLM judgment.

When classification is needed, an isolated **quarantine LLM** processes the hidden content with no tool access and explicit data-framing, making it highly resistant to being hijacked by the payload it is examining.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for a full architectural diagram and design description.

---

## Files

| File | Purpose |
|---|---|
| `fides_security_agent.py` | Core FIDES implementation — content labels, variable store, middleware, quarantine LLM |
| `test_fides_agent.py` | Test harness — runs the full dataset and reports classification metrics |
| `requirements.txt` | Python dependencies |

---

## Prerequisites

- **Ollama** running locally at `http://localhost:11434`
- **Granite 4** model pulled: `ollama pull granite4:latest`
- Python 3.11+

```bash
pip install -r requirements.txt
```

---

## Running the Test Harness

```bash
cd MAF-FIDES

# Run against all 500 prompts
python test_fides_agent.py

# Quick smoke test — first 20 prompts only
python test_fides_agent.py --limit 20

# Start from a specific entry (useful for resuming interrupted runs)
python test_fides_agent.py --start 100 --limit 50

# Save detailed per-prompt results to a JSON file
python test_fides_agent.py --output results.json
```

**CLI options:**

| Flag | Default | Description |
|---|---|---|
| `--dataset` | repo root JSONL | Path to the dataset file |
| `--output` | auto-named JSON | Path to save the detailed results report |
| `--limit` | 0 (all) | Maximum number of prompts to test |
| `--start` | 0 | Entry index to start from (0-based) |

---

## Output Metrics

The test harness produces the same metrics as the Ollama harness for direct comparison, plus FIDES-specific fields:

| Metric | Description |
|---|---|
| **Accuracy** | % of prompts correctly classified |
| **Precision** | % of malicious predictions that were correct |
| **Sensitivity / Recall** | % of malicious prompts detected |
| **Specificity** | % of benign prompts correctly passed |
| **F1 Score** | Harmonic mean of precision and recall |
| **Confusion Matrix** | TP / TN / FP / FN counts |
| **Items Hidden** | Count of prompts auto-hidden by FIDES middleware |
| **By Attack Type** | Detection rate broken down by attack category |

The saved JSON report additionally includes `fides_stats` with per-prompt variable IDs and middleware event logs.

---

## FIDES Core Concepts

### Content Labels

Every piece of content carries a two-dimensional security label:

| Dimension | Values | Default for external input |
|---|---|---|
| **Integrity** | `trusted` / `untrusted` | `untrusted` |
| **Confidentiality** | `public` / `private` / `user_identity` | `private` |

### Automatic Content Hiding

When the FIDES middleware receives `UNTRUSTED` content, it:

1. Stores the raw text in a `VariableStore` under a generated ID (e.g. `var_a3f9c12b`).
2. Returns an opaque `VariableReference` token to the caller instead of the raw text.
3. The main LLM context only ever contains `[UNTRUSTED_CONTENT_REF: var_a3f9c12b]`.

The main LLM is therefore **structurally incapable** of being manipulated by the hidden content.

### Quarantine LLM

When the agent needs to classify hidden content, it calls `quarantined_llm()`:

- Retrieves raw content from the variable store.
- Calls the LLM with a purpose-built **quarantine system prompt** that explicitly frames the content as untrusted data to analyse, never as instructions to follow.
- The quarantine LLM has no tool access and cannot affect any external system.
- Any injection attempts inside the payload are treated as literal text for analysis.

### Classification result

```json
{
  "internal_analysis_scratchpad": "step-by-step reasoning...",
  "is_malicious": true,
  "confidence_score": 0.95,
  "attack_types": ["Roleplay & Virtualization"],
  "flagged_paths": ["user_input"],
  "severity": "HIGH",
  "fides_metadata": {
    "var_id": "var_a3f9c12b",
    "content_hidden": true,
    "integrity_label": "untrusted",
    "confidentiality_label": "private",
    "processing": "quarantine_isolation"
  }
}
```
