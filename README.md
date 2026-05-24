# Prompt Injection Testing

## Purpose

This repository tests and compares different approaches to defending AI agents against **prompt injection attacks** — malicious instructions embedded in external content (documents, emails, API responses) that try to hijack an LLM's behaviour.

The research originated from the **RFP Responder** multi-agent solution, which extracts requirements from RFP documents and submits them to an LLM for answering. Adversaries could embed prompt injection payloads inside those documents, making the security of the extraction pipeline critical.

---

## Repository Structure

```
Prompt-Injection-Testing/
├── README.md                                          # This file
├── DATASET.md                                         # Dataset documentation
├── security_agent-Prompt_INJECTION_And_Benign_DATASET.jsonl  # Shared test dataset
├── Ollama/                                            # LLM-based inline security agent
│   ├── README.md
│   ├── ARCHITECTURE.md
│   ├── security_agent.py
│   └── test_security_agent.py
└── MAF-FIDES/                                         # FIDES content-labelling approach
    ├── README.md
    ├── ARCHITECTURE.md
    ├── fides_security_agent.py
    ├── test_fides_agent.py
    └── requirements.txt
```

---

## Shared Dataset

`security_agent-Prompt_INJECTION_And_Benign_DATASET.jsonl`

A curated dataset of **500 labelled prompts** (250 malicious, 250 benign) used by both test harnesses to enable direct comparison.

| Field | Description |
|---|---|
| `id` | Unique identifier (e.g. `pi-001`) |
| `prompt` | The raw text to classify |
| `label` | `malicious` or `benign` |
| `attack_type` | `code_execution`, `obfuscation`, `jailbreaking`, `data_leakage`, `role_playing`, or `none` |
| `context` | Human-readable description of the attack or query |
| `response` | Expected agent response |

**Attack type distribution:**

| Attack Type | Count |
|---|---|
| code_execution | 146 |
| obfuscation | 61 |
| data_leakage | 18 |
| jailbreaking | 17 |
| role_playing | 8 |
| none (benign) | 250 |

---

## Approaches Compared

### 1. Ollama — Inline LLM Security Agent

**Folder:** `Ollama/`

An inline security sentinel that sends each piece of content directly to a local Ollama-hosted LLM (Granite 4) and asks it to classify the payload as malicious or benign.

- The LLM receives the raw content and applies a detailed threat-detection system prompt.
- Two-phase analysis: per-node scan + full-structure scan for split-payload attacks.
- Output: `is_malicious`, `confidence_score`, `severity`, `attack_types`.

See [`Ollama/README.md`](Ollama/README.md) and [`Ollama/ARCHITECTURE.md`](Ollama/ARCHITECTURE.md).

---

### 2. MAF-FIDES — Content Labelling + Quarantine Isolation

**Folder:** `MAF-FIDES/`

An implementation of Microsoft's **FIDES** (Foundational Integration Defense for Execution Security) approach from the [Microsoft Agent Framework](https://github.com/microsoft/agent-framework/tree/main/python/samples/02-agents/security).

Rather than asking an LLM to detect attacks in raw content, FIDES **prevents** injection structurally:

- All external input is labelled `UNTRUSTED`.
- A middleware layer **hides** untrusted content behind an opaque variable reference before it reaches the main LLM.
- The main LLM never sees raw untrusted text; it only sees `[UNTRUSTED_CONTENT_REF: var_xxxxxxxx]`.
- When classification is needed, the agent calls a `quarantined_llm` tool that processes the hidden content in complete isolation with no tool access.

See [`MAF-FIDES/README.md`](MAF-FIDES/README.md) and [`MAF-FIDES/ARCHITECTURE.md`](MAF-FIDES/ARCHITECTURE.md).

---

## Key Distinction Between Approaches

| Dimension | Ollama Approach | FIDES Approach |
|---|---|---|
| **Defence mechanism** | Probabilistic detection (LLM judgment) | Structural prevention (content hiding) |
| **Raw content seen by main LLM** | Yes | Never |
| **Injection vector** | LLM may be tricked by clever payloads | Structurally impossible (main LLM has no raw content) |
| **Classification method** | Direct LLM analysis with security system prompt | Quarantine LLM with isolation framing |
| **False negative risk** | Higher — LLM may fail on novel attacks | Lower — quarantine framing reduces susceptibility |
| **False positive risk** | Moderate | Moderate |
| **Explainability** | Full scratchpad reasoning in output | Full scratchpad reasoning from quarantine LLM |

---

## Running the Comparisons

Both harnesses produce the same set of metrics (accuracy, precision, recall, F1, confusion matrix) from the same dataset, making results directly comparable.

```bash
# Ollama approach
cd Ollama
python test_security_agent.py --limit 20        # quick test
python test_security_agent.py                   # full 500-prompt run

# FIDES approach
cd MAF-FIDES
pip install -r requirements.txt
python test_fides_agent.py --limit 20           # quick test
python test_fides_agent.py                      # full 500-prompt run
```

Both scripts accept `--limit N`, `--start N`, and `--output path/to/results.json`.

---

## Prerequisites

- **Ollama** running locally at `http://localhost:11434`
- **Granite 4** model pulled: `ollama pull granite4:latest`
- Python 3.11+, `pip install openai`
