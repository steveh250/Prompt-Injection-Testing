# Architecture — FIDES Content Labelling + Quarantine Isolation

## Overview

The FIDES (Foundational Integration Defense for Execution Security) approach to prompt injection defence is fundamentally different from the Ollama inline approach. Rather than asking an LLM to detect attacks by reading raw content, FIDES **prevents injection structurally** by ensuring the main LLM never receives untrusted content in a form it can act on.

The core insight: if the main agent's LLM context never contains the raw payload, it cannot be manipulated by it. Classification still happens — but in a quarantined, isolated sub-call where the attack surface is minimised.

Reference: [microsoft/agent-framework — security sample](https://github.com/microsoft/agent-framework/tree/main/python/samples/02-agents/security)

---

## Component Diagram

```mermaid
graph TD
    INPUT["External Input\n(untrusted — e.g. RFP requirement, user prompt)"]

    subgraph MIDDLEWARE["FIDES Middleware (auto_hide_untrusted=True)"]
        LABEL["Apply ContentLabel\nintegrity: UNTRUSTED\nconfidentiality: PRIVATE"]
        STORE["VariableStore\nStore raw content under var_xxxxxxxx"]
        REF["Return VariableReference\n[UNTRUSTED_CONTENT_REF: var_xxxxxxxx]"]
    end

    MAIN_AGENT["Main Agent Context\nReceives only the opaque reference token\nNever sees raw payload"]

    subgraph QUARANTINE["Quarantine LLM Call"]
        RETRIEVE["Retrieve raw content\nfrom VariableStore"]
        QPROMPT["Quarantine System Prompt\n• Isolation framing\n• Content = data, not instructions\n• No tool access\n• 7 threat categories"]
        QLABEL["User message wraps content\nas UNTRUSTED DATA block"]
        QLLM["Ollama LLM\ngranite4:latest\nTemperature 0.1"]
    end

    subgraph OUTPUT["Classification Result"]
        RESULT["{\n  is_malicious: bool\n  confidence_score: 0.0–1.0\n  attack_types: [...]\n  severity: CRITICAL|HIGH|MEDIUM|LOW|NONE\n  fides_metadata: { var_id, content_hidden, ... }\n}"]
    end

    POLICY["Policy Enforcement\nBlock / allow downstream\nagent actions based on verdict"]

    INPUT --> MIDDLEWARE
    MIDDLEWARE --> LABEL --> STORE --> REF
    REF --> MAIN_AGENT
    MAIN_AGENT -->|"calls quarantined_llm(var_id)"| QUARANTINE
    QUARANTINE --> RETRIEVE --> QLABEL
    QLABEL --> QPROMPT
    QPROMPT --> QLLM --> OUTPUT
    OUTPUT --> POLICY
```

---

## Data Flow

```
External input arrives (integrity = UNTRUSTED by default)
    │
    ▼
FIDESMiddleware.process_incoming()
    │   raw content → VariableStore["var_a3f9c12b"] = "<raw text>"
    │   returns VariableReference("[UNTRUSTED_CONTENT_REF: var_a3f9c12b]")
    │
    ▼
Main LLM context (the main agent)
    │   Only sees: [UNTRUSTED_CONTENT_REF: var_a3f9c12b]
    │   Cannot be influenced by the hidden payload
    │
    ▼
FIDESAgent calls quarantined_llm(client, raw_content, var_id)
    │   System prompt: quarantine isolation framing
    │   User message: content wrapped as "UNTRUSTED DATA BLOCK"
    │   LLM has: no tools, no external access
    │
    ▼
Quarantine LLM returns JSON classification
    │
    ▼
Result annotated with fides_metadata (var_id, content_hidden, labels)
    │
    ▼
Policy enforcement (downstream tools blocked if verdict = malicious)
```

---

## Key Components

### ContentLabel

A two-dimensional security label attached to every piece of content flowing through the system.

| Dimension | Values | Purpose |
|---|---|---|
| **Integrity** | `trusted` / `untrusted` | Controls whether content is hidden |
| **Confidentiality** | `public` / `private` / `user_identity` | Controls where content may flow |

All external/user input defaults to `UNTRUSTED / PRIVATE` — the secure-by-default posture.

### VariableStore

An in-memory dictionary mapping generated variable IDs to `(raw_content, ContentLabel)` pairs. The variable ID is the only token that escapes into the main LLM context. The raw content never does.

```
VariableStore._store = {
    "var_a3f9c12b": ("Ignore all previous instructions...", ContentLabel(UNTRUSTED, PRIVATE)),
    "var_d91e4700": ("Calculate 5 * 7.", ContentLabel(UNTRUSTED, PRIVATE)),
}
```

### FIDESMiddleware

Intercepts all incoming content and applies the auto-hiding policy:

- If `integrity == UNTRUSTED` and `auto_hide_untrusted == True` → content is stored, reference returned.
- If `integrity == TRUSTED` → content passes through unchanged.
- Every hiding event is logged to `middleware.events` for auditability.

### quarantined_llm()

The isolation-layer LLM call. Key properties:

- **No tool access** — the LLM cannot call external APIs, read files, or take any action.
- **Explicit data framing** — the user message wraps the content between `--- BEGIN UNTRUSTED CONTENT ---` and `--- END UNTRUSTED CONTENT ---` markers, with explicit instruction that anything inside is data, not a directive.
- **Quarantine system prompt** — separate from the main agent's system prompt; establishes the observer role before the content is shown.
- **Same JSON output schema** as the Ollama agent — enables direct metric comparison.

### Quarantine System Prompt (summary)

The quarantine system prompt differs from the Ollama agent's in one critical way: it explicitly tells the LLM it is inside an isolated container with no external capabilities, and that ANY instruction found inside the content is a threat indicator, not a command. This additional framing makes it significantly harder for a sophisticated injection to co-opt the classifier's reasoning.

---

## Comparison with Ollama Approach

| Dimension | Ollama Agent | FIDES Agent |
|---|---|---|
| **Main LLM sees raw payload** | Yes | Never |
| **Injection vector** | Possible — LLM reasons over raw attack | Structurally closed — main LLM has no payload |
| **Defence type** | Probabilistic (LLM judgment) | Structural (content hiding) + probabilistic (quarantine LLM) |
| **Quarantine isolation** | No | Yes — separate LLM call, no tools, data framing |
| **Scratchpad reasoning** | Yes | Yes (in quarantine LLM) |
| **Output schema** | `{is_malicious, confidence, attack_types, severity}` | Same + `fides_metadata` |
| **Audit trail** | Per-node results + full-structure result | Middleware events + variable store log |

---

## Threat Model

### What FIDES prevents structurally

- **Direct prompt injection into the main agent** — the main LLM never receives the raw payload, so it cannot follow instructions embedded in it.
- **Privilege escalation via external content** — untrusted content cannot instruct the main agent to call restricted tools or expose private data.

### Remaining risk surface

| Risk | Detail |
|---|---|
| **Quarantine LLM susceptibility** | The quarantine LLM still receives the raw payload. An extremely sophisticated jailbreak could theoretically confuse it into reporting benign. The isolation framing and no-tool constraint substantially reduce but do not eliminate this. |
| **Variable store trust boundary** | Content is retrieved from the variable store and passed to the quarantine LLM in plaintext. If the store were compromised, the isolation guarantee would break. |
| **Label spoofing** | In a fuller FIDES implementation, labels propagate through tool calls with anti-spoofing controls. In this test harness, labels are assigned at ingestion only. |

---

## Configuration

| Constant | Default | Description |
|---|---|---|
| `OLLAMA_MODEL_ID` | `granite4:latest` | Ollama model used by the quarantine LLM |
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1/` | Ollama API endpoint |
| `auto_hide_untrusted` | `True` | Whether middleware hides UNTRUSTED content automatically |
| `temperature` | `0.1` | LLM sampling temperature (quarantine call) |
