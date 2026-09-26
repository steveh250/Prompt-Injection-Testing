# Additional Test Datasets

The main dataset for all harnesses is the Kaggle set in the repository root
(`security_agent-Prompt_INJECTION_And_Benign_DATASET.jsonl`, 500 prompts). This folder holds
scripts that fetch **other** datasets and convert them to the same JSONL format, so every
harness can run them unchanged with `--dataset`.

## rogue-security/prompt-injections-benchmark

[`rogue-security/prompt-injections-benchmark`](https://huggingface.co/datasets/rogue-security/prompt-injections-benchmark)
(formerly `qualifire/prompt-injections-benchmark`) has **5,000 prompts, labelled `jailbreak` or `benign`**.
Its publisher states that no model was trained on it, and it focuses on complex jailbreaks and
long benign prompts. That makes it a hard test of **false positives**, and an independent check
of the Jev-Tuned severity rule, which was tuned on the Kaggle set.

### Ready to use

The dataset is already in the repository root:

| File | Contents |
|---|---|
| `prompt-injections-benchmark.csv` | the original export (`text,label`): **5,000 prompts, 3,001 benign and 1,999 jailbreak** |
| `prompt-injections-benchmark.jsonl` | the same prompts converted to the Kaggle format for the harnesses (ids `rs-0001`…, shuffled with seed 42) |

Prompts are much longer than in the Kaggle set: the median is 615 characters, and the longest is
11,977 characters (about 3,000 tokens, within Jev's limit).

To regenerate the JSONL from the CSV:

```bash
cd Datasets
python fetch_rogue_benchmark.py --csv ../prompt-injections-benchmark.csv --output ../prompt-injections-benchmark.jsonl
```

### Fetch and convert from Hugging Face

```bash
cd Datasets
pip install datasets
python fetch_rogue_benchmark.py
```

If the download is refused because the dataset is gated, accept its terms on the
Hugging Face page, create an access token (Settings → Access Tokens), and run
`export HF_TOKEN=hf_...` before re-running.

The script:
- prints the columns and **label mapping** it used (e.g. `'jailbreak' -> malicious`). Check
  this before running a harness.
- writes `rogue-security-prompt-injections-benchmark.jsonl` in the Kaggle format:
  - ids are `rs-0001`…;
  - `attack_type` is `jailbreak` or `none`, since the dataset has no finer categories;
  - entries are shuffled with a fixed seed (`--seed`, default 42), so `--limit N` in a harness
    takes a mix of both classes.
- prints the class counts and prompt lengths.

`--text-column` / `--label-column` override the auto-detected columns if needed.

Files the script writes into `Datasets/` are **git-ignored**; the committed copy is the one in
the repository root.

### Run the harnesses on it

```bash
cd Jev-Tuned        # or Jev, Ollama, MAF-FIDES
python test_security_agent.py --dataset ../prompt-injections-benchmark.jsonl --limit 20   # quick test
python test_security_agent.py --dataset ../prompt-injections-benchmark.jsonl             # all 5,000
```

Approximate cost and time for all 5,000 prompts, based on the Kaggle runs:

| Harness | Time | Cost |
|---|---|---|
| Jev / Jev-Tuned | ~10 minutes | ~$0.25, possibly more (long prompts cost more input tokens) |
| Granite4:3b (Ollama) | ~9 hours | local |
| Gemma4:26b (Ollama) | ~25 hours | local |

Notes:
- **Context line:** every harness wraps each prompt with the RFP context line (*"This is a
  single input field from an RFP requirements document."*), as in the Kaggle runs. The Jev
  harnesses also accept `--context "..."`, for example to describe a general-purpose
  assistant. That may matter here, because these are general chat prompts.
- **Jev's input limit:** Jev accepts at most 32k tokens of state per request. Any extremely long
  prompt that exceeds it will be listed as an **error** in the Jev harnesses, not scored.
