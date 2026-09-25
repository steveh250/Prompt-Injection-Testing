# Summary Results

As I have tested more models within the harness and tools like Micrososft MAF-FIDES I decided to start to track the results to see if the same harness, with the same Kaggle dataset (250 benign and 250 malicious prompts) produce different results (in the case of my harness, with the same prompt).

There are lots more details in the results - this is just a summary of the more interesting ones.


|Model      |False Positives|Correct        |Incorrect|Code Execution         |Data Leakage         |Jailbreaking         |Obfuscation         |Role Playing       |
|-----------|---------------|---------------|---------|-----------------------|---------------------|---------------------|--------------------|-------------------|
|Gemma4:26b |0              |498/500 (99.6%)|2/500    |146/146 detected (100%)|17/18 detected (94%) |17/17 detected (100%)|60/61 detected (98%)|8/8 detected (100%)|
|Granite4:3b|0              |491/500 (98.2%)|9/500    |143/146 detected (98%) |18/18 detected (100%)|12/17 detected (71%) |60/61 detected (98%)|8/8 detected (100%)|
|MAF-FIDES  |2              |451/500 (90.2%)|49/500   |122/146 detected (84%) |15/18 detected (83%) |17/17 detected (100%)|41/61 detected (67%)|8/8 detected (100%)|
|LFM2.5 350M|0              |250/500 (50.0%)|250/500  |0/146 detected (0%)    |0/18 detected (0%)   |0/17 detected (0%)   |0/61 detected (0%)  |0/8 detected (0%)  |
|Jev 1.13   |0              |461/500 (92.2%)|39/500   |130/146 detected (89%) |18/18 detected (100%)|16/17 detected (94%) |39/61 detected (64%)|8/8 detected (100%)|
|Jev 1.13 Tuned*|0           |500/500 (100%) |0/500    |146/146 detected (100%)|18/18 detected (100%)|17/17 detected (100%)|61/61 detected (100%)|8/8 detected (100%)|

* False Positives: Benign prompts marked as Malicious - interesting because they impact people using legitimate prompts.
* Correct and Incorrect: Overall scores
* Attack type breakdown: Code Execution, Data Leakage, Jailbreaking, Obfuscation, Role Playing
* \* Jev 1.13 Tuned: the verdict rule was tuned after seeing the Jev 1.13 results on this same dataset, so this row is not an independent result. See the note below.

## Note on the LFM2.5 350M run

At first glance the LFM2.5 350M row looks like a coin-flip (50% correct), which might suggest it caught roughly half of the attacks. It didn't. Digging into the raw results (`security_test_results_20260823_161335.json`) shows that **every one of the 500 prompts was classified as benign** - `detected_malicious` is `false` on all 500 records.

That means:

* **True Negatives (benign correctly passed): 250** - all of the "correct" results.
* **False Negatives (malicious missed): 250** - every attack prompt got through.
* **True Positives (malicious correctly caught): 0** - none.
* **False Positives: 0** - because it never flagged anything.

So the 50% accuracy is entirely an artefact of the dataset being an even 250/250 split: the model scores a perfect 100% on the benign half simply because it lets everything through, and 0% on the malicious half for the same reason. It is behaving as a "pass-everything" classifier, not a detector.

One thing that can be misleading in the raw file: most records (including missed attacks) have a populated `detected_attack_types` list. That field is *not* the verdict - the actual decision is the `detected_malicious` flag, which stays `false` throughout, so the harness correctly scores those prompts as missed. This is worth flagging because a very small model like this (350M parameters) appears to go through the motions of naming attack categories without ever committing to a malicious verdict.

Bottom line: 0% detection across all five attack categories. The row is accurate as shown.

## Note on the Jev 1.13 run

Jev (TypeSafe AI's decision model, run through OpenRouter) is hosted rather than local, and returns probabilities instead of text. The row above uses the default 0.5 threshold, which was fixed before the run.

* **Speed and cost:** all 500 prompts took **56.2 seconds** (p50 latency 103 ms) and cost **$0.024** in total, about $0.05 per 1,000 prompts. For comparison, the local runs took 12.1 minutes (MAF-FIDES) to 178.8 minutes (LFM2.5 350M) on different hardware.
* **Perfect ranking:** ROC-AUC was 1.0000. Every attack scored higher than every benign prompt. Benign prompts all scored 0.02–0.04; the lowest attack scored 0.16. 37 of the 39 misses scored 0.31–0.49, just under the threshold, and there were no false positives. Jev's severity score also rated every missed attack as MEDIUM to HIGH impact. A threshold of 0.1–0.3 would have scored 99.6–100%, but it was picked after seeing these results, so the table reports 0.5.
* **What it missed:** mostly bare shell commands with no manipulation language, such as fork bombs, `dd`, reverse shells and 22 `whoami | gzip | gunzip`-style obfuscation variants.

Full write-up: [`Jev/Test Results - Jev 1.13.md`](Jev/Test%20Results%20-%20Jev%201.13.md).

## Note on the Jev 1.13 Tuned run

A second Jev run with one change to the verdict: content is flagged if `p(is_malicious) ≥ 0.5` **or** Jev's severity score is LOW (1.0) or above. In the first run, Jev rated every missed attack at least LOW severity, while no benign prompt scored above 0.18.

* **Result:** 500/500 with 0 false positives. All 39 former misses were caught by the severity rule, and no correct verdict changed. Time (60.5 s) and cost ($0.024) were the same, because the severity answer was already in every request.
* **Margins:** benign severity scores peaked at 0.19; the lowest attack scored 1.40. Any severity threshold from 0.25 to 1.5 gives 100%.
* **Run-to-run variation:** Jev's probabilities moved by up to ±0.08 between the two runs, so which borderline attacks the untuned 0.5 rule catches changes from run to run. The severity signal stayed well clear of the threshold in both runs.
* **Caveat:** the rule was fitted to the first run's results, so 100% here is expected and doesn't show how it behaves on unseen data. The untuned 92.2% row remains the fair comparison with the other models. Testing on a different set of benign prompts is the next step.

Full write-up: [`Jev-Tuned/Test Results - Jev 1.13 Tuned.md`](Jev-Tuned/Test%20Results%20-%20Jev%201.13%20Tuned.md).
