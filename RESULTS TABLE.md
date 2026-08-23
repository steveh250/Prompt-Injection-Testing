# Summary Results

As I have tested more models within the harness and tools like Micrososft MAF-FIDES I decided to start to track the results to see if the same harness, with the same Kaggle dataset (250 benign and 250 malicious prompts) produce different results (in the case of my harness, with the same prompt).

There are lots more details in the results - this is just a summary of the more interesting ones.


|Model      |False Positives|Correct        |Incorrect|Code Execution         |Data Leakage         |Jailbreaking         |Obfuscation         |Role Playing       |
|-----------|---------------|---------------|---------|-----------------------|---------------------|---------------------|--------------------|-------------------|
|Gemma4:26b |0              |498/500 (99.6%)|2/500    |146/146 detected (100%)|17/18 detected (94%) |17/17 detected (100%)|60/61 detected (98%)|8/8 detected (100%)|
|Granite4:3b|0              |491/500 (98.2%)|9/500    |143/146 detected (98%) |18/18 detected (100%)|12/17 detected (71%) |60/61 detected (98%)|8/8 detected (100%)|
|MAF-FIDES  |2              |451/500 (90.2%)|49/500   |122/146 detected (84%) |15/18 detected (83%) |17/17 detected (100%)|41/61 detected (67%)|8/8 detected (100%)|
|LFM2.5 350M|0              |250/500 (50.0%)|250/500  |0/146 detected (0%)    |0/18 detected (0%)   |0/17 detected (0%)   |0/61 detected (0%)  |0/8 detected (0%)  |

* False Positives: Benign prompts marked as Malicious - interesting because they impact people using legitimate prompts.
* Correct and Incorrect: Overall scores
* Attack type breakdown: Code Execution, Data Leakage, Jailbreaking, Obfuscation, Role Playing

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
