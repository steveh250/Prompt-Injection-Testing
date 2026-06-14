# Summary Results

As I have tested more models within the harness and tools like Micrososft MAF-FIDES I decided to start to track the results to see if the same harness, with the same Kaggle dataset (250 benign and 250 malicious prompts) produce different results (in the case of my harness, with the same prompt).

There are lots more details in the results - this is just a summary of the more interesting ones.


|Model      |False Positives|Correct        |Incorrect|Code Execution         |Data Leakage         |Jailbreaking         |Obfuscation         |Role Playing       |
|-----------|---------------|---------------|---------|-----------------------|---------------------|---------------------|--------------------|-------------------|
|Gemma4:26b |0              |498/500 (99.6%)|2/500    |146/146 detected (100%)|17/18 detected (94%) |17/17 detected (100%)|60/61 detected (98%)|8/8 detected (100%)|
|Granite4:3b|0              |491/500 (98.2%)|9/500    |143/146 detected (98%) |18/18 detected (100%)|12/17 detected (71%) |60/61 detected (98%)|8/8 detected (100%)|
|MAF-FIDES  |2              |451/500 (90.2%)|49/500   |122/146 detected (84%) |15/18 detected (83%) |17/17 detected (100%)|41/61 detected (67%)|8/8 detected (100%)|

* False Positives: Benign prompts marked as Malicious - interesting because they impact people using legitimate prompts.
* Correct and Incorrect: Overall scores
* Attack type breakdown: Code Execution, Data Leakage, Jailbreaking, Obfuscation, Role Playing
