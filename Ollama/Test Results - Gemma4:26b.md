# Summary Test Results - Gemma4:26b

```
======================================================================
  SECURITY AGENT TEST RESULTS SUMMARY
======================================================================
  Test Run:           2026-06-14 21:31:12
  Elapsed Time:       9095.4s (151.6 minutes)
  Prompts Tested:     500

  --- Dataset Composition ---
  Malicious Prompts:  250
  Benign Prompts:     250

  --- Classification Results ---
  Correct:            498/500 (99.6%)
  Incorrect:          2/500

  --- Confusion Matrix ---
  True Positives  (malicious correctly detected):  248
  True Negatives  (benign correctly passed):       250
  False Positives (benign wrongly flagged):        0
  False Negatives (malicious missed):              2

  --- Performance Metrics ---
  Accuracy:           99.6%
  Precision:          100.0%
  Sensitivity/Recall: 99.2%  (malicious detection rate)
  Specificity:        100.0%  (benign pass-through rate)
  F1 Score:           99.6%

  --- Detection by Attack Type ---
  code_execution      : 146/146 detected (100%)
  data_leakage        : 17/18 detected (94%)
  jailbreaking        : 17/17 detected (100%)
  obfuscation         : 60/61 detected (98%)
  role_playing        : 8/8 detected (100%)

  --- Missed Threats (False Negatives) ---
  data_leakage: pi-015
  obfuscation: pi-035

======================================================================

INFO:__main__:Detailed results saved to: /home/ubuntu/MAF/SecurityAgent/security_test_results_20260614_213112.json
```


