# Contributing

Start with `python -m pip install -e .` and `python -m unittest discover -s tests -v` on Python 3.11 or newer. Core tests use only the standard library. See docs/model-setup.md for optional model tests.

Keep detector improvements separate from benchmark expectations. A new case needs a synthetic origin, family, exact Unicode code-point offsets and a short rationale. Record failures instead of deleting hard cases or relabelling them to improve a score. Do not tune detectors against a newly labelled holdout and then call the same set independent validation.

Contributions we want first:

1. Arabic and mixed-language false negatives/false positives, including dialectal labels, Unicode edge cases and contextual names.
2. Independently reproduced, pinned local-model runs with environment and timing information.
3. Adversarial tests of schema validation, forwarding, credential isolation, restoration and failure handling.
4. Separately designed adapters that preserve the same explicit supported-input contract.

Use reserved domains and clearly synthetic values. Do not upload customer data, screenshots containing private records, active credentials or identifying incident logs. Report potential vulnerabilities through the private channel in SECURITY.md where available.

Pull requests should explain the behavior, tests, compatibility impact and remaining limitations. By submitting, you agree your contribution is licensed under Apache-2.0.
