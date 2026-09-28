# v0.1.0 publication record

Published on 2026-09-28. These are launch records, not evidence of reach or endorsement.

- [Experimental GitHub release](https://github.com/mirogate/mirogate-boundary/releases/tag/v0.1.0): source distribution, wheel and SHA-256 checksums; release commit `725b2fa72d5b91aea0444b8d5d3ea13c528b5faa`.
- [Medium article by Mirogate](https://medium.com/@mirogate/mirogate-boundary-testing-the-data-we-send-to-ai-92e8c1ca1e0d): the source HTML is [medium-article.html](medium-article.html). Topics: Artificial Intelligence, Open Source, Data Privacy, NLP and Arabic.
- [LinkedIn announcement by Mirogate](https://www.linkedin.com/feed/update/urn:li:share:7510434346437275648/): published from the Mirogate company page. The source text is [linkedin-post.txt](linkedin-post.txt). Public audience; includes repository and article links.

## Verification evidence

- [Release-source test matrix](https://github.com/mirogate/mirogate-boundary/actions/runs/36477806550): all four Ubuntu/Windows and Python 3.11/3.13 jobs passed, with 80 tests per job.
- [Actual Linux CPU model evaluation](https://github.com/mirogate/mirogate-boundary/actions/runs/36476642007): pinned Privacy Filter and hybrid runs; raw reports and caveats are in [evaluation.md](../docs/evaluation.md).
- The built wheel was installed into a separate target directory and exercised with synthetic input.

No paid ads, paid-provider inference, PyPI upload or customer-data upload was performed. The Windows model attempt was blocked by Application Control; host security settings were not changed. The model metrics come from the separate Linux evaluation.
