### Security

- Bind PyPI publication to the exact current protected `develop` tip, rejecting manual runs from other refs and version/tag mismatches before Trusted Publishing can mint upload authority.
- Smoke-install the built wheel in a fresh virtual environment outside the source checkout and verify the installed CLI, scanner rules, and dashboard assets before publication.
- Add the bounded HIGH `github-actions-pypi-unbound-release-source` scanner rule and immutable protected/#967 workflow corpus. Detect missing same-job, pre-build fail-closed protected-source binding without claiming external PyPI exploit success; document supported syntax and FP/FN boundaries.
