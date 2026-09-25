### Changed

- Skip the duplicate local Trivy filesystem scan on code-changing pull requests targeting the default branch, where the central required Security Scan already covers vulnerabilities, secrets, and misconfigurations; retain the local fallback for documentation/image-only pull requests, pushes, and pull requests targeting other branches.
