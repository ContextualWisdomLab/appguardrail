### Changed

- Skip the duplicate local Trivy filesystem scan on pull requests targeting the default branch, where the central required Security Scan already covers vulnerabilities, secrets, and misconfigurations; retain the local scan for pushes and pull requests targeting other branches.
