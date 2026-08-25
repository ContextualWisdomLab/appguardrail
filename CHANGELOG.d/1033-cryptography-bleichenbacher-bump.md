### Changed

- The hash-pinned release lock now resolves `cryptography==50.0.0`, leaving the Bleichenbacher PKCS#7 EnvelopedData oracle window (`>=44,<50`) reported by Dependabot alert #1; the lock was regenerated with the documented `uv pip compile --generate-hashes` command plus a targeted `--upgrade-package cryptography` (#1033).
