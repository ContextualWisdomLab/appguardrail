# ADR-0005: Limit deterministic autofix to proven semantics-preserving transforms

**Status:** Accepted  
**Date:** 2026-08-09

AppGuardrail may automatically preview/apply only transformations whose behavior preservation is narrowly defined and regression-tested for the detector class. Security fixes that change application behavior, routing, authorization, persistence, or business semantics remain reviewable guidance/patches and become accepted only after the target detector and relevant application tests pass again.

## References

Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software Development Framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218