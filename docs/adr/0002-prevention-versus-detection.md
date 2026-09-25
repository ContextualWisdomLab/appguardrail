# ADR-0002: Treat prevention and scanner detection as separate obligations

**Status:** Accepted  
**Date:** 2026-08-09

A vulnerable AppGuardrail endpoint can be hardened without making AppGuardrail capable of finding the same unsafe pattern in other software. Therefore product-control prevention and scanner detection are separately traceable and separately tested. A fixed webhook storage boundary does not satisfy stored-SSRF scanner coverage until an executable detector has positive and fixed negative target-code tests.

## References

Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure Software Development Framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218