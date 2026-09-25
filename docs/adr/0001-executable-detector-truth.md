# ADR-0001: Detection truth must come from executable evidence

**Status:** Accepted  
**Date:** 2026-08-09

## Context

A security registry, issue record, or fixture can state that a vulnerability should exist, but consuming that statement as the detector result creates circular assurance.

## Decision

A finding/obligation result is produced only by actual detector logic over answer-free bounded evidence or authenticated structured workflow evidence. Registries map requirements to detector families and evidence sources; they do not assert pass/fail themselves.

## Consequences

Issue-to-detector coverage must execute real detector adapters. Unknown/untrusted evidence is inconclusive/fail-closed. Audit tests must prevent registry-derived fake “live” inventories or expected-answer fixture fields from satisfying the contract.

## References

Joint Task Force. (2022). *Assessing security and privacy controls in information systems and organizations* (NIST SP 800-53A Rev. 5). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-53Ar5

Scarfone, K. A., Souppaya, M. P., Cody, A., & Orebaugh, A. D. (2008). *Technical guide to information security testing and assessment* (NIST SP 800-115). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-115