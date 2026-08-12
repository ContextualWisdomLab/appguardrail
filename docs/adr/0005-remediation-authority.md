# ADR-0005: Limit deterministic autofix to proven semantics-preserving transforms

**Status:** Accepted  
**Date:** 2026-08-09

AppGuardrail may automatically preview/apply only transformations whose behavior preservation is narrowly defined and regression-tested for the detector class. Security fixes that change application behavior, routing, authorization, persistence, or business semantics remain reviewable guidance/patches and become accepted only after the target detector and relevant application tests pass again.