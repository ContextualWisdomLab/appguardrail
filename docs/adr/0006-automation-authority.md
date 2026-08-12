# ADR-0006: Separate autonomous development from independent review, merge, and release authority

**Status:** Accepted  
**Date:** 2026-08-09

Autonomous development may perform RCA, create test-first source changes, run credential-free verification, and publish ordinary reviewable work through bounded trusted tooling. It cannot manufacture a qualifying approval, bypass required checks, force protected merge, tag, or publish. Model-provider credentials and reviewer/merge/release credentials remain separate identities/scopes.