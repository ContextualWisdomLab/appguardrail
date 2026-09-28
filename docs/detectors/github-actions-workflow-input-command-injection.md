# GitHub Actions workflow-input command-injection detector

**Status:** Source-derived detector slice  
**Rule ID:** `github-actions-workflow-input-command-injection`  
**Primary weakness classes:** CWE-78, CWE-94  
**Collected issue:** AppGuardrail issue #552  
**Source change:** `ContextualWisdomLab/.github` reusable `deploy-pages.yml`; vulnerable head `2b034ac27d90487b4b0df3aea9d3fdc355e97296` and blob `f86b614022a658702ce3c6032ff61ffe4658adde`; reviewed fixed head `5999b2bdbd32a362b01b8553f1ee2a1d7f45e5da` and blob `118816bd7156472baa0cc011cd6e8a4d68b7ff22`

## Buyer-visible protection

A reusable or manually dispatched workflow can accept caller-controlled string inputs. GitHub evaluates `${{ ... }}` expressions before a `run` program reaches its shell or script interpreter. Directly interpolating an input into `run` therefore lets quotes, separators, substitutions, or newlines become part of executable source rather than ordinary data.

The collected central workflow inserted reusable-workflow inputs into Cloudflare deployment commands and shell summary or domain-management steps. A caller able to choose those strings could alter runner commands and potentially reach repository credentials, workflow secrets, generated artifacts, or deployment state. AppGuardrail reports the proven source shape as a deploy-blocking CRITICAL finding.

## Detection contract

The lightweight detector requires all of the following evidence in one `.github/workflows/*.yml` or `.yaml` file:

1. `workflow_call` or `workflow_dispatch` declares an `inputs` mapping;
2. one named input is explicitly declared with YAML type `string`;
3. the same input name is referenced through `inputs.name` or `inputs['name']`;
4. that expression occurs directly in an inline, literal, or folded `run` program;
5. the declaration and sink occur within bounded source windows.

The detector accepts quoted YAML keys, legal whitespace around mapping colons, dot and bracket input access, expression fallbacks, and legal blank lines in the bounded input metadata and `run` block. File-level prefilters use lexical tokens shared by those grammar variants rather than formatting-specific literals.

The input declaration and the interpolated expression are name-bound. A different string input elsewhere in the workflow does not taint a boolean input used by the shell step.

## Source-authoritative evidence corpus

`tests/test_github_actions_workflow_input_injection_rules.py` preserves:

- the exact vulnerable central-workflow blob;
- the exact reviewed fixed blob;
- immutable repository, head, and Git-blob identities;
- direct inline-shell interpolation;
- literal and folded run blocks;
- dot and bracket input access;
- `workflow_call` and `workflow_dispatch`;
- quoted and whitespace-varied YAML keys;
- legal blank lines inside input metadata and run blocks;
- expression fallback syntax;
- a safe step-level environment-variable boundary;
- an action `with:` input that is not inline shell source;
- expressions in `name` and `if` outside `run`;
- a non-string input;
- a separate string input plus interpolated boolean input;
- path scoping outside `.github/workflows`;
- the production `_scan_file` finding envelope, including line, CRITICAL severity, category, confidence, CWE, and OWASP metadata.

The first test-only commit `8bc9ecc226f99e3f0cfb1f6064738e2b10df8be1` produced hosted Tests run `31936994435`: Python 3.11 and 3.13 failed because the packaged detector did not yet exist, while 1,004 pre-existing tests passed. The second test-first commit `40e7b3b015ea97d212e8c4fdab3b037bdeca38b6` produced hosted Tests run `31940187012`: both Python versions reproduced four grammar bypasses while 1,016 tests passed. Production repairs followed those RED states.

## Remediation boundary

A complete repair keeps untrusted data separate from interpreter source:

1. evaluate the GitHub expression into a step-level environment variable;
2. reference the environment variable with the target interpreter's native variable syntax;
3. quote native variable expansion according to that interpreter;
4. apply a strict allowlist when the operation accepts a restricted grammar such as a project name, path, domain, tag, or release identifier;
5. prefer a pinned action's structured `with:` input when no inline interpreter is required;
6. keep workflow permissions and exposed secrets at the minimum required scope;
7. avoid reflecting rejected input values into logs or workflow summaries.

For shell steps, `${{ env.NAME }}` inside `run` is not equivalent to native `$NAME` expansion. It is still GitHub expression interpolation before the temporary script executes.

## Declared limitations

This is not a general GitHub Actions taint or YAML dataflow engine. It intentionally does not claim coverage for:

- untrusted `github.*`, `env.*`, `vars.*`, `secrets.*`, matrix, step-output, job-output, or event-payload contexts;
- inputs copied through intermediate environment variables and later re-interpolated with `${{ env.NAME }}`;
- reusable workflows whose input declaration and shell sink are split across files;
- composite actions, JavaScript actions, Docker actions, or generated workflows;
- dynamically constructed input keys;
- shell source assembled through files, outputs, heredoc producers, templates, or helper actions;
- action `with:` values whose receiving action is itself vulnerable;
- non-string values that are converted to attacker-controlled strings elsewhere;
- arbitrary interpreter-specific semantic validation beyond direct expression placement.

Those cases require separate source-derived detector obligations or structural interprocedural analysis. Expanding this bounded regex without a real vulnerable source, a reviewed fixed negative, and independent grammar or semantic controls is prohibited.

## APA 7 references

GitHub. (2026). *Script injections*. GitHub Docs. https://docs.github.com/en/actions/concepts/security/script-injections

MITRE Corporation. (2026). *CWE-78: Improper neutralization of special elements used in an OS command ('OS command injection')* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/78.html

MITRE Corporation. (2026). *CWE-94: Improper control of generation of code ('Code injection')* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/94.html

OWASP Foundation. (2021). *A03:2021—Injection*. https://owasp.org/Top10/2021/A03_2021-Injection/
