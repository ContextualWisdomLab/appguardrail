# Mutable MultipartFile byte-array detector

**Status:** Source-derived detector slice  
**Rule ID:** `java-multipart-mutable-byte-array-exposure`  
**Primary weakness classes:** CWE-374, CWE-375  
**Collected issue:** AppGuardrail issue #551  
**Source change:** `ContextualWisdomLab/clearfolio` PR #239; vulnerable head `a44209e2cb743393ff41b17a59ba21fa546473ab` and blob `7bd4d0df252a9ecfde89b1b87cafb716130f8a69`; reviewed fixed head `ae0bc74d3ccc811da6d117443663170b2df189c4` and blob `c47cdd80a786bddddaacd2bb05a82b8b37e61114`

## Buyer-visible protection

A file wrapper that retains a caller-owned `byte[]` or returns its private array directly allows another component to change uploaded bytes after validation, hashing, deduplication, malware inspection, or policy decisions. The object may still look immutable because the field is `final`, while the array contents remain mutable. This can invalidate evidence, content identities, and downstream authorization or conversion decisions.

Clearfolio PR #239 attempted to remove both defensive copies as a memory optimization. The source PR was closed without merge after review established that the optimization exposed mutable aliasing across the multipart-file integrity boundary. AppGuardrail issue #551 records the related cancelled Strix run as provenance only; detector truth comes from the exact vulnerable source, the reviewed fixed source, and independent positive and negative tests.

## Detection contract

The lightweight detector requires the following evidence in one Java source file:

1. a class directly implements Spring's `MultipartFile` interface;
2. the class stores bytes in a `private final byte[]` field;
3. either the class constructor assigns a `byte[]` parameter directly to that field, including the collected nullable ternary form, or `getBytes()` returns the private field directly;
4. the evidence occurs inside bounded class, constructor, and method windows.

The detector reports either trust-boundary failure independently. Copying constructor input does not make a direct getter return safe, and returning a copy does not make retention of caller-owned input safe.

The rule is protected by the file-level prefilters `implements MultipartFile`, `private final byte[]`, and `getBytes`. These avoid evaluating the multiline expression for unrelated Java files.

## Source-authoritative evidence corpus

`tests/test_java_multipart_mutable_byte_array_rules.py` preserves:

- the exact vulnerable Clearfolio Java blob;
- the exact reviewed defensive-copy blob;
- a constructor-alias-only positive;
- a direct-getter-only positive;
- an equivalent `clone()`-based safe implementation;
- an unrelated byte-array holder outside the `MultipartFile` boundary;
- a `getBytes()` method that returns newly allocated bytes;
- immutable source repository, head, and blob identifiers;
- the production `_scan_file` finding envelope, including line, severity, confidence, CWE, and OWASP metadata.

The initial branch commit contained the tests and exact fixtures without the production rule. Exact-head Python 3.11 and 3.13 workflows failed only because the detector was absent, preserving an executable RED state before the GREEN rule commit.

## Remediation boundary

A complete repair must protect both directions of the mutable boundary:

1. copy a non-null caller-provided array before storing it, using `Arrays.copyOf`, `clone`, or an equivalent explicit copy;
2. return a fresh array from `getBytes()` rather than the private field;
3. avoid exposing the same backing storage through another getter, stream adapter, buffer, or package-visible field;
4. verify that validation, hashing, and persistence observe a stable byte sequence;
5. measure memory optimization at a different boundary, such as bounded streaming or immutable ownership transfer whose contract is explicit and mechanically enforced.

Java's `final` modifier prevents reassignment of the array reference but does not make array elements immutable. Spring's `MultipartFile` contract does not authorize implementations to assume that arbitrary caller-provided arrays or returned arrays will remain unchanged.

## Declared limitations

This is not a general Java alias or escape analysis engine. It intentionally does not claim coverage for:

- inheritance where the `MultipartFile` interface or byte-array field is declared in another class;
- records, generated code, Lombok accessors, or helper methods that retain or expose mutable state;
- `ByteBuffer`, mutable collections, streams, memory-mapped files, or custom buffer types;
- arrays stored through factories, builders, dependency injection, or cross-file calls;
- constructor parameters renamed or transformed through intermediate variables;
- copies performed by helper methods that are not visible as direct `Arrays.copyOf` or `clone` semantics;
- mutation through another method when `getBytes()` itself is safe.

These cases require separate source-derived detector obligations or structural interprocedural analysis. Expanding this bounded regex without a new vulnerable source and an independent fixed negative is prohibited.

## APA 7 references

MITRE Corporation. (2026). *CWE-374: Passing mutable objects to an untrusted method* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/374.html

MITRE Corporation. (2026). *CWE-375: Returning a mutable object to an untrusted caller* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/375.html

Oracle. (2026). *Arrays (Java SE 26 & JDK 26)*. https://docs.oracle.com/en/java/javase/26/docs/api/java.base/java/util/Arrays.html

OWASP Foundation. (2021). *A08:2021—Software and data integrity failures*. https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/

Spring. (2026). *MultipartFile (Spring Framework 7.0.8 API)*. https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/multipart/MultipartFile.html
