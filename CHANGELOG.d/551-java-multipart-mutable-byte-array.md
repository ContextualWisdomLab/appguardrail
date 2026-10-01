## Added

- Added the HIGH `java-multipart-mutable-byte-array-exposure` SAST detector for Spring `MultipartFile` implementations that retain caller-owned `byte[]` input or return a private backing array directly.
- Added exact vulnerable and reviewed fixed Clearfolio Git-object fixtures, independent one-sided boundary variants, safe `Arrays.copyOf` and `clone` negatives, and production scanner-envelope regressions.
- Documented the CWE-374/CWE-375 integrity boundary, bounded rule scope, false-positive and false-negative limits, and defensive-copy remediation with APA 7 references.
