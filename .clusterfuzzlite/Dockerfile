FROM scratch
USER 65532:65532
HEALTHCHECK NONE

# ClusterFuzzLite discovery marker for Scorecard and central coverage builds.
# AppGuardrail's runtime scanner is Python-only, so this marker avoids adding
# an unrelated container runtime just to satisfy fuzzing posture discovery.
