"""Coverage tests for the GraphQL API misconfiguration rule pack (5 rules)."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


CASES = {
    "graphql-introspection-enabled-production": (
        [
            "new ApolloServer({ typeDefs, resolvers, introspection: true })",
            "  introspection:true,",
        ],
        [
            "introspection: false",
            "introspection: process.env.NODE_ENV !== 'production'",
        ],
    ),
    "apollo-csrf-prevention-disabled": (
        [
            "new ApolloServer({ csrfPrevention: false })",
            "csrfPrevention:false,",
        ],
        [
            "csrfPrevention: true",
            "// csrfPrevention protects against XS-Search",
        ],
    ),
    "graphql-graphiql-enabled": (
        [
            "graphqlHTTP({ schema, graphiql: true })",
            "  graphiql:true",
        ],
        [
            "graphiql: false",
            "// graphiql is disabled in production",
        ],
    ),
    "graphql-playground-enabled": (
        [
            "new ApolloServer({ playground: true })",
            "  playground:true,",
        ],
        [
            "playground: false",
            "playground: isDev",
        ],
    ),
    "apollo-stacktrace-in-error-responses": (
        [
            "new ApolloServer({ includeStacktraceInErrorResponses: true })",
            "  includeStacktraceInErrorResponses:true,",
        ],
        [
            "includeStacktraceInErrorResponses: false",
            "includeStacktraceInErrorResponses: process.env.NODE_ENV !== 'production'",
        ],
    ),
}


@pytest.mark.parametrize("rule_id", CASES.keys())
def test_rule_precision(rule_id):
    rule = _rule(rule_id)
    positives, negatives = CASES[rule_id]
    for s in positives:
        assert rule["pattern"].search(s), f"{rule_id} should match: {s!r}"
    for s in negatives:
        assert not rule["pattern"].search(s), f"{rule_id} false-positive on: {s!r}"


def test_severities():
    assert (
        _rule("graphql-introspection-enabled-production")["severity"] == "WARNING"
    )
    assert _rule("apollo-csrf-prevention-disabled")["severity"] == "WARNING"
    assert _rule("graphql-graphiql-enabled")["severity"] == "WARNING"
    assert _rule("graphql-playground-enabled")["severity"] == "WARNING"
    assert (
        _rule("apollo-stacktrace-in-error-responses")["severity"] == "HIGH"
    )
