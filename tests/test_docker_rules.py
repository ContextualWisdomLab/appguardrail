"""Coverage tests for the Docker/IaC misconfiguration rule pack (6 rules)."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


CASES = {
    "dockerfile-user-root": (
        ["USER root", "   USER    root", "FROM node:20\nUSER root\n"],
        ["USER node", "USER 1000", "# USER root", "USER app:app", "RUN adduser root"],
    ),
    "dockerfile-base-image-latest": (
        ["FROM node:latest", "FROM python:latest AS build", "  from ubuntu:latest"],
        ["FROM node:20.11-alpine", "FROM python:3.12", "FROM builder", "FROM scratch"],
    ),
    "dockerfile-add-remote-url": (
        [
            "ADD https://example.com/f.tar /f",
            "add http://x/y .",
            "ADD --chown=1:1 https://x /y",
        ],
        ["COPY https://x /y", "ADD ./local /app", "ADD app.tar.gz /app", "RUN curl https://x"],
    ),
    "dockerfile-curl-pipe-shell": (
        [
            "RUN curl -fsSL https://get.example.com/i.sh | sh",
            "RUN wget -qO- https://x | bash",
            "curl https://x | sudo bash",
        ],
        ["RUN curl -o file https://x", "RUN echo hi | grep h", "RUN wget https://x -O f"],
    ),
    "compose-privileged-true": (
        ["    privileged: true", "privileged: yes", "  privileged:  true"],
        ["privileged: false", "# privileged: true", "privileged_mode: false"],
    ),
    "docker-socket-bind-mount": (
        [
            "- /var/run/docker.sock:/var/run/docker.sock",
            '- "/var/run/docker.sock:/var/run/docker.sock:ro"',
        ],
        ["- ./data:/data", "- /var/run/app.sock:/x", "volumes:"],
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


def test_all_docker_rules_loaded():
    for rule_id in CASES:
        assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"


def test_severities():
    assert _rule("dockerfile-user-root")["severity"] == "WARNING"
    assert _rule("dockerfile-base-image-latest")["severity"] == "WARNING"
    assert _rule("dockerfile-add-remote-url")["severity"] == "WARNING"
    assert _rule("dockerfile-curl-pipe-shell")["severity"] == "HIGH"
    assert _rule("compose-privileged-true")["severity"] == "HIGH"
    assert _rule("docker-socket-bind-mount")["severity"] == "HIGH"
