"""Correct the authoritative OpenCode operator references to APA 7 form."""

from __future__ import annotations

from pathlib import Path


REFERENCES = '''## References

Anomaly. (n.d.-a). *Agents*. OpenCode. Retrieved August 6, 2026, from https://opencode.ai/docs/agents/

Anomaly. (n.d.-b). *GitHub integration*. OpenCode. Retrieved August 6, 2026, from https://opencode.ai/docs/github/

Anomaly. (n.d.-c). *Permissions*. OpenCode. Retrieved August 6, 2026, from https://opencode.ai/docs/permissions/

Anomaly. (n.d.-d). *Providers: NVIDIA*. OpenCode. Retrieved August 6, 2026, from https://opencode.ai/docs/providers/

GitHub. (n.d.). *Use GITHUB_TOKEN for authentication in workflows*. GitHub Docs. Retrieved August 6, 2026, from https://docs.github.com/actions/security-for-github-actions/security-guides/automatic-token-authentication

NVIDIA. (n.d.). *NVIDIA NIM API reference*. NVIDIA API Catalog. Retrieved August 6, 2026, from https://docs.api.nvidia.com/nim/
'''


def main() -> None:
    """Replace the operator document's reference list without altering policy."""
    path = Path("docs/commercial-readiness-opencode.md")
    text = path.read_text(encoding="utf-8")
    marker = "## References\n"
    if text.count(marker) != 1:
        raise SystemExit("expected one operator reference section")
    prefix, _marker, _references = text.partition(marker)
    path.write_text(prefix.rstrip() + "\n\n" + REFERENCES, encoding="utf-8")


if __name__ == "__main__":
    main()
