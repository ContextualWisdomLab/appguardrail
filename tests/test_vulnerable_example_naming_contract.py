"""Naming-contract regression for the intentionally vulnerable security fixture."""

from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_EXAMPLE_README = (
    REPOSITORY_ROOT / "examples" / "vulnerable-vibe-app" / "README.md"
)


def test_vulnerable_example_keeps_security_flaws_but_uses_semantic_project_names() -> None:
    """Security vulnerabilities must not be coupled to ambiguous owned naming."""
    example_text = VULNERABLE_EXAMPLE_README.read_text(encoding="utf-8")

    required_semantic_names = (
        "app/api/projects/[projectId]/route.ts",
        ".from('project_records')",
        ".eq('project_id', params.projectId)",
        "CREATE TABLE project_records (",
        "project_id UUID PRIMARY KEY",
        "owner_user_id UUID REFERENCES auth.users(id)",
        "project_name TEXT",
        "project_payload JSONB",
    )
    preserved_vulnerability_markers = (
        "No authentication check!",
        "No ownership verification!",
        "RLS never enabled, no policies",
        "Missing: ALTER TABLE project_records ENABLE ROW LEVEL SECURITY;",
    )
    forbidden_generic_names = (
        "app/api/projects/[id]/route.ts",
        ".from('projects')",
        ".eq('id', params.id)",
        "CREATE TABLE projects (",
        "  id UUID PRIMARY KEY",
        "  user_id UUID REFERENCES auth.users(id)",
        "  name TEXT",
        "  data JSONB",
    )

    for semantic_name in required_semantic_names:
        assert semantic_name in example_text
    for vulnerability_marker in preserved_vulnerability_markers:
        assert vulnerability_marker in example_text
    for generic_name in forbidden_generic_names:
        assert generic_name not in example_text
