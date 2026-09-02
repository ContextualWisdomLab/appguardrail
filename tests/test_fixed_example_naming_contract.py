"""Regression coverage for semantic names in the fixed security example."""

from pathlib import Path


FIXED_EXAMPLE_README = Path("examples/fixed-vibe-app/README.md")


def test_fixed_example_uses_semantic_project_database_names() -> None:
    """Keep generic owned database names out of the fixed project example."""
    example_text = FIXED_EXAMPLE_README.read_text(encoding="utf-8")

    required_semantic_names = (
        "CREATE TABLE project_records (",
        "project_id UUID PRIMARY KEY",
        "owner_user_id UUID REFERENCES auth.users(id) NOT NULL",
        "project_name TEXT NOT NULL",
        "project_payload JSONB",
        ".from('project_records')",
        ".eq('project_id', params.projectId)",
    )
    forbidden_owned_names = (
        "CREATE TABLE projects (",
        "  id UUID PRIMARY KEY",
        "  user_id UUID REFERENCES auth.users(id) NOT NULL",
        "  name TEXT NOT NULL",
        "  data JSONB",
        ".from('projects')",
        ".eq('id', params.id)",
    )

    for semantic_name in required_semantic_names:
        assert semantic_name in example_text
    for generic_name in forbidden_owned_names:
        assert generic_name not in example_text
