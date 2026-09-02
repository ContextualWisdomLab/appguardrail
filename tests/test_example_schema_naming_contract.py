"""Guard semantic naming in the paired project security examples."""

from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PROJECT_EXAMPLE_READMES = (
    Path("examples/vulnerable-vibe-app/README.md"),
    Path("examples/fixed-vibe-app/README.md"),
)


@pytest.mark.parametrize("example_readme_path", PROJECT_EXAMPLE_READMES)
def test_project_example_uses_semantic_owned_identifiers(
    example_readme_path: Path,
) -> None:
    """Keep project-owned route and database identifiers context-specific."""
    example_text = (REPOSITORY_ROOT / example_readme_path).read_text(encoding="utf-8")

    assert "app/api/projects/[projectId]/route.ts" in example_text
    assert "params: { projectId: string }" in example_text
    assert ".eq('project_id', params.projectId)" in example_text
    assert "project_id UUID PRIMARY KEY DEFAULT gen_random_uuid()" in example_text
    assert "project_name TEXT" in example_text
    assert "project_payload_json JSONB" in example_text

    assert "app/api/projects/[id]/route.ts" not in example_text
    assert "params: { id: string }" not in example_text
    assert ".eq('id', params.id)" not in example_text
    assert "\n  id UUID PRIMARY KEY DEFAULT gen_random_uuid()," not in example_text
    assert "\n  name TEXT" not in example_text
    assert "\n  data JSONB" not in example_text

    # Supabase's auth schema owns this external identifier; do not rewrite it.
    assert "REFERENCES auth.users(id)" in example_text


def test_supabase_result_fields_are_aliased_at_the_example_boundary() -> None:
    """Translate vendor result keys into semantic internal names in both examples."""
    for example_readme_path in PROJECT_EXAMPLE_READMES:
        example_text = (REPOSITORY_ROOT / example_readme_path).read_text(encoding="utf-8")
        assert "data: projectRecord" in example_text
        assert "error: projectQueryError" in example_text
