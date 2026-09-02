"""Regression coverage for semantic names in the fixed security example."""

from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXED_EXAMPLE_README = (
    REPOSITORY_ROOT / "examples" / "fixed-vibe-app" / "README.md"
)


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
        ".eq('project_id', validatedProjectId)",
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


def test_fixed_example_validates_protected_request_inputs() -> None:
    """Require schema/parameter validation before protected sample operations."""
    example_text = FIXED_EXAMPLE_README.read_text(encoding="utf-8")

    required_validation_contracts = (
        "projectIdSchema.safeParse(params.projectId)",
        "checkoutRequestSchema.safeParse(",
        "await httpRequest.json().catch(() => null)",
        "adminRequestUrl.searchParams.keys()",
        "Unexpected query parameters",
    )
    for validation_contract in required_validation_contracts:
        assert validation_contract in example_text


def test_admin_example_authenticates_before_processing_query_input() -> None:
    """Authenticate protected admin requests before touching untrusted query input."""
    example_text = FIXED_EXAMPLE_README.read_text(encoding="utf-8")
    admin_section_text = example_text.split("### 7. Admin Auth Check Added", 1)[1]

    authentication_position = admin_section_text.index("const authSession = await auth();")
    query_validation_position = admin_section_text.index(
        "const adminRequestUrl = new URL(httpRequest.url);"
    )

    assert authentication_position < query_validation_position


def test_fixed_example_preserves_existing_sample_api_surface() -> None:
    """Naming repairs must not introduce unrelated sample API contract changes."""
    example_text = FIXED_EXAMPLE_README.read_text(encoding="utf-8")

    assert "return Response.json({ url: checkoutSession.url });" in example_text
    assert "`app/api/admin/users/route.ts`" in example_text
    assert "checkout_url" not in example_text
    assert "`app/api/admin/user-accounts/route.ts`" not in example_text
