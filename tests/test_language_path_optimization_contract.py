"""Regression tests for string-based language-profile path handling."""

from pathlib import Path

import pytest

from appguardrail_core.language import detect_language_axes, detect_stack_profile


@pytest.mark.parametrize(
    "path_text",
    [
        "src/app.py",
        "src/component.tsx",
        "src/page.html",
        "src/archive.tar.py",
        "src/.hidden.py",
        "src/....py",
        "src/trailing.py.",
        "package.json",
        "nested/tsconfig.json",
        r"windows\service\App.java",
        r"windows\web\api\route.ts",
    ],
)
def test_string_path_language_detection_matches_path_objects(path_text: str) -> None:
    """The optimized string path must preserve the declared Path input contract."""
    assert detect_language_axes([path_text]) == detect_language_axes([Path(path_text)])


def test_generator_input_is_materialized_once_for_profile_detection(
    tmp_path: Path,
) -> None:
    """One-shot iterables must feed language, framework, and signal detection once."""
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies":{"next":"15"}}\n', encoding="utf-8")
    route = tmp_path / "app" / "api" / "route.ts"
    route.parent.mkdir(parents=True)
    route.write_text("export const GET = true;\n", encoding="utf-8")

    profile = detect_stack_profile(path for path in (manifest, route))

    assert profile.id == "node-typescript-web"
    assert profile.languages == ("javascript", "typescript")
    assert {"app", "api", "next", "package.json"} <= set(profile.signals)
    assert profile.zap_recommended is True


def test_windows_style_string_paths_preserve_web_directory_signals() -> None:
    """String inputs from another operating system must retain directory signals."""
    profile = detect_stack_profile([r"workspace\app\api\route.ts"])

    assert profile.id == "node-typescript-web"
    assert profile.languages == ("typescript",)
    assert {"app", "api"} <= set(profile.signals)
    assert profile.zap_recommended is True
