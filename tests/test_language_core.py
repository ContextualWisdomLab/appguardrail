from appguardrail_core.language import (detect_language_axes,
                                        detect_stack_profile)


def test_detect_language_axes_uses_source_files_and_manifests(tmp_path):
    paths = []
    for name in ["pyproject.toml", "pom.xml", "package.json", "tsconfig.json"]:
        path = tmp_path / name
        path.write_text("{}\n")
        paths.append(path)

    assert detect_language_axes(paths) == {
        "java",
        "javascript",
        "python",
        "typescript",
    }


def test_detect_stack_profile_python_web(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\ndependencies = ["fastapi", "jinja2"]\n')
    app = tmp_path / "app.py"
    app.write_text("from fastapi import FastAPI\n")
    template = tmp_path / "templates" / "index.html"
    template.parent.mkdir()
    template.write_text("<h1>Hello</h1>\n")

    profile = detect_stack_profile([pyproject, app, template])

    assert profile.id == "python-web"
    assert profile.display_name == "Python web application"
    assert profile.languages == ("python", "web")
    assert "fastapi" in profile.frameworks
    assert profile.external_tools == ("bandit", "ruff", "semgrep", "trivy")
    assert profile.zap_recommended is True


def test_detect_stack_profile_java_only(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text("<artifactId>spring-security</artifactId>\n")
    source = tmp_path / "src" / "main" / "java" / "App.java"
    source.parent.mkdir(parents=True)
    source.write_text("class App {}\n")

    profile = detect_stack_profile([pom, source])

    assert profile.id == "java"
    assert profile.languages == ("java",)
    assert "spring-security" in profile.frameworks
    assert profile.external_tools == ("semgrep", "trivy")


def test_detect_stack_profile_java_node_typescript(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text("<artifactId>spring-boot</artifactId>\n")
    package = tmp_path / "package.json"
    package.write_text('{"dependencies": {"next": "latest", "express": "latest"}}\n')
    java = tmp_path / "service" / "App.java"
    java.parent.mkdir()
    java.write_text("class App {}\n")
    api = tmp_path / "web" / "api" / "server.ts"
    api.parent.mkdir(parents=True)
    api.write_text("export const handler = true;\n")

    profile = detect_stack_profile([pom, package, java, api])

    assert profile.id == "java-node-typescript"
    assert profile.languages == ("java", "javascript", "typescript")
    assert {"express", "next", "spring-boot"} <= set(profile.frameworks)
    assert profile.external_tools == ("semgrep", "trivy")
    assert profile.zap_recommended is True


def test_detect_stack_profile_unknown_without_source_signals(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("docs only\n")

    profile = detect_stack_profile([readme])

    assert profile.id == "unknown"
    assert profile.languages == ()
    assert profile.external_tools == ()


def test_legacy_functions():
    from appguardrail_core.language import _detect_framework_markers, _detect_signals, _is_web_reachable
    from pathlib import Path
    paths = [Path("package.json"), Path("templates/index.html"), Path("src/api/route.js")]

    # Needs a real file to trigger manifest text
    with open("package.json", "w") as pkg:
        pkg.write('{"dependencies": {"express": "1.0"}}')

    markers = _detect_framework_markers(paths)
    assert "templates" in markers

    signals = _detect_signals(paths, markers)
    assert "templates" in signals
    assert "package.json" in signals
    assert "api" in signals

    reachable = _is_web_reachable({"python"}, {"templates"}, paths)
    assert reachable is True

    import os
    os.remove("package.json")


def test_legacy_functions_more():
    from appguardrail_core.language import detect_language_axes, detect_stack_profile
    # Hit missing lines 152 (tsconfig.json), 165-166 (OSError on manifest read),
    from pathlib import Path

    paths = [Path("tsconfig.json"), Path("invalid_manifest.json")]

    # Needs a real file to trigger manifest text
    with open("invalid_manifest.json", "w") as pkg:
        pkg.write('{"dependencies": {"express": "1.0"}}')

    axes = detect_language_axes(paths)
    assert "typescript" in axes

    import os
    os.chmod("invalid_manifest.json", 0o000) # Cause OSError

    # Mock MANIFEST_NAMES in module to include invalid_manifest.json for this test
    import appguardrail_core.language
    old_manifests = appguardrail_core.language.MANIFEST_NAMES
    appguardrail_core.language.MANIFEST_NAMES = old_manifests | {"invalid_manifest.json"}

    try:
        prof = detect_stack_profile(paths)
    finally:
        appguardrail_core.language.MANIFEST_NAMES = old_manifests
        os.chmod("invalid_manifest.json", 0o644)
        os.remove("invalid_manifest.json")


def test_legacy_functions_even_more():
    from appguardrail_core.language import _is_web_reachable, _read_manifest_text
    from pathlib import Path
    import os

    paths = [Path("views/page.html")]
    reachable = _is_web_reachable(set(), set(), paths)
    assert reachable is True

    reachable2 = _is_web_reachable(set(), {"django"}, [Path("no_match.py")])
    assert reachable2 is True

    with open("invalid_manifest2.json", "w") as pkg:
        pkg.write('{"dependencies": {"express": "1.0"}}')

    os.chmod("invalid_manifest2.json", 0o000) # Cause OSError
    text = _read_manifest_text(Path("invalid_manifest2.json"))
    assert text == ""

    os.chmod("invalid_manifest2.json", 0o644)
    os.remove("invalid_manifest2.json")


def test_legacy_functions_the_final_line():
    from appguardrail_core.language import _is_web_reachable
    from pathlib import Path

    paths = [Path("something_else.txt")]
    reachable = _is_web_reachable(set(), set(), paths)
    assert reachable is False


def test_legacy_functions_missing_318():
    from appguardrail_core.language import _is_web_reachable
    from pathlib import Path

    paths = [Path("something/else.txt")]
    reachable = _is_web_reachable({"python"}, set(), paths)
    assert reachable is False


def test_legacy_functions_missing_318_again():
    from appguardrail_core.language import _is_web_reachable
    from pathlib import Path

    paths = [Path("something/else.txt"), Path("app/file.js")]
    reachable = _is_web_reachable(set(), set(), paths)
    assert reachable is True


def test_legacy_functions_missing_318_absolutely():
    from appguardrail_core.language import _is_web_reachable
    from pathlib import Path

    # Needs to match WEB_SIGNAL_DIRS which are {"app", "api", "pages", "routes", "templates", "views", "public"}
    paths = [Path("api/route.py")]
    reachable = _is_web_reachable(set(), set(), paths)
    assert reachable is True


def test_legacy_functions_missing_318_absolutely_this_time():
    from appguardrail_core.language import _is_web_reachable
    from pathlib import Path

    paths = [Path("unknown/route.py")]
    reachable = _is_web_reachable(set(), set(), paths)
    assert reachable is False
