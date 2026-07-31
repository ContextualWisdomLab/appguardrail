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

def test_is_web_reachable_generator():
    def get_files():
        yield "package.json"
        yield "src/app/page.tsx"

    # Should work and consume generator safely
    profile = detect_stack_profile(get_files())
    assert profile.zap_recommended is True
    assert "javascript" in profile.languages
