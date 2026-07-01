import json
import re
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.cli.appguardrail import (
    SCAN_RULES,
    _bandit_findings,
    _collect_files,
    _detect_scan_languages,
    _load_packaged_regex_rules,
    _path_allowed_by_rule,
    _print_scan_results,
    _ruff_findings,
    _run_bandit_scan,
    _run_codegraph_command,
    _run_codegraph_index,
    _run_ruff_security_scan,
    _run_semgrep_scan,
    _run_trivy_fs,
    _run_zap_baseline,
    _scan_file,
    _semgrep_findings,
    cmd_init,
    cmd_monitor,
    cmd_scan,
)

MOCK_RULES = [
    {
        "id": "mock-secret",
        "pattern": re.compile(r"MOCK_SECRET_KEY"),
        "severity": "CRITICAL",
        "message": "Found mock secret",
        "extensions": None,
    },
    {
        "id": "mock-todo",
        "pattern": re.compile(r"TODO: fix auth"),
        "severity": "HIGH",
        "message": "Found auth todo",
        "extensions": None,
    },
    {
        "id": "mock-rules-ext",
        "pattern": re.compile(r"allow all"),
        "severity": "CRITICAL",
        "message": "Allows all",
        "extensions": [".rules"],
    },
]


class Args:
    def __init__(self, tool="cursor", stack=None):
        self.tool = tool
        self.stack = stack


class ScanArgs:
    def __init__(self, path, trivy=False):
        self.path = str(path)
        self.trivy = trivy
        self.external = "off"
        self.bandit = False
        self.ruff = False
        self.semgrep = False
        self.semgrep_config = None
        self.zap_baseline = None
        self.codegraph = False


class MonitorArgs:
    pass


def _create_symlink(target, link, target_is_directory=False):
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:  # pragma: no cover
        pytest.skip(
            f"symlinks are not available in this environment: {exc}"
        )  # pragma: no cover


def test_scan_file_error_handling(tmp_path):
    test_file = tmp_path / "unsafe.ts"
    test_file.write_text("const key = 'x';\n")

    with patch.object(Path, "open", side_effect=PermissionError("Permission denied")):
        assert _scan_file(test_file, tmp_path) == []

    with patch.object(Path, "open", side_effect=OSError("OS error")):
        assert _scan_file(test_file, tmp_path) == []


@patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES)
def test_scan_file_no_findings(tmp_path):
    test_file = tmp_path / "safe.py"
    test_file.write_text("print('hello')\n")
    assert _scan_file(test_file, tmp_path) == []


@patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES)
def test_scan_file_with_findings(tmp_path):
    test_file = tmp_path / "unsafe.ts"
    test_file.write_text("const key = MOCK_SECRET_KEY;\n")

    findings = _scan_file(test_file, tmp_path)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "mock-secret"


@patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES)
def test_scan_file_with_multiple_findings(tmp_path):
    test_file = tmp_path / "unsafe_multiple.js"
    test_file.write_text(
        "const key = MOCK_SECRET_KEY;\n// TODO: fix auth checks here\n"
    )

    findings = _scan_file(test_file, tmp_path)
    rule_ids = [f["rule_id"] for f in findings]
    assert len(findings) == 2
    assert "mock-secret" in rule_ids
    assert "mock-todo" in rule_ids


def test_scan_file_detects_strix_derived_patterns(tmp_path):
    samples = {
        "app.js": {
            "content": (
                "localStorage.setItem('scopeweave:planner-state:v1', JSON.stringify(state));\n"
                "taskEl.innerHTML = task.title;\n"
                "const headers = { 'X-Dev-User': devUser };\n"
                "fetch('/api/calendar/writeback-intent', { method: 'POST', body: JSON.stringify({ target_source_id }) });\n"
            ),
            "ids": {
                "browser-localstorage-sensitive-state",
                "dom-xss-html-sink",
                "client-side-dev-user-auth",
                "state-changing-fetch-without-csrf-token",
            },
        },
        "frontend.tsx": {
            "content": "const [dsn, setDsn] = useState('');\nreturn <input value={dsn} />;\n",
            "ids": {"frontend-database-dsn-exposure"},
        },
        "index.html": {
            "content": "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self' 'unsafe-inline'\">\n",
            "ids": {"unsafe-inline-script-csp"},
        },
        "upload.py": {
            "content": "target = os.path.join(tmpdir, upload.filename)\n",
            "ids": {"upload-filename-path-traversal-risk"},
        },
        "main.py": {
            "content": "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n",
            "ids": {"python-permissive-cors"},
        },
        "auth.py": {
            "content": "claims = jwt.decode(token, key)\n",
            "ids": {"python-jwt-decode-without-algorithms"},
        },
        "data.py": {
            "content": 'cursor.execute(f"SELECT * FROM users WHERE name = {name}")\n',
            "ids": {"python-dynamic-sql"},
        },
        "media.py": {
            "content": 'subprocess.run(f"ffmpeg -i {source_path}")\n',
            "ids": {"python-subprocess-string-command"},
        },
        "api.py": {
            "content": "raise HTTPException(status_code=500) from exc\n",
            "ids": {"http-exception-chains-internal-error"},
        },
        "media_args.py": {
            "content": (
                "subprocess.run(['ffmpeg', '-i', source_path, '-fs', str(target_bytes)])\n"
            ),
            "ids": {"python-subprocess-user-controlled-args"},
        },
        "media_bounds.py": {
            "content": (
                "def shrink(target_bytes):\n"
                "    if target_bytes <= 0:\n"
                "        raise ValueError('bad target')\n"
            ),
            "ids": {"python-target-bytes-missing-upper-bound"},
        },
        "config.py": {
            "content": "API_KEY = 'abc1234567890secret'\n",
            "ids": {"hardcoded-api-credential"},
        },
        "routes.py": {
            "content": (
                "@router.post('/api/calendar/writeback-intent')\n"
                "async def writeback_intent(target_source_id: str):\n"
                "    return {'ok': True}\n"
            ),
            "ids": {"fastapi-state-changing-route-without-auth"},
        },
        "schemas.py": {
            "content": (
                "class BoundingBox(BaseModel):\n"
                "    x: float\n"
                "    y: float\n"
                "    width: float\n"
                "    height: float\n\n"
                "class ParseQuality(BaseModel):\n"
                "    warnings: list[list[str]]\n"
            ),
            "ids": {
                "pydantic-bounding-box-unconstrained",
                "pydantic-unbounded-nested-list",
            },
        },
        "paths.py": {
            "content": (
                "candidate = Path(input_path)\n"
                "if '..' in candidate.parts:\n"
                "    raise ValueError('bad path')\n"
            ),
            "ids": {"python-absolute-path-traversal-check-missing"},
        },
    }

    for name, sample in samples.items():
        test_file = tmp_path / name
        test_file.write_text(sample["content"])
        rule_ids = {finding["rule_id"] for finding in _scan_file(test_file, tmp_path)}
        assert sample["ids"] <= rule_ids


def test_scan_file_detects_sast_dast_derived_patterns(tmp_path):
    samples = {
        "tls.py": {
            "content": "requests.get('https://api.example.test', verify=False)\n",
            "ids": {"python-requests-verify-false"},
        },
        "tmp.py": {
            "content": "name = tempfile.mktemp()\n",
            "ids": {"python-tempfile-mktemp"},
        },
        "flask_app.py": {
            "content": "app.run(host='0.0.0.0', debug=True)\n",
            "ids": {"python-flask-debug-true"},
        },
        "templates.py": {
            "content": "env = jinja2.Environment(loader=loader, autoescape=False)\n",
            "ids": {"python-jinja-autoescape-disabled"},
        },
        "views.py": {
            "content": "@csrf_exempt\ndef update_profile(request):\n    return HttpResponse('ok')\n",
            "ids": {"python-django-csrf-exempt"},
        },
        "tls.js": {
            "content": "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
            "ids": {"node-tls-validation-disabled"},
        },
        "jwt.ts": {
            "content": "jwt.verify(token, key, { algorithms: ['none'] });\n",
            "ids": {"node-jwt-none-algorithm"},
        },
        "cors.ts": {
            "content": "app.use(cors({ origin: '*', credentials: true }));\n",
            "ids": {"node-cors-wildcard-with-credentials"},
        },
        "helmet.ts": {
            "content": "app.use(helmet({ contentSecurityPolicy: false }));\n",
            "ids": {"node-helmet-csp-disabled"},
        },
        "frame.ts": {
            "content": "app.use(helmet({ frameguard: false }));\n",
            "ids": {"node-clickjacking-protection-disabled"},
        },
        "xss.js": {
            "content": "res.send('<h1>' + req.query.name + '</h1>');\n",
            "ids": {"express-reflected-input-send"},
        },
        "SecurityConfig.java": {
            "content": "http.csrf(csrf -> csrf.disable());\n",
            "ids": {"java-spring-csrf-disabled"},
        },
        "TrustAll.java": {
            "content": (
                "HostnameVerifier verifier = new HostnameVerifier() {\n"
                "    public boolean verify(String host, SSLSession session) {\n"
                "        return true;\n"
                "    }\n"
                "};\n"
            ),
            "ids": {"java-hostname-verifier-allow-all"},
        },
        "CookieConfig.java": {
            "content": "cookie.setSecure(false);\n",
            "ids": {"java-cookie-secure-false"},
        },
        "JwtVerifier.java": {
            "content": "Algorithm algorithm = Algorithm.none();\n",
            "ids": {"java-jwt-none-algorithm"},
        },
        "Deserialize.java": {
            "content": "ObjectInputStream in = new ObjectInputStream(request.getInputStream());\n",
            "ids": {"java-objectinputstream-deserialization"},
        },
    }

    for name, sample in samples.items():
        test_file = tmp_path / name
        test_file.write_text(sample["content"])
        rule_ids = {finding["rule_id"] for finding in _scan_file(test_file, tmp_path)}
        assert sample["ids"] <= rule_ids


@patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES)
def test_scan_file_redacts_sensitive_snippet(tmp_path):
    test_file = tmp_path / "unsafe.ts"
    test_file.write_text("const key = MOCK_SECRET_KEY;\n")

    findings = _scan_file(test_file, tmp_path)
    assert findings[0]["snippet"] == "[REDACTED: sensitive match suppressed]"


def test_scan_file_unreadable(tmp_path):
    test_file = tmp_path / "unreadable.ts"
    test_file.write_text("MOCK_SECRET_KEY\n")

    with patch.object(Path, "open", side_effect=PermissionError("Permission denied")):
        assert _scan_file(test_file, tmp_path) == []


@patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES)
def test_scan_file_extensions_filter(tmp_path):
    test_file = tmp_path / "rules.js"
    test_file.write_text("allow all\n")

    findings = _scan_file(test_file, tmp_path)
    rule_ids = [f["rule_id"] for f in findings]
    assert "mock-rules-ext" not in rule_ids

    test_file_rules = tmp_path / "firestore.rules"
    test_file_rules.write_text("allow all\n")

    findings = _scan_file(test_file_rules, tmp_path)
    rule_ids = [f["rule_id"] for f in findings]
    assert "mock-rules-ext" in rule_ids


def test_packaged_yaml_regex_rules_are_loaded():
    packaged_rules = _load_packaged_regex_rules()
    packaged_ids = {rule["id"] for rule in packaged_rules}
    active_ids = {rule["id"] for rule in SCAN_RULES}

    assert "hardcoded-generic-secret" in packaged_ids
    assert "firebase-rules-allow-all" in packaged_ids
    assert "nextjs-env-secret-client-prefix" in active_ids


def test_yaml_rule_path_filters_match_root_and_nested_paths():
    assert _path_allowed_by_rule(".env.local", ["**/.env*"], [])
    assert _path_allowed_by_rule("apps/web/.env.production", ["**/.env*"], [])
    assert not _path_allowed_by_rule("src/config.ts", ["**/.env*"], [])
    assert not _path_allowed_by_rule("tests/mock-auth.ts", [], ["**/tests/**"])


def test_scan_file_detects_packaged_yaml_regex_rule(tmp_path):
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=sbp_12345678901234567890\n"
    )

    rule_ids = {finding["rule_id"] for finding in _scan_file(env_file, tmp_path)}

    assert "supabase-service-role-key-in-env" in rule_ids


def test_scan_file_rule_cache_invalidates_when_scan_rules_change(tmp_path):
    test_file = tmp_path / "unsafe.py"
    test_file.write_text("FIRST_TOKEN\nSECOND_TOKEN\n")

    first_rules = [
        {
            "id": "first",
            "pattern": re.compile(r"FIRST_TOKEN"),
            "severity": "HIGH",
            "message": "first token",
            "extensions": [".py"],
        }
    ]
    second_rules = [
        {
            "id": "second",
            "pattern": re.compile(r"SECOND_TOKEN"),
            "severity": "HIGH",
            "message": "second token",
            "extensions": [".py"],
        }
    ]

    with patch("scanner.cli.appguardrail.SCAN_RULES", first_rules):
        assert [finding["rule_id"] for finding in _scan_file(test_file, tmp_path)] == [
            "first"
        ]

    with patch("scanner.cli.appguardrail.SCAN_RULES", second_rules):
        assert [finding["rule_id"] for finding in _scan_file(test_file, tmp_path)] == [
            "second"
        ]


def test_collect_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = Path(tmpdir)
        (base_path / "src").mkdir()
        (base_path / "src" / "main.py").touch()
        (base_path / "src" / "utils.js").touch()
        (base_path / "README.md").touch()
        (base_path / "node_modules").mkdir()
        (base_path / "node_modules" / "index.js").touch()
        (base_path / ".git").mkdir()
        (base_path / ".git" / "config").touch()
        (base_path / "src" / "image.png").touch()
        (base_path / "package.lock").touch()

        collected_files = list(_collect_files(base_path))
        collected_rel_paths = {
            f.relative_to(base_path).as_posix() for f in collected_files
        }

        assert collected_rel_paths == {"src/main.py", "src/utils.js", "README.md"}
        assert "node_modules/index.js" not in collected_rel_paths
        assert ".git/config" not in collected_rel_paths
        assert "src/image.png" not in collected_rel_paths
        assert "package.lock" not in collected_rel_paths


def test_collect_files_skips_file_symlink(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("print('target')\n")
    link = tmp_path / "linked.py"
    _create_symlink(target, link)

    collected_rel_paths = {
        f.relative_to(tmp_path).as_posix() for f in _collect_files(tmp_path)
    }

    assert "target.py" in collected_rel_paths
    assert "linked.py" not in collected_rel_paths


def test_collect_files_skips_dir_symlink(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "nested.py").write_text("print('nested')\n")
    link = tmp_path / "linked_dir"
    _create_symlink(real_dir, link, target_is_directory=True)

    collected_rel_paths = {
        f.relative_to(tmp_path).as_posix() for f in _collect_files(tmp_path)
    }

    assert "real/nested.py" in collected_rel_paths
    assert "linked_dir/nested.py" not in collected_rel_paths


def test_collect_files_handles_broken_symlink(tmp_path):
    link = tmp_path / "broken.py"
    _create_symlink(tmp_path / "missing.py", link)

    assert list(_collect_files(tmp_path)) == []


def test_collect_files_handles_cyclic_symlink(tmp_path):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "a.py").write_text("print('a')\n")
    (dir_b / "b.py").write_text("print('b')\n")
    _create_symlink(dir_b, dir_a / "to_b", target_is_directory=True)
    _create_symlink(dir_a, dir_b / "to_a", target_is_directory=True)

    collected_rel_paths = {
        f.relative_to(tmp_path).as_posix() for f in _collect_files(tmp_path)
    }

    assert collected_rel_paths == {"a/a.py", "b/b.py"}


@patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES)
def test_scan_file_skips_symlink(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("MOCK_SECRET_KEY\n")
    link = tmp_path / "linked.py"
    _create_symlink(target, link)

    assert _scan_file(link, tmp_path) == []


def test_cmd_scan_skips_symlink_path(tmp_path, capsys):
    target = tmp_path / "target.py"
    target.write_text("print('target')\n")
    link = tmp_path / "linked.py"
    _create_symlink(target, link)

    assert cmd_scan(ScanArgs(link)) == 0
    assert "Skipping symlink path:" in capsys.readouterr().out


def test_cmd_scan_returns_failure_when_no_files_scanned(tmp_path, capsys):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "index.js").write_text("console.log('ignored')\n")

    assert cmd_scan(ScanArgs(tmp_path)) == 1
    out = capsys.readouterr().out
    assert "No files were scanned. Are you in the right directory?" in out
    assert "Scanned 0 files" in out


def test_cmd_scan_auto_external_uses_detected_language_axes(tmp_path, monkeypatch):
    monkeypatch.delenv("APPGUARDRAIL_TARGET_URL", raising=False)
    (tmp_path / "app.py").write_text("print('safe')\n")
    (tmp_path / "App.java").write_text("class App {}\n")
    (tmp_path / "server.ts").write_text("export const ok = true;\n")

    args = ScanArgs(tmp_path)
    args.external = "auto"

    def fake_available(name, version_args=("--version",)):
        return f"/usr/bin/{name}" if name in {"bandit", "ruff", "semgrep"} else None

    with patch("scanner.cli.appguardrail.SCAN_RULES", []), patch(
        "scanner.cli.appguardrail._external_tool_available",
        side_effect=fake_available,
    ), patch(
        "scanner.cli.appguardrail._run_bandit_scan", return_value=[]
    ) as bandit, patch(
        "scanner.cli.appguardrail._run_ruff_security_scan", return_value=[]
    ) as ruff, patch(
        "scanner.cli.appguardrail._run_semgrep_scan", return_value=[]
    ) as semgrep:
        assert cmd_scan(args) == 0

    bandit.assert_called_once_with(tmp_path.resolve())
    ruff.assert_called_once_with(tmp_path.resolve())
    semgrep.assert_called_once_with(tmp_path.resolve(), "auto")


def test_cmd_scan_streams_collected_files_while_detecting_languages(tmp_path):
    files = [tmp_path / "first.py", tmp_path / "second.py"]
    for file_path in files:
        file_path.write_text("print('safe')\n")
    events = []

    def fake_collect_files(_base_path):
        for file_path in files:
            events.append(f"yield:{file_path.name}")
            yield file_path

    def fake_scan_file(file_path, _base_path):
        events.append(f"scan:{file_path.name}")
        return []

    with patch("scanner.cli.appguardrail._collect_files", side_effect=fake_collect_files), patch(
        "scanner.cli.appguardrail._scan_file", side_effect=fake_scan_file
    ):
        assert cmd_scan(ScanArgs(tmp_path)) == 0

    assert events[:2] == ["yield:first.py", "scan:first.py"]


def test_collect_files_includes_security_hidden_directories(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow_file = workflow_dir / "security.yml"
    workflow_file.write_text("name: Security\n")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    ignored_file = git_dir / "config"
    ignored_file.write_text("[core]\n")

    files = {path.relative_to(tmp_path) for path in _collect_files(tmp_path)}

    assert Path(".github/workflows/security.yml") in files
    assert Path(".git/config") not in files


def test_run_trivy_fs_maps_json_findings(tmp_path):
    report = {
        "Results": [
            {
                "Target": str(tmp_path / "package-lock.json"),
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "leftpad",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "HIGH",
                        "Title": "demo vuln",
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "AVD-DS-0001",
                        "Severity": "MEDIUM",
                        "Title": "Dockerfile root user",
                        "Message": "Container runs as root",
                        "CauseMetadata": {"StartLine": 7},
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "private-key",
                        "Severity": "CRITICAL",
                        "Title": "Private key",
                        "StartLine": 3,
                        "Match": "SHOULD_NOT_PRINT",
                    }
                ],
            }
        ]
    }
    process = type(
        "Process", (), {"returncode": 0, "stdout": json.dumps(report), "stderr": ""}
    )()

    with (
        patch("scanner.cli.appguardrail.shutil.which", return_value="/usr/bin/trivy"),
        patch("scanner.cli.appguardrail.subprocess.run", return_value=process) as run,
    ):
        findings = _run_trivy_fs(tmp_path)

    assert run.call_args.args[0][:2] == ["/usr/bin/trivy", "fs"]
    assert [finding["rule_id"] for finding in findings] == [
        "trivy:CVE-2026-0001",
        "trivy:AVD-DS-0001",
        "trivy:private-key",
    ]
    assert findings[0]["file"] == "package-lock.json"
    assert findings[1]["severity"] == "WARNING"
    assert findings[1]["line"] == 7
    assert findings[2]["severity"] == "CRITICAL"
    assert findings[0]["source"] == "trivy"
    assert findings[0]["category"] == "dependency"
    assert findings[0]["context"] == "app-code"
    assert findings[0]["fix_prompt"].startswith("Fix trivy:CVE-2026-0001")
    assert "SHOULD_NOT_PRINT" not in findings[2]["snippet"]


def test_run_trivy_fs_passes_scan_path_as_literal_argument(tmp_path):
    scan_path = tmp_path / "literal;touch INJECTED"
    scan_path.mkdir()
    process = type(
        "Process", (), {"returncode": 0, "stdout": json.dumps({}), "stderr": ""}
    )()

    with (
        patch("scanner.cli.appguardrail.shutil.which", return_value="/usr/bin/trivy"),
        patch("scanner.cli.appguardrail.subprocess.run", return_value=process) as run,
    ):
        assert _run_trivy_fs(scan_path) == []

    command = run.call_args.args[0]
    assert command[-1] == str(scan_path)
    assert run.call_args.kwargs["shell"] is False


def test_run_trivy_fs_requires_trivy(tmp_path):
    with patch("scanner.cli.appguardrail.shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="trivy executable not found"):
            _run_trivy_fs(tmp_path)


def test_detect_scan_languages_maps_file_extensions(tmp_path):
    files = []
    for name in ["app.py", "Main.java", "server.js", "view.tsx", "index.html"]:
        path = tmp_path / name
        path.write_text("// sample\n")
        files.append(path)

    assert _detect_scan_languages(files) == {
        "java",
        "javascript",
        "python",
        "typescript",
        "web",
    }


def test_bandit_findings_maps_json_report(tmp_path):
    report = {
        "results": [
            {
                "test_id": "B501",
                "filename": str(tmp_path / "client.py"),
                "line_number": 12,
                "issue_severity": "HIGH",
                "issue_text": "Requests call with verify=False",
                "code": "requests.get(url, verify=False)",
            }
        ]
    }

    findings = _bandit_findings(report, tmp_path)

    assert findings[0]["rule_id"] == "bandit:B501"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["file"] == "client.py"
    assert findings[0]["line"] == 12


def test_run_bandit_scan_maps_json_findings(tmp_path):
    report = {
        "results": [
            {
                "test_id": "B201",
                "filename": str(tmp_path / "app.py"),
                "line_number": 5,
                "issue_severity": "MEDIUM",
                "issue_text": "Flask app run with debug=True",
                "code": "app.run(debug=True)",
            }
        ]
    }
    process = type(
        "Process", (), {"returncode": 1, "stdout": json.dumps(report), "stderr": ""}
    )()

    with patch(
        "scanner.cli.appguardrail.shutil.which", return_value="/usr/bin/bandit"
    ), patch("scanner.cli.appguardrail.subprocess.run", return_value=process) as run:
        findings = _run_bandit_scan(tmp_path)

    assert run.call_args.args[0][:4] == ["/usr/bin/bandit", "-f", "json", "-q"]
    assert "-r" in run.call_args.args[0]
    assert findings[0]["rule_id"] == "bandit:B201"
    assert findings[0]["severity"] == "WARNING"


def test_ruff_findings_maps_json_diagnostics(tmp_path):
    report = [
        {
            "code": "S501",
            "filename": str(tmp_path / "client.py"),
            "location": {"row": 9},
            "message": "Probable use of requests call with verify=False",
        }
    ]

    findings = _ruff_findings(report, tmp_path)

    assert findings[0]["rule_id"] == "ruff:S501"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["file"] == "client.py"
    assert findings[0]["line"] == 9


def test_run_ruff_security_scan_maps_json_findings(tmp_path):
    report = [
        {
            "code": "S201",
            "filename": str(tmp_path / "app.py"),
            "location": {"row": 3},
            "message": "flask app with debug=True",
        }
    ]
    process = type(
        "Process", (), {"returncode": 1, "stdout": json.dumps(report), "stderr": ""}
    )()

    with patch(
        "scanner.cli.appguardrail.shutil.which", return_value="/usr/bin/ruff"
    ), patch("scanner.cli.appguardrail.subprocess.run", return_value=process) as run:
        findings = _run_ruff_security_scan(tmp_path)

    assert run.call_args.args[0][:4] == [
        "/usr/bin/ruff",
        "check",
        "--select",
        "S",
    ]
    assert findings[0]["rule_id"] == "ruff:S201"


def test_semgrep_findings_maps_json_results(tmp_path):
    report = {
        "results": [
            {
                "check_id": "javascript.express.security.audit.xss.direct-response",
                "path": str(tmp_path / "server.ts"),
                "start": {"line": 7},
                "extra": {
                    "message": "Detected reflected response",
                    "severity": "ERROR",
                    "lines": "res.send(req.query.name)",
                },
            }
        ]
    }

    findings = _semgrep_findings(report, tmp_path)

    assert findings[0]["rule_id"].startswith("semgrep:javascript.express")
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["file"] == "server.ts"
    assert findings[0]["line"] == 7


def test_run_semgrep_scan_maps_json_findings(tmp_path):
    report = {
        "results": [
            {
                "check_id": "java.lang.security.audit.cookie-missing-secure",
                "path": str(tmp_path / "App.java"),
                "start": {"line": 11},
                "extra": {
                    "message": "Cookie missing Secure flag",
                    "severity": "WARNING",
                    "lines": "cookie.setSecure(false);",
                },
            }
        ]
    }
    process = type(
        "Process", (), {"returncode": 1, "stdout": json.dumps(report), "stderr": ""}
    )()

    with patch(
        "scanner.cli.appguardrail.shutil.which", return_value="/usr/bin/semgrep"
    ), patch("scanner.cli.appguardrail.subprocess.run", return_value=process) as run:
        findings = _run_semgrep_scan(tmp_path, "auto")

    assert run.call_args.args[0][:5] == [
        "/usr/bin/semgrep",
        "scan",
        "--config",
        "auto",
        "--json",
    ]
    assert findings[0]["rule_id"].startswith("semgrep:java.lang")
    assert findings[0]["severity"] == "WARNING"


def test_run_zap_baseline_maps_json_findings(tmp_path):
    report = {
        "site": [
            {
                "@name": "https://example.test",
                "alerts": [
                    {
                        "pluginid": "10038",
                        "riskdesc": "High (Medium)",
                        "alert": "Content Security Policy Header Not Set",
                        "instances": [
                            {
                                "uri": "https://example.test/",
                                "evidence": "missing header",
                            }
                        ],
                    }
                ],
            }
        ]
    }

    def fake_run(command, **kwargs):
        Path(command[4]).write_text(json.dumps(report))
        return type("Process", (), {"returncode": 1, "stdout": "", "stderr": ""})()

    with patch(
        "scanner.cli.appguardrail.shutil.which", return_value="/usr/bin/zap-baseline.py"
    ), patch("scanner.cli.appguardrail.subprocess.run", side_effect=fake_run) as run:
        findings = _run_zap_baseline("https://example.test")

    assert run.call_args.args[0][:3] == [
        "/usr/bin/zap-baseline.py",
        "-t",
        "https://example.test",
    ]
    assert findings[0]["rule_id"] == "zap:10038"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["file"] == "https://example.test/"


def test_run_codegraph_index_initializes_when_missing(tmp_path):
    status_process = type(
        "Process", (), {"returncode": 0, "stdout": "Index is up to date", "stderr": ""}
    )()
    init_process = type("Process", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with (
        patch(
            "scanner.cli.appguardrail.shutil.which", return_value="/usr/bin/codegraph"
        ),
        patch(
            "scanner.cli.appguardrail.subprocess.run",
            side_effect=[init_process, status_process],
        ) as run,
    ):
        assert _run_codegraph_index(tmp_path) == "Index is up to date"

    assert run.call_args_list[0].args[0] == ["/usr/bin/codegraph", "init", "-i"]
    assert run.call_args_list[1].args[0] == ["/usr/bin/codegraph", "status"]


def test_run_codegraph_index_syncs_existing_index(tmp_path):
    (tmp_path / ".codegraph").mkdir()
    status_process = type(
        "Process", (), {"returncode": 0, "stdout": "Index is up to date", "stderr": ""}
    )()
    sync_process = type("Process", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with (
        patch(
            "scanner.cli.appguardrail.shutil.which", return_value="/usr/bin/codegraph"
        ),
        patch(
            "scanner.cli.appguardrail.subprocess.run",
            side_effect=[sync_process, status_process],
        ) as run,
    ):
        assert _run_codegraph_index(tmp_path) == "Index is up to date"

    assert run.call_args_list[0].args[0] == ["/usr/bin/codegraph", "sync"]
    assert run.call_args_list[1].args[0] == ["/usr/bin/codegraph", "status"]


def test_run_codegraph_index_requires_codegraph(tmp_path):
    with patch("scanner.cli.appguardrail.shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="codegraph executable not found"):
            _run_codegraph_index(tmp_path)


def test_run_codegraph_index_rejects_file_at_index_path(tmp_path):
    (tmp_path / ".codegraph").write_text("not a directory")

    with patch(
        "scanner.cli.appguardrail.shutil.which", return_value="/usr/bin/codegraph"
    ):
        with pytest.raises(RuntimeError, match="not a directory"):
            _run_codegraph_index(tmp_path)


def test_run_codegraph_command_rejects_non_string_argument(tmp_path):
    with pytest.raises(RuntimeError, match="must be a string"):
        _run_codegraph_command(["/usr/bin/codegraph", 123], tmp_path, "status")


def test_run_codegraph_command_rejects_control_characters(tmp_path):
    with pytest.raises(RuntimeError, match="control characters"):
        _run_codegraph_command(["/usr/bin/codegraph", "status\n"], tmp_path, "status")


def test_run_codegraph_command_rejects_unexpected_arguments(tmp_path):
    with pytest.raises(RuntimeError, match="Unsupported CodeGraph status command"):
        _run_codegraph_command(
            ["/usr/bin/codegraph", "status", ";", "echo", "pwned"], tmp_path, "status"
        )


@patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES)
def test_cmd_scan_does_not_block_doc_findings(tmp_path, capsys):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "example.md").write_text("MOCK_SECRET_KEY\n")

    assert cmd_scan(ScanArgs(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "| doc" in out
    assert "Gate:    non-blocking context" in out
    assert "🔴 0 critical issues" in out


@patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES)
def test_cmd_scan_blocks_app_code_findings(tmp_path, capsys):
    (tmp_path / "app.py").write_text("MOCK_SECRET_KEY\n")

    assert cmd_scan(ScanArgs(tmp_path)) == 1
    out = capsys.readouterr().out
    assert "| app-code" in out
    assert "🔴 1 critical issue" in out


def test_cmd_scan_redacts_sensitive_values_in_output(tmp_path, capsys):
    rules = [
        {
            "id": "stripe-secret",
            "pattern": re.compile(r"sk_test_123456789"),
            "severity": "CRITICAL",
            "message": "Stripe key exposed",
            "extensions": None,
        },
        {
            "id": "openai-token",
            "pattern": re.compile(r"sk-openai-abcdefghijk"),
            "severity": "CRITICAL",
            "message": "OpenAI key exposed",
            "extensions": None,
        },
        {
            "id": "jwt-hardcoded",
            "pattern": re.compile(r"jwt-secret-value"),
            "severity": "HIGH",
            "message": "JWT secret hardcoded",
            "extensions": None,
        },
        {
            "id": "database-url",
            "pattern": re.compile(r"sqlite:///tmp/app.db"),
            "severity": "HIGH",
            "message": "Database URL hardcoded",
            "extensions": None,
        },
    ]
    (tmp_path / ".env").write_text(
        "\n".join(
            [
                "STRIPE_SECRET_KEY=sk_test_123456789",
                "OPENAI_API_KEY=sk-openai-abcdefghijk",
                "JWT_SECRET=jwt-secret-value",
                "DATABASE_URL=sqlite:///tmp/app.db",
            ]
        )
        + "\n"
    )

    with patch("scanner.cli.appguardrail.SCAN_RULES", rules):
        assert cmd_scan(ScanArgs(tmp_path)) == 1

    captured = capsys.readouterr()
    combined = f"{captured.out}\n{captured.err}"
    assert "sk_test_123456789" not in combined
    assert "sk-openai-abcdefghijk" not in combined
    assert "jwt-secret-value" not in combined
    assert "sqlite:///tmp/app.db" not in combined
    assert "[REDACTED: sensitive match suppressed]" in captured.out


def test_cmd_scan_does_not_block_embedded_scanner_rule_fixtures(tmp_path, capsys):
    scanner_cli = tmp_path / "scanner" / "cli"
    scanner_cli.mkdir(parents=True)
    (scanner_cli / "appguardrail.py").write_text('"message": "Use eval() detected"\n')
    rules = [
        {
            "id": "dangerous-eval",
            "pattern": re.compile(r"eval"),
            "severity": "CRITICAL",
            "message": "eval detected",
            "extensions": [".py"],
        }
    ]

    with patch("scanner.cli.appguardrail.SCAN_RULES", rules):
        assert cmd_scan(ScanArgs(tmp_path)) == 0

    out = capsys.readouterr().out
    assert "| scanner-fixture" in out
    assert "🔴 0 critical issues" in out


def test_cmd_scan_single_file_keeps_scanner_fixture_context(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    scanner_cli = tmp_path / "scanner" / "cli"
    scanner_cli.mkdir(parents=True)
    scanner_file = scanner_cli / "appguardrail.py"
    scanner_file.write_text('"message": "Use eval() detected"\n')
    rules = [
        {
            "id": "dangerous-eval",
            "pattern": re.compile(r"eval"),
            "severity": "CRITICAL",
            "message": "eval detected",
            "extensions": [".py"],
        }
    ]

    with patch("scanner.cli.appguardrail.SCAN_RULES", rules):
        assert cmd_scan(ScanArgs(str(scanner_file))) == 0

    out = capsys.readouterr().out
    assert "scanner/cli/appguardrail.py" in out
    assert "| scanner-fixture" in out
    assert "🔴 0 critical issues" in out


def test_print_scan_results_empty(capsys):
    _print_scan_results([], 5)
    captured = capsys.readouterr()

    assert "Scanned 5 files" in captured.out
    assert "🔴 0 critical issues" in captured.out
    assert "✅ No issues found in this scan." in captured.out
    assert "Run 'appguardrail review'" not in captured.out


def test_print_scan_results_critical(capsys):
    findings = [
        {
            "severity": "CRITICAL",
            "file": "app/page.tsx",
            "line": 10,
            "rule_id": "VSEC-001",
            "message": "Found a critical issue",
            "snippet": "const secret = 'abc';",
        }
    ]
    _print_scan_results(findings, 2)
    captured = capsys.readouterr()

    assert "[🔴 CRITICAL] app/page.tsx:10" in captured.out
    assert "Rule:    VSEC-001" in captured.out
    assert "Found a critical issue" in captured.out
    assert "Code:    const secret = 'abc';" in captured.out
    assert "🔴 1 critical issue" in captured.out
    assert "❌ Critical issue found. Fix before deploying." in captured.out
    assert (
        "💡 Run 'appguardrail review' to get an AI prompt for fixing this issue."
        in captured.out
    )


def test_print_scan_results_high(capsys):
    findings = [
        {
            "severity": "HIGH",
            "file": "app/api/route.ts",
            "line": 5,
            "rule_id": "VSEC-002",
            "message": "Found a high issue",
            "snippet": "export async function GET() {}",
        }
    ]
    _print_scan_results(findings, 3)
    captured = capsys.readouterr()

    assert "[🟠 HIGH] app/api/route.ts:5" in captured.out
    assert "🟠 1 high issue" in captured.out
    assert "⚠️  High-severity issue found. Review before deploying." in captured.out


def test_print_scan_results_warnings_only(capsys):
    findings = [
        {
            "severity": "WARNING",
            "file": "utils.ts",
            "line": 1,
            "rule_id": "VSEC-003",
            "message": "Found a warning",
            "snippet": "console.log(data);",
        }
    ]
    _print_scan_results(findings, 1)
    captured = capsys.readouterr()

    assert "[🟡 WARNING] utils.ts:1" in captured.out
    assert "🟡 1 warning" in captured.out
    assert "✅ No deploy-blocking critical or high issues found." in captured.out


def test_print_scan_results_sorting(capsys):
    findings = [
        {
            "severity": "INFO",
            "file": "info.ts",
            "line": 1,
            "rule_id": "VSEC-004",
            "message": "Info message",
            "snippet": "info",
        },
        {
            "severity": "CRITICAL",
            "file": "crit.ts",
            "line": 2,
            "rule_id": "VSEC-001",
            "message": "Crit message",
            "snippet": "crit",
        },
        {
            "severity": "HIGH",
            "file": "high.ts",
            "line": 3,
            "rule_id": "VSEC-002",
            "message": "High message",
            "snippet": "high",
        },
        {
            "severity": "WARNING",
            "file": "warn.ts",
            "line": 4,
            "rule_id": "VSEC-003",
            "message": "Warn message",
            "snippet": "warn",
        },
    ]
    _print_scan_results(findings, 4)
    out = capsys.readouterr().out

    idx_crit = out.find("[🔴 CRITICAL]")
    idx_high = out.find("[🟠 HIGH]")
    idx_warn = out.find("[🟡 WARNING]")
    idx_info = out.find("[🔵 INFO]")

    assert idx_crit != -1
    assert idx_high != -1
    assert idx_warn != -1
    assert idx_info != -1
    assert idx_crit < idx_high < idx_warn < idx_info


def test_cmd_init_cursor(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="cursor"))

    assert (tmp_path / ".cursor" / "rules" / "appguardrail.md").exists()
    assert (tmp_path / "APPGUARDRAIL_CHECKLIST.md").exists()
    captured = capsys.readouterr()
    assert "✅ AppGuardrail initialized successfully!" in captured.out
    assert ".cursor/rules/appguardrail.md" in captured.out


def test_cmd_init_claude_code_new(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="claude-code"))

    assert (tmp_path / "CLAUDE.md").exists()
    assert (tmp_path / "APPGUARDRAIL_CHECKLIST.md").exists()


def test_cmd_init_claude_code_append(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    claude_file = tmp_path / "CLAUDE.md"
    claude_file.write_text("Existing rules\n")

    cmd_init(Args(tool="claude-code"))

    content = claude_file.read_text()
    assert "Existing rules" in content
    assert len(content.splitlines()) > 1
    assert "CLAUDE.md (appended)" in capsys.readouterr().out


def test_cmd_init_claude_code_skip(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    claude_file = tmp_path / "CLAUDE.md"
    claude_file.write_text("AppGuardrail existing rules\n")

    cmd_init(Args(tool="claude-code"))

    assert claude_file.read_text() == "AppGuardrail existing rules\n"
    out = capsys.readouterr().out
    assert "⏭️  Skipped (already configured):" in out
    assert "CLAUDE.md" in out


def test_cmd_init_windsurf(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="windsurf"))

    assert (tmp_path / ".windsurf" / "rules" / "appguardrail.md").exists()
    assert (tmp_path / "APPGUARDRAIL_CHECKLIST.md").exists()
    assert ".windsurf/rules/appguardrail.md" in capsys.readouterr().out


def test_cmd_init_lovable(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="lovable"))

    lovable_file = tmp_path / "LOVABLE_SECURITY_CHECKLIST.md"
    assert lovable_file.exists()
    assert "AppGuardrail Secure Build Checklist for Lovable" in lovable_file.read_text()
    assert (tmp_path / "APPGUARDRAIL_CHECKLIST.md").exists()
    out = capsys.readouterr().out
    assert "LOVABLE_SECURITY_CHECKLIST.md" in out
    assert "APPGUARDRAIL_CHECKLIST.md" in out


def test_cmd_monitor_installs_github_actions_workflow(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    assert cmd_monitor(MonitorArgs()) == 0

    workflow = tmp_path / ".github" / "workflows" / "appguardrail-monitor.yml"
    workflow_text = workflow.read_text()
    assert workflow.exists()
    assert "name: AppGuardrail Monitor" in workflow_text
    assert "appguardrail scan ." in workflow_text
    assert "appguardrail-monitor.yml" in capsys.readouterr().out


def test_cmd_monitor_path_traversal(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    github_dir = tmp_path / ".github"
    github_dir.mkdir()
    outside_dir = tmp_path.parent / "outside_monitor_workflows"
    outside_dir.mkdir(exist_ok=True)
    _create_symlink(outside_dir, github_dir / "workflows", target_is_directory=True)

    assert cmd_monitor(MonitorArgs()) == 1
    assert "escapes the project root" in capsys.readouterr().err


def test_cmd_init_unknown_tool(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        cmd_init(Args(tool="invalid-tool"))

    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Error: Unknown tool 'invalid-tool'" in captured.err
    assert (
        "Supported tools are auto, cursor, codex, copilot, claude-code, windsurf, lovable"
        in captured.err
    )


def test_cmd_init_supabase_stack(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(stack="nextjs-supabase"))

    captured = capsys.readouterr()
    assert "Supabase stack detected. Quick reminders:" in captured.out
    assert "Enable RLS on every user-data table" in captured.out


def test_sanitize_terminal_output():
    from scanner.cli.appguardrail import _sanitize_terminal_output

    # Test normal strings
    assert _sanitize_terminal_output("normal string") == "normal string"
    assert _sanitize_terminal_output("tabs\tare\tallowed") == "tabs\tare\tallowed"

    # Test ANSI escape sequences (e.g. \033[2K clears line)
    assert _sanitize_terminal_output("malicious\033[2K") == "malicious\\x1b[2K"

    # Test carriage return and newline
    assert _sanitize_terminal_output("hidden\rmessage") == "hidden\\rmessage"
    assert _sanitize_terminal_output("line1\nline2") == "line1\\nline2"

    # Test non-strings
    assert _sanitize_terminal_output(None) is None


def test_scan_file_insecure_deserialization(tmp_path):
    test_file = tmp_path / "unsafe.py"
    test_file.write_text(
        "import marshal\n"
        "import pickle\n"
        "import yaml\n"
        "pickle.loads(data)\n"
        "yaml.load(raw_config)\n"
        "yaml.unsafe_load(raw_config)\n"
        "yaml.safe_load(trusted_config)\n"
        "marshal.load(stream)\n"
    )

    findings = [
        finding
        for finding in _scan_file(test_file, tmp_path)
        if finding["rule_id"] == "python-insecure-deserialization"
    ]

    assert len(findings) == 4
    assert [finding["line"] for finding in findings] == [4, 5, 6, 8]
    assert any("pickle.loads" in finding["snippet"] for finding in findings)
    assert any("yaml.load" in finding["snippet"] for finding in findings)
    assert any("yaml.unsafe_load" in finding["snippet"] for finding in findings)
    assert any("marshal.load" in finding["snippet"] for finding in findings)
    assert all("yaml.safe_load" not in finding["snippet"] for finding in findings)


def test_cmd_init_checklist_skipped(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    checklist_file = tmp_path / "APPGUARDRAIL_CHECKLIST.md"
    checklist_file.write_text("Existing checklist\n")

    cmd_init(Args(tool="cursor"))

    assert checklist_file.read_text() == "Existing checklist\n"
    out = capsys.readouterr().out
    assert "⏭️  Skipped (already configured):" in out
    assert "APPGUARDRAIL_CHECKLIST.md" in out


def test_cmd_init_prints_emoji_prefixes(tmp_path, monkeypatch, capsys):
    from collections import namedtuple

    from scanner.cli.appguardrail import cmd_init

    Args = namedtuple("Args", ["tool", "stack"])

    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="cursor", stack=None))

    out = capsys.readouterr().out
    assert "✨ Created/updated files:" in out
    assert "🚀 Next steps:" in out
