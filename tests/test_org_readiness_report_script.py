import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_render_script_writes_buyer_evidence_bundle(tmp_path):
    repos_json = tmp_path / "repos.json"
    prs_json = tmp_path / "prs.json"
    bundle_dir = tmp_path / "bundle"
    repos_json.write_text(
        json.dumps(
            [
                {
                    "name": "appguardrail",
                    "isFork": False,
                    "isPrivate": False,
                    "primaryLanguage": {"name": "Python"},
                    "defaultBranchRef": {"name": "develop"},
                },
                {
                    "name": "waf-ids-ai-soc",
                    "isFork": False,
                    "isPrivate": True,
                    "primaryLanguage": {"name": "Rust"},
                    "defaultBranchRef": {"name": "main"},
                },
            ]
        )
    )
    prs_json.write_text(
        json.dumps(
            [
                {
                    "number": 157,
                    "title": "Resolve source conflict",
                    "isDraft": False,
                    "mergeable": "CONFLICTING",
                    "mergeStateStatus": "DIRTY",
                    "reviewDecision": "",
                    "statusCheckRollup": [{"status": "QUEUED"}],
                }
            ]
        )
    )

    subprocess.run(
        [
            sys.executable,
            "scripts/ci/render_org_readiness_report.py",
            "--repos-json",
            str(repos_json),
            "--prs-json",
            str(prs_json),
            "--prs-repository",
            "ContextualWisdomLab/appguardrail",
            "--bundle-dir",
            str(bundle_dir),
            "--active-repository-target",
            "2",
            "--generated-at",
            "2026-07-03T00:00:00Z",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )

    report = (bundle_dir / "org-readiness.md").read_text()
    evidence = json.loads((bundle_dir / "buyer-evidence.json").read_text())
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    readme = (bundle_dir / "README.md").read_text()

    assert "Generated: 2026-07-03T00:00:00Z" in report
    assert evidence["overall_status"] == "fail"
    assert manifest["source"]["repositories"]["kind"] == "file"
    assert manifest["collection_warnings"] == []
    assert manifest["summary"]["open_pull_requests"] == 1
    assert manifest["summary"]["action_bucket_counts"]["source-work"] == 1
    assert manifest["artifacts"]["org_readiness_markdown"] == "org-readiness.md"
    assert "AppGuardrail Buyer Evidence Bundle" in readme
    assert "Largest action bucket: source-work (1)" in readme


def test_gh_pr_list_records_repo_collection_warnings(monkeypatch, capsys):
    from appguardrail_core import org_bundle

    def fake_gh_json(args):
        repo = args[args.index("--repo") + 1]
        if repo.endswith("/bad"):
            raise subprocess.CalledProcessError(
                1,
                args,
                stderr="HTTP 502: Bad Gateway",
            )
        return [{"number": 1, "title": "good"}]

    monkeypatch.setattr(org_bundle, "gh_json", fake_gh_json)

    pulls, warnings = org_bundle.gh_pr_list(
        "ContextualWisdomLab",
        [
            {"name": "good", "isFork": False},
            {"name": "bad", "isFork": False},
            {"name": "fork", "isFork": True},
        ],
        30,
    )

    assert [pull["repository"]["nameWithOwner"] for pull in pulls] == [
        "ContextualWisdomLab/good"
    ]
    assert warnings == [
        "Skipped PR collection for ContextualWisdomLab/bad: HTTP 502: Bad Gateway"
    ]
    assert (
        "warning: Skipped PR collection for ContextualWisdomLab/bad"
        in capsys.readouterr().err
    )
