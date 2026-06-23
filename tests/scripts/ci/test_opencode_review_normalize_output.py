from scripts.ci.opencode_review_normalize_output import iter_json_objects, main


def test_iter_json_objects_pure_json_once():
    assert iter_json_objects('{"a": 1}') == [{"a": 1}]


def test_iter_json_objects_with_prose_and_multiple_objects():
    text = 'review: {"a": 1} next {"b": {"c": 2}} done'
    assert iter_json_objects(text) == [{"a": 1}, {"b": {"c": 2}}]


def test_iter_json_objects_skips_invalid_and_partial_json():
    assert iter_json_objects("not json") == []
    assert iter_json_objects('before {"a": after') == []


def test_main_accepts_workflow_temp_output_file(tmp_path, monkeypatch):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    outside_file = tmp_path / "opencode-output.txt"
    outside_file.write_text(
        (
            '{"head_sha":"sha","run_id":"run","run_attempt":"1","result":"APPROVE",'
            '"reason":"Reviewed scripts/ci/opencode_review_normalize_output.py on current head.",'
            '"summary":"No blockers after inspecting scripts/ci/opencode_review_normalize_output.py.",'
            '"findings":[]}'
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(project_root)

    result = main(["prog", "sha", "run", "1", str(outside_file)])

    assert result == 0
    assert (
        "<!-- opencode-review-gate head_sha=sha run_id=run run_attempt=1 -->"
        in outside_file.read_text(encoding="utf-8")
    )


def test_main_amends_approve_summary_from_bounded_changed_file_evidence(tmp_path):
    output_file = tmp_path / "opencode-output.md"
    evidence_file = tmp_path / "bounded-review-evidence.md"
    output_file.write_text(
        (
            '{"head_sha":"sha","run_id":"run","run_attempt":"1","result":"APPROVE",'
            '"reason":"No blocking issues found.",'
            '"summary":"Inspected changed files and found no actionable blockers.",'
            '"findings":[]}'
        ),
        encoding="utf-8",
    )
    evidence_file.write_text(
        (
            "# OpenCode bounded PR review evidence\n\n"
            "## Changed files\n\n"
            "M\tscanner/cli/vibesec.py\n"
            "A\ttests/test_vibesec.py\n\n"
            "## Focused changed hunks\n\n"
        ),
        encoding="utf-8",
    )

    result = main(["prog", "sha", "run", "1", str(output_file), str(evidence_file)])

    normalized = output_file.read_text(encoding="utf-8")
    assert result == 0
    assert "Changed-file evidence: scanner/cli/vibesec.py" in normalized


def test_main_rejects_pathless_approve_summary_without_bounded_evidence(tmp_path):
    output_file = tmp_path / "opencode-output.md"
    output_file.write_text(
        (
            '{"head_sha":"sha","run_id":"run","run_attempt":"1","result":"APPROVE",'
            '"reason":"No blocking issues found.",'
            '"summary":"Inspected changed files and found no actionable blockers.",'
            '"findings":[]}'
        ),
        encoding="utf-8",
    )

    assert main(["prog", "sha", "run", "1", str(output_file)]) == 4
