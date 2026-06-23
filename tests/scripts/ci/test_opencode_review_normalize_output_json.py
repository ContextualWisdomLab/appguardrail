from scripts.ci.opencode_review_normalize_output import iter_json_objects, main


def test_iter_json_objects():
    text = 'some prose {"a": 1} more prose {"b": [2, 3]} end'
    objects = iter_json_objects(text)
    assert len(objects) == 2
    assert objects[0] == {"a": 1}
    assert objects[1] == {"b": [2, 3]}


def test_iter_json_objects_invalid():
    text = 'some prose {invalid json} more prose {"b": 2} end'
    objects = iter_json_objects(text)
    assert len(objects) == 1
    assert objects[0] == {"b": 2}


def test_iter_json_objects_empty():
    text = 'no json here'
    objects = iter_json_objects(text)
    assert len(objects) == 0


def test_normalizer_accepts_temp_output_file_outside_repo(tmp_path):
    output_file = tmp_path / "opencode-output.md"
    output_file.write_text(
        '{"head_sha":"abc123","run_id":"42","run_attempt":"1",'
        '"result":"APPROVE",'
        '"reason":"No blockers after reviewing scripts/ci/opencode_review_normalize_output.py.",'
        '"summary":"Reviewed scripts/ci/opencode_review_normalize_output.py and tests/scripts/ci/test_opencode_review_normalize_output_json.py.",'
        '"findings":[]}',
        encoding="utf-8",
    )

    assert main(["opencode_review_normalize_output.py", "abc123", "42", "1", str(output_file)]) == 0
    assert "<!-- opencode-review-control-v1" in output_file.read_text(encoding="utf-8")
