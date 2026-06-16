import pytest
from scripts.ci.opencode_review_normalize_output import iter_json_objects

def test_iter_json_objects_pure_json():
    text = '{"a": 1}'
    result = iter_json_objects(text)
    assert result == [{"a": 1}, {"a": 1}]

def test_iter_json_objects_with_prose():
    text = 'Here is the result: {"a": 1} Thanks.'
    result = iter_json_objects(text)
    assert result == [{"a": 1}]

def test_iter_json_objects_multiple_objects():
    text = '{"a": 1} and {"b": 2}'
    result = iter_json_objects(text)
    assert result == [{"a": 1}, {"b": 2}]

def test_iter_json_objects_nested():
    text = '{"a": {"b": 1}}'
    result = iter_json_objects(text)
    assert result == [{"a": {"b": 1}}, {"a": {"b": 1}}, {"b": 1}]

def test_iter_json_objects_invalid():
    text = "Not a json"
    result = iter_json_objects(text)
    assert result == []

def test_iter_json_objects_partial():
    text = '{"a": '
    result = iter_json_objects(text)
    assert result == []
