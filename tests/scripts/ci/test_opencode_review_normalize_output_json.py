from scripts.ci.opencode_review_normalize_output import iter_json_objects

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
