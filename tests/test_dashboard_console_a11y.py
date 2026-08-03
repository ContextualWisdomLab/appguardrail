import pytest
import os
import re

def test_console_dashboard_a11y_contracts():
    """
    Focused regression test to verify:
    1. <th> elements have scope="col"
    2. Interactive <tr> rows have title (not aria-label)
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(repo_root, "scanner", "dashboard", "console.html")

    with open(file_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    # 1. Verify <th> elements have scope="col"
    th_tags = re.findall(r'<th[\s>][^>]*>', html_content)
    assert len(th_tags) > 0, "Expected table headers to be present"
    for th in th_tags:
        assert 'scope="col"' in th, f"Expected th to have scope='col', got {th}"

    # 2. Verify interactive <tr> rows have title (not aria-label)
    interactive_row_tags = re.findall(r'<tr[^>]*role="button"[^>]*>', html_content)
    assert len(interactive_row_tags) > 0, "Expected interactive row to be present"
    for tr in interactive_row_tags:
        assert 'title=' in tr, f"Expected title on interactive row, got {tr}"
        assert 'aria-label=' not in tr, f"Expected no aria-label on interactive row, got {tr}"
