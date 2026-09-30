import pytest
import os
import re

def test_hostile_severity_regression():
    html_path = os.path.join(os.path.dirname(__file__), "..", "scanner", "dashboard", "index.html")
    with open(html_path, 'r', encoding='utf-8') as f:
        html = f.read()

    # Check that the fixed behavior (Object.hasOwn) is present
    assert bool(re.search(r'Object\.hasOwn\(SEV, s\)', html)) == True

    # Verify that the direct object interpolation (SEV[s] without escaping or Object.hasOwn check in template literal) is removed.
    # We want to ensure things like SEV[s]?SEV[s].color are gone, but we still allow SEV[s].color if it's protected by Object.hasOwn
    assert bool(re.search(r'\$\{SEV\[s\]\?SEV\[s\]\.color:\'var\(--info\)\'\}', html)) == False

    html_console_path = os.path.join(os.path.dirname(__file__), "..", "scanner", "dashboard", "console.html")
    with open(html_console_path, 'r', encoding='utf-8') as f:
        html_console = f.read()

    assert bool(re.search(r'Object\.hasOwn\(SEV, f\.severity\)', html_console)) == True
    assert bool(re.search(r'\$\{SEV\[f\.severity\]\|\|\'var\(--info\)\'\}', html_console)) == False
