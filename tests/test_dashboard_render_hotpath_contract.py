import subprocess
import json
import re
import tempfile
import os

def test_dashboard_render_hotpath_contract():
    """Extract and execute the exact filter/sort hot-path block from index.html
    to verify it correctly preserves legacy ordering and original `i` mapping
    for recognized, missing, and unknown severities."""

    with open("scanner/dashboard/index.html", encoding="utf-8") as f:
        html = f.read()

    # Extract SEV_ORDER and SEV_ORDER_MAP
    match_defs = re.search(r'(const SEV_ORDER = \[.*?\];\nconst SEV_ORDER_MAP = Object\.fromEntries.*?;\n)', html)
    assert match_defs is not None, "Could not find SEV_ORDER definitions in index.html"
    defs = match_defs.group(1)

    # Extract the sorting logic in render()
    match_sort = re.search(r'(\s*const filtered = \[\];.*?\n\s*filtered\.sort\(\(a, b\) => a\._sevOrder - b\._sevOrder\);)', html, re.DOTALL)
    assert match_sort is not None, "Could not find sorting logic in render()"
    sort_logic = match_sort.group(1)

    script = f"""
    {defs}
    const ALL = [
      {{ severity: 'INFO', file: 'd', message: 'test msg', rule_id: 'R1', category: 'C1' }},
      {{ severity: 'CRITICAL', file: 'a', message: 'test msg', rule_id: 'R1', category: 'C1' }},
      {{ severity: 'MISSING', file: 'e', message: 'test msg', rule_id: 'R1', category: 'C1' }},
      {{ file: 'f', message: 'test msg', rule_id: 'R1', category: 'C1' }},
      {{ severity: 'HIGH', file: 'b', message: 'test msg', rule_id: 'R1', category: 'C1' }},
      {{ severity: 'UNKNOWN', file: 'g', message: 'test msg', rule_id: 'R1', category: 'C1' }},
      {{ severity: 'WARNING', file: 'c', message: 'test msg', rule_id: 'R1', category: 'C1' }}
    ];
    let filterSev = '';
    let query = '';

    // Simulate exact legacy logic (indexOf returning -1 for unknown/missing)
    const exactLegacy = ALL.map((f,i)=>({{f,i}})).sort((a,b)=> SEV_ORDER.indexOf(String(a.f.severity).toUpperCase()) - SEV_ORDER.indexOf(String(b.f.severity).toUpperCase()));

    {sort_logic}

    console.log(JSON.stringify({{
        legacy: exactLegacy.map(x => x.f.file),
        new: filtered.map(x => x.f.file),
        legacyIdx: exactLegacy.map(x => x.i),
        newIdx: filtered.map(x => x.i)
    }}));
    """

    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(script)
        temp_name = f.name

    try:
        out = subprocess.check_output(["node", temp_name]).decode("utf-8")
        data = json.loads(out)
        assert data["legacy"] == data["new"]
        assert data["legacyIdx"] == data["newIdx"]
    finally:
        os.remove(temp_name)
