"""Tests for the Strix-corpus aggregated detection rule pack.

Every rule in ``scanner/rules/strix-aggregated.yml`` encodes a concrete
vulnerability class that the organization Strix Security Scan flagged across
ContextualWisdomLab repositories. These tests assert each rule matches the
vulnerable idiom, does not fire on the safe alternative, keeps a stable
severity, and that an end-to-end scan of a synthetic tree surfaces them all.
"""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_IDS = {
    "python-numpy-load-allow-pickle",
    "python-xml-insecure-parser",
    "python-gethostbyname-ssrf-bypass",
    "python-ffmpeg-missing-protocol-whitelist",
    "python-copymode-preserves-setuid",
    "weak-hash-md5-sha1",
}

_BY_ID = {}
for _rule in SCAN_RULES:
    if _rule["id"] in _RULE_IDS:
        _BY_ID.setdefault(_rule["id"], []).append(_rule)


def _rules(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def _matches(rule_id, text):
    return any(rule["pattern"].search(text) for rule in _rules(rule_id))


def _severity(rule_id):
    severities = {rule["severity"] for rule in _rules(rule_id)}
    assert len(severities) == 1, f"{rule_id} has inconsistent severity"
    return severities.pop()


# ---------------------------------------------------------------------------
# All six rules are expected to load from the packaged YAML.
# ---------------------------------------------------------------------------


def test_all_strix_rules_loaded():
    assert set(_BY_ID) == _RULE_IDS


# ---------------------------------------------------------------------------
# python-numpy-load-allow-pickle (CWE-502)
# ---------------------------------------------------------------------------


def test_numpy_allow_pickle_positive():
    assert _matches("python-numpy-load-allow-pickle", "w = np.load(path, allow_pickle=True)")
    assert _matches("python-numpy-load-allow-pickle", "numpy.load(f, allow_pickle = True)")


def test_numpy_allow_pickle_negative():
    assert not _matches("python-numpy-load-allow-pickle", "w = np.load(path)")
    assert not _matches("python-numpy-load-allow-pickle", "np.load(p, allow_pickle=False)")


def test_numpy_allow_pickle_severity():
    assert _severity("python-numpy-load-allow-pickle") == "CRITICAL"


# ---------------------------------------------------------------------------
# python-xml-insecure-parser (CWE-611)
# ---------------------------------------------------------------------------


def test_xml_parser_positive():
    assert _matches("python-xml-insecure-parser", "root = xml.etree.ElementTree.fromstring(data)")
    assert _matches("python-xml-insecure-parser", "doc = minidom.parseString(payload)")
    assert _matches("python-xml-insecure-parser", "p = xml.sax.make_parser()")
    assert _matches("python-xml-insecure-parser", "tree = lxml.etree.parse(src)")


def test_xml_parser_negative():
    assert not _matches("python-xml-insecure-parser", "data = json.parse(body)")
    assert not _matches("python-xml-insecure-parser", "cfg = tree.parse_config(path)")


def test_xml_parser_severity():
    assert _severity("python-xml-insecure-parser") == "HIGH"


# ---------------------------------------------------------------------------
# python-gethostbyname-ssrf-bypass (CWE-918)
# ---------------------------------------------------------------------------


def test_gethostbyname_positive():
    assert _matches("python-gethostbyname-ssrf-bypass", "ip = socket.gethostbyname(host)")
    assert _matches("python-gethostbyname-ssrf-bypass", "socket.gethostbyname_ex(target)")


def test_gethostbyname_negative():
    assert not _matches("python-gethostbyname-ssrf-bypass", "infos = socket.getaddrinfo(host, None)")


def test_gethostbyname_severity():
    assert _severity("python-gethostbyname-ssrf-bypass") == "MEDIUM"


# ---------------------------------------------------------------------------
# python-ffmpeg-missing-protocol-whitelist (CWE-918)
# ---------------------------------------------------------------------------


def test_ffmpeg_missing_whitelist_positive():
    assert _matches(
        "python-ffmpeg-missing-protocol-whitelist",
        'subprocess.run(["ffmpeg", "-i", src])',
    )
    assert _matches(
        "python-ffmpeg-missing-protocol-whitelist",
        "subprocess.check_output(['ffprobe', '-v', 'quiet', path])",
    )


def test_ffmpeg_with_whitelist_negative():
    assert not _matches(
        "python-ffmpeg-missing-protocol-whitelist",
        'subprocess.run(["ffmpeg", "-protocol_whitelist", "file,crypto,data", "-i", src])',
    )
    # An unrelated subprocess call must not trip the ffmpeg rule.
    assert not _matches(
        "python-ffmpeg-missing-protocol-whitelist",
        'subprocess.run(["convert", "a.png", "b.jpg"])',
    )


def test_ffmpeg_missing_whitelist_severity():
    assert _severity("python-ffmpeg-missing-protocol-whitelist") == "HIGH"


# ---------------------------------------------------------------------------
# python-copymode-preserves-setuid (CWE-732)
# ---------------------------------------------------------------------------


def test_copymode_positive():
    assert _matches("python-copymode-preserves-setuid", "shutil.copymode(src, dst)")
    assert _matches("python-copymode-preserves-setuid", "shutil.copystat(a, b)")


def test_copymode_negative():
    assert not _matches("python-copymode-preserves-setuid", "shutil.copyfile(a, b)")
    assert not _matches("python-copymode-preserves-setuid", "shutil.copytree(x, y)")


def test_copymode_severity():
    assert _severity("python-copymode-preserves-setuid") == "MEDIUM"


# ---------------------------------------------------------------------------
# weak-hash-md5-sha1 (CWE-328) — spans Python and JS/TS.
# ---------------------------------------------------------------------------


def test_weak_hash_positive():
    assert _matches("weak-hash-md5-sha1", "digest = hashlib.md5(data).hexdigest()")
    assert _matches("weak-hash-md5-sha1", "fp = hashlib.sha1(body[:500])")
    assert _matches("weak-hash-md5-sha1", "const h = crypto.createHash('md5')")


def test_weak_hash_negative():
    assert not _matches("weak-hash-md5-sha1", "digest = hashlib.sha256(data)")
    assert not _matches("weak-hash-md5-sha1", "const h = crypto.createHash('sha256')")


def test_weak_hash_severity():
    assert _severity("weak-hash-md5-sha1") == "MEDIUM"


# ---------------------------------------------------------------------------
# End-to-end: a synthetic tree of vulnerable files surfaces every rule, and a
# hardened counterpart file produces none of these findings.
# ---------------------------------------------------------------------------


def test_end_to_end_scan_flags_every_rule(tmp_path):
    vuln_py = tmp_path / "vuln.py"
    vuln_py.write_text(
        "import numpy as np, shutil, socket, subprocess, hashlib\n"
        "import xml.etree.ElementTree as ElementTree\n"
        "w = np.load(p, allow_pickle=True)\n"
        "root = ElementTree.fromstring(body)\n"
        "ip = socket.gethostbyname(host)\n"
        "subprocess.run(['ffmpeg', '-i', src])\n"
        "shutil.copymode(src, dst)\n"
        "fp = hashlib.md5(data)\n",
        encoding="utf-8",
    )
    vuln_js = tmp_path / "vuln.js"
    vuln_js.write_text("const h = crypto.createHash('sha1');\n", encoding="utf-8")

    findings = _scan_file(vuln_py, tmp_path) + _scan_file(vuln_js, tmp_path)
    flagged = {f["rule_id"] for f in findings}
    assert _RULE_IDS <= flagged, f"missing: {_RULE_IDS - flagged}"


def test_end_to_end_scan_clean_on_hardened_file(tmp_path):
    safe_py = tmp_path / "safe.py"
    safe_py.write_text(
        "import numpy as np, socket, subprocess, hashlib\n"
        "import defusedxml.ElementTree as ET\n"
        "w = np.load(p, allow_pickle=False)\n"
        "root = ET.fromstring(body)\n"
        "infos = socket.getaddrinfo(host, None)\n"
        "subprocess.run(['ffmpeg', '-protocol_whitelist', 'file,crypto,data', '-i', src])\n"
        "fp = hashlib.sha256(data)\n",
        encoding="utf-8",
    )
    findings = _scan_file(safe_py, tmp_path)
    flagged = {f["rule_id"] for f in findings}
    assert not (_RULE_IDS & flagged), f"unexpected: {_RULE_IDS & flagged}"
