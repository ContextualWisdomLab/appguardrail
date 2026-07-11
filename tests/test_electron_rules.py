"""Coverage tests for the Electron desktop-app security rule pack (6 rules)."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


CASES = {
    "electron-node-integration-enabled": (
        [
            "webPreferences: { nodeIntegration: true }",
            "nodeIntegration:true,",
        ],
        [
            "nodeIntegration: false",
            "nodeIntegrationInWorker: true",
            "app.setNodeIntegration(userPref)",
        ],
    ),
    "electron-context-isolation-disabled": (
        [
            "webPreferences: { contextIsolation: false }",
            "contextIsolation:false,",
        ],
        [
            "contextIsolation: true",
            "const contextIsolation = getSetting()",
        ],
    ),
    "electron-web-security-disabled": (
        [
            "webPreferences: { webSecurity: false }",
            "webSecurity:false",
        ],
        [
            "webSecurity: true",
            "// webSecurity stays enabled by default",
        ],
    ),
    "electron-allow-running-insecure-content": (
        [
            "allowRunningInsecureContent: true,",
            "webPreferences: { allowRunningInsecureContent:true }",
        ],
        [
            "allowRunningInsecureContent: false",
        ],
    ),
    "electron-shell-openexternal-user-input": (
        [
            "shell.openExternal(url)",
            "await shell.openExternal(event.data.href)",
            "shell.openExternal(`myapp://${target}`)",
        ],
        [
            "shell.openExternal('https://example.com/docs')",
            'shell.openExternal("mailto:support@example.com")',
            "shell.openExternal(`https://example.com/static`)",
        ],
    ),
    "electron-remote-module-enabled": (
        [
            "webPreferences: { enableRemoteModule: true }",
            "enableRemoteModule:true,",
        ],
        [
            "enableRemoteModule: false",
        ],
    ),
}

SEVERITIES = {
    "electron-node-integration-enabled": "CRITICAL",
    "electron-context-isolation-disabled": "CRITICAL",
    "electron-web-security-disabled": "HIGH",
    "electron-allow-running-insecure-content": "HIGH",
    "electron-shell-openexternal-user-input": "HIGH",
    "electron-remote-module-enabled": "WARNING",
}


@pytest.mark.parametrize("rule_id", CASES.keys())
def test_rule_precision(rule_id):
    rule = _rule(rule_id)
    positives, negatives = CASES[rule_id]
    for s in positives:
        assert rule["pattern"].search(s), f"{rule_id} should match: {s!r}"
    for s in negatives:
        assert not rule["pattern"].search(s), f"{rule_id} false-positive on: {s!r}"


@pytest.mark.parametrize("rule_id", SEVERITIES.keys())
def test_rule_severity(rule_id):
    assert _rule(rule_id)["severity"] == SEVERITIES[rule_id]


@pytest.mark.parametrize("rule_id", CASES.keys())
def test_rule_applies_to_all_extensions(rule_id):
    # languages: [generic] — Electron main-process code lives in .js/.ts/.mjs
    # files, so the rules must not be extension-scoped.
    assert _rule(rule_id)["extensions"] is None


def test_e2e_scan_vulnerable_electron_main(tmp_path):
    main_js = tmp_path / "main.js"
    main_js.write_text(
        "const { app, BrowserWindow, shell } = require('electron');\n"
        "function createWindow() {\n"
        "  const win = new BrowserWindow({\n"
        "    webPreferences: {\n"
        "      nodeIntegration: true,\n"
        "      contextIsolation: false,\n"
        "      webSecurity: false,\n"
        "      allowRunningInsecureContent: true,\n"
        "      enableRemoteModule: true,\n"
        "    },\n"
        "  });\n"
        "  win.webContents.setWindowOpenHandler(({ url }) => {\n"
        "    shell.openExternal(url);\n"
        "    return { action: 'deny' };\n"
        "  });\n"
        "}\n"
    )
    findings = _scan_file(main_js, tmp_path)
    rule_ids = {f["rule_id"] for f in findings}
    assert set(CASES.keys()) <= rule_ids


def test_e2e_scan_hardened_electron_main_is_clean(tmp_path):
    main_js = tmp_path / "main.js"
    main_js.write_text(
        "const { app, BrowserWindow, shell } = require('electron');\n"
        "function createWindow() {\n"
        "  const win = new BrowserWindow({\n"
        "    webPreferences: {\n"
        "      nodeIntegration: false,\n"
        "      contextIsolation: true,\n"
        "      preload: path.join(__dirname, 'preload.js'),\n"
        "    },\n"
        "  });\n"
        "  win.webContents.setWindowOpenHandler(() => {\n"
        "    shell.openExternal('https://example.com/help');\n"
        "    return { action: 'deny' };\n"
        "  });\n"
        "}\n"
    )
    findings = _scan_file(main_js, tmp_path)
    electron_hits = {
        f["rule_id"] for f in findings if f["rule_id"].startswith("electron-")
    }
    assert electron_hits == set()


def test_e2e_non_electron_code_not_flagged(tmp_path):
    # The same-looking config keys do not exist in ordinary web code; make
    # sure typical express/react code never trips the Electron pack.
    app_js = tmp_path / "server.js"
    app_js.write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/open', (req, res) => {\n"
        "  res.json({ isolation: false, integration: true });\n"
        "});\n"
        "window.open(externalUrl);\n"
    )
    findings = _scan_file(app_js, tmp_path)
    electron_hits = {
        f["rule_id"] for f in findings if f["rule_id"].startswith("electron-")
    }
    assert electron_hits == set()
