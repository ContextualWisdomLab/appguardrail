"""Executable regressions for untrusted dashboard severity values."""

import json
import subprocess
from pathlib import Path


CONSOLE_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"
)

NODE_CONSOLE_PROBE = r"""
const fs = require("fs");
const vm = require("vm");

const html = fs.readFileSync(process.argv[1], "utf8");
const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].at(-1)[1];
const elements = new Map();
function element() {
  return {
    innerHTML: "",
    textContent: "",
    value: "",
    dataset: {},
    isConnected: true,
    classList: {add() {}, remove() {}, contains() { return true; }},
    addEventListener() {},
    removeAttribute() {},
    setAttribute() {},
    focus() {},
    scrollIntoView() {},
    querySelector() { return element(); },
    querySelectorAll() { return []; },
  };
}
for (const id of ["connect", "key", "logout", "detail"]) {
  elements.set(id, element());
}

const finding = {
  severity: "constructor",
  rule_id: "rule",
  message: "message",
  file: "file.py",
  line: 7,
};
const context = {
  console,
  document: {
    activeElement: null,
    addEventListener() {},
    querySelector(selector) { return elements.get(selector.slice(1)); },
  },
  fetch: async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      id: 1,
      created_at: "2026-10-01T00:00:00Z",
      repo: "ContextualWisdomLab/appguardrail",
      findings: [finding],
    }),
  }),
  HTMLElement: class {},
  location: {reload() {}},
  sessionStorage: {getItem() { return null; }, setItem() {}, removeItem() {}},
  window: {matchMedia() { return {matches: true}; }},
};
vm.createContext(context);
vm.runInContext(script, context);
vm.runInContext("detail('1')", context).then(() => {
  process.stdout.write(JSON.stringify({html: elements.get("detail").innerHTML}));
});
"""


def test_console_inherited_severity_key_uses_info_color() -> None:
    """An inherited Object key must not override the fixed INFO fallback."""
    completed = subprocess.run(
        ["node", "-e", NODE_CONSOLE_PROBE, str(CONSOLE_PATH)],
        check=True,
        capture_output=True,
        text=True,
    )
    rendered = json.loads(completed.stdout)["html"]

    assert 'style="background:var(--info)"' in rendered
    assert "function Object()" not in rendered
    assert ">constructor</span>" in rendered
