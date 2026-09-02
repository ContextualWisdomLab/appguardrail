"""Behavioral contracts for the deploy-blocking dashboard filter."""

import re
import subprocess

from scanner.cli.appguardrail import dashboard_index_path


def _dashboard_html() -> str:
    """Read the shipped dashboard asset used by the CLI server."""
    return dashboard_index_path().read_text(encoding="utf-8")


def _render_script_prefix(html: str) -> str:
    """Return the real dashboard script through `render` without boot side effects."""
    match = re.search(r"<script>(?P<script>[\s\S]*?)</script>", html)
    assert match is not None
    script = match.group("script")
    prefix, separator, _ = script.partition("function openDetail(f){")
    assert separator
    return prefix


def test_deploy_blocking_card_filter_contract_is_complete() -> None:
    """The card must expose pointer, keyboard, pressed-state, and filter wiring."""
    html = _dashboard_html()
    card = re.search(
        r'<div id="deploy-blocking-card" class="card"(?P<attrs>[^>]*)>',
        html,
    )

    assert card is not None
    attrs = card.group("attrs")
    assert 'role="button"' in attrs
    assert 'tabindex="0"' in attrs
    assert 'aria-pressed="${filterBlocking}"' in attrs
    assert 'onclick="filterBlocking=!filterBlocking; render();"' in attrs
    assert "event.key==='Enter'||event.key===' '" in attrs
    assert ".filter(({f})=> !filterBlocking || isDeployBlocking(f))" in html


def test_deploy_blocking_filter_executes_and_restores_focus() -> None:
    """Run the shipped render logic and verify filtering, pressed state, and focus."""
    html = _dashboard_html()
    script = _render_script_prefix(html)
    harness = r'''
const registry = new Map();
function makeElement(id) {
  return {
    id,
    _html: '',
    textContent: '',
    value: '',
    selectionStart: 0,
    selectionEnd: 0,
    listeners: {},
    addEventListener(type, fn) { this.listeners[type] = fn; },
    querySelectorAll() { return []; },
    focus() { document.activeElement = this; },
    setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; }
  };
}
const body = makeElement('body');
const app = makeElement('app');
const summary = makeElement('findings-summary');
Object.defineProperty(app, 'innerHTML', {
  get() { return this._html; },
  set(value) {
    this._html = value;
    registry.set('q', makeElement('q'));
    registry.set('sev', makeElement('sev'));
    if (value.includes('id="deploy-blocking-card"')) {
      registry.set('deploy-blocking-card', makeElement('deploy-blocking-card'));
    } else {
      registry.delete('deploy-blocking-card');
    }
  }
});
const document = {
  activeElement: body,
  getElementById(id) {
    if (id === 'app') return app;
    if (id === 'findings-summary') return summary;
    if (id === 'body') return body;
    return registry.get(id) || null;
  }
};
'''
    assertions = r'''
ALL = [
  {severity:'CRITICAL', context:'app-code', message:'blocking-one', file:'a.py', rule_id:'A', category:'security', line:1},
  {severity:'HIGH', context:'test', message:'nonblocking-test', file:'b.py', rule_id:'B', category:'security', line:2},
  {severity:'WARNING', context:'app-code', message:'warning-only', file:'c.py', rule_id:'C', category:'quality', line:3}
];
render();
const firstCard = registry.get('deploy-blocking-card');
if (!firstCard) throw new Error('deploy-blocking card was not rendered with a stable id');
firstCard.focus();
filterBlocking = !filterBlocking;
render();
if (!app.innerHTML.includes('blocking-one')) throw new Error('blocking finding disappeared');
if (app.innerHTML.includes('nonblocking-test')) throw new Error('non-blocking test finding leaked through filter');
if (app.innerHTML.includes('warning-only')) throw new Error('warning finding leaked through filter');
if (!app.innerHTML.includes('aria-pressed="true"')) throw new Error('pressed state did not follow filter state');
if (document.activeElement?.id !== 'deploy-blocking-card') throw new Error('focus was not restored to the replaced card');
'''

    completed = subprocess.run(
        ["node", "-e", harness + script + assertions],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
