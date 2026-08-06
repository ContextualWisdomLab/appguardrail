"""Apply the reviewed dashboard status contract and remove after verification."""

from __future__ import annotations

from pathlib import Path


DASHBOARD_PATH = Path("scanner/dashboard/index.html")
PALETTE_PATH = Path(".jules/palette.md")
CHANGELOG_PATH = Path("CHANGELOG.d/879-880-dashboard-status.md")


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    """Replace one exact source contract or fail without partial output."""
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def _update_dashboard() -> None:
    """Separate unloaded and clean reports while centralizing count grammar."""
    text = DASHBOARD_PATH.read_text(encoding="utf-8")
    text = _replace_once(
        text,
        """function isDeployBlocking(f){
  const sev = String(f.severity||'INFO').toUpperCase();
  const ctx = String(f.context||'app-code');
  return BLOCKING_SEV.has(sev) && !NON_BLOCKING.has(ctx);
}
function esc(s){return String(s==null?'':s).replace(/[&<>\"'`]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;','`':'&#96;'}[c]));}
""",
        """function isDeployBlocking(f){
  const sev = String(f.severity||'INFO').toUpperCase();
  const ctx = String(f.context||'app-code');
  return BLOCKING_SEV.has(sev) && !NON_BLOCKING.has(ctx);
}
function formatFindingCount(count){
  return `${count} ${count === 1 ? 'finding' : 'findings'}`;
}
function esc(s){return String(s==null?'':s).replace(/[&<>\"'`]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;','`':'&#96;'}[c]));}
""",
        "finding count formatter",
    )
    text = _replace_once(text, "let ALL = [];", "let ALL = null;", "loaded-state sentinel")
    text = _replace_once(text, "  if(!ALL.length){", "  if(!ALL){", "unloaded-state guard")
    text = _replace_once(
        text,
        """    browseFindings.addEventListener('click', () => fileInput.click());
    return;
  }
  const counts = {CRITICAL:0,HIGH:0,WARNING:0,INFO:0};
""",
        """    browseFindings.addEventListener('click', () => fileInput.click());
    return;
  }
  if(ALL.length === 0){
    if (liveSummary) liveSummary.textContent = 'Clean scan · 0 findings · deploy gate clear';
    app.innerHTML = `<div class=\"empty\">
      <h1>Clean scan</h1>
      <p>No findings were detected in this report. The deploy gate is clear.</p>
      <p id=\"findings-upload-help\" class=\"drop\">Load a different <code>findings.json</code> file to review another report.</p>
      <p><button type=\"button\" id=\"browse-findings\" class=\"primary-action\" aria-describedby=\"findings-upload-help\">Browse findings.json</button></p>
    </div>`;
    const browseFindings = document.getElementById('browse-findings');
    const fileInput = document.getElementById('file');
    browseFindings.addEventListener('click', () => fileInput.click());
    return;
  }
  const counts = {CRITICAL:0,HIGH:0,WARNING:0,INFO:0};
""",
        "clean-scan state",
    )
    text = _replace_once(
        text,
        """  const findingsText = filtered.length === ALL.length
    ? `${ALL.length} findings`
    : `${filtered.length} of ${ALL.length} findings`;
""",
        """  const allFindingsText = formatFindingCount(ALL.length);
  const findingsText = filtered.length === ALL.length
    ? allFindingsText
    : `${filtered.length} of ${allFindingsText}`;
""",
        "filtered count grammar",
    )
    text = _replace_once(
        text,
        """  document.getElementById('src').textContent = `${srcLabel} · ${findings.length} findings${data.schema?` · ${data.schema}`:''}`;
""",
        """  document.getElementById('src').textContent = `${srcLabel} · ${formatFindingCount(findings.length)}${data.schema?` · ${data.schema}`:''}`;
""",
        "loaded source count grammar",
    )
    DASHBOARD_PATH.write_text(text, encoding="utf-8")


def _update_documentation() -> None:
    """Record the bounded accessibility decision and release-facing change."""
    palette = PALETTE_PATH.read_text(encoding="utf-8").rstrip()
    marker = "## 2026-08-06 - Dashboard status semantics"
    if marker not in palette:
        palette += """

## 2026-08-06 - Dashboard status semantics
**Learning:** A loaded report with zero findings is a successful security outcome, not the same state as missing input. Announcing the same update through multiple live regions can also create duplicate screen-reader output.
**Action:** Keep one pre-existing polite, atomic status region; separate the unloaded and clean-report states with an explicit loaded sentinel; and centralize English finding-count grammar in one formatter.
"""
    PALETTE_PATH.write_text(palette + "\n", encoding="utf-8")
    CHANGELOG_PATH.write_text(
        """### Changed

- Distinguished an unloaded dashboard from a successfully loaded clean scan, including a clear deploy-gate outcome and replacement-file action.
- Centralized singular and plural finding counts while retaining one polite, atomic screen-reader status region to prevent duplicate announcements.
""",
        encoding="utf-8",
    )


def main() -> None:
    """Apply dashboard, documentation, and changelog updates deterministically."""
    _update_dashboard()
    _update_documentation()


if __name__ == "__main__":
    main()
