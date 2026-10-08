fpath = "scanner/dashboard/index.html"
with open(fpath) as f:
    html = f.read()

html = html.replace(
    '  const sevKey = Object.hasOwn(SEV, f.severity) ? f.severity : \'INFO\';\n  const ctx = String(f.context||\'app-code\');',
    '  const s = String(f.severity||\'INFO\').toUpperCase();\n  const sevKey = Object.hasOwn(SEV, s) ? s : \'INFO\';\n  const ctx = String(f.context||\'app-code\');'
)

html = html.replace(
    '  for(const f of ALL){\n    const sevKey = Object.hasOwn(SEV, f.severity) ? f.severity : \'INFO\';',
    '  for(const f of ALL){\n    const s = String(f.severity||\'INFO\').toUpperCase();\n    const sevKey = Object.hasOwn(SEV, s) ? s : \'INFO\';'
)

html = html.replace(
    '    .filter(({f})=> {\n      const sevKey = Object.hasOwn(SEV, f.severity) ? f.severity : \'INFO\';',
    '    .filter(({f})=> {\n      const s = String(f.severity||\'INFO\').toUpperCase();\n      const sevKey = Object.hasOwn(SEV, s) ? s : \'INFO\';'
)

html = html.replace(
    '    .sort((a,b)=> {\n      const keyA = Object.hasOwn(SEV, a.f.severity) ? a.f.severity : \'INFO\';\n      const keyB = Object.hasOwn(SEV, b.f.severity) ? b.f.severity : \'INFO\';',
    '    .sort((a,b)=> {\n      const sA = String(a.f.severity||\'INFO\').toUpperCase();\n      const keyA = Object.hasOwn(SEV, sA) ? sA : \'INFO\';\n      const sB = String(b.f.severity||\'INFO\').toUpperCase();\n      const keyB = Object.hasOwn(SEV, sB) ? sB : \'INFO\';'
)

html = html.replace(
    '  const rows = filtered.map(({f,i})=>{\n    const sevKey = Object.hasOwn(SEV, f.severity) ? f.severity : \'INFO\';\n    const s = f.severity || \'INFO\';',
    '  const rows = filtered.map(({f,i})=>{\n    const s = String(f.severity||\'INFO\').toUpperCase();\n    const sevKey = Object.hasOwn(SEV, s) ? s : \'INFO\';'
)

html = html.replace(
    'function openDetail(f){\n  lastFocus = document.activeElement;\n  const sevKey = Object.hasOwn(SEV, f.severity) ? f.severity : \'INFO\';\n  const s = f.severity || \'INFO\';',
    'function openDetail(f){\n  lastFocus = document.activeElement;\n  const s = String(f.severity||\'INFO\').toUpperCase();\n  const sevKey = Object.hasOwn(SEV, s) ? s : \'INFO\';'
)

with open(fpath, "w") as f:
    f.write(html)
