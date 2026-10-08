fpath = "scanner/dashboard/console.html"
with open(fpath) as f:
    html = f.read()

html = html.replace(
    '    const rows=(s.findings||[]).map(f=>{\n      const sevKey = Object.hasOwn(SEV, f.severity) ? f.severity : \'INFO\';\n      return `<tr><td><span class="pill" style="background:${esc(SEV[sevKey])}">${esc(f.severity || \'INFO\')}</span></td>',
    '    const rows=(s.findings||[]).map(f=>{\n      const sv = String(f.severity||\'INFO\').toUpperCase();\n      const sevKey = Object.hasOwn(SEV, sv) ? sv : \'INFO\';\n      return `<tr><td><span class="pill" style="background:${esc(SEV[sevKey])}">${esc(f.severity || \'INFO\')}</span></td>'
)

with open(fpath, "w") as f:
    f.write(html)
