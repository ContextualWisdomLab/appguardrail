1. Add strict `Number()` coercion and explicit `esc()` escaping in `scanner/dashboard/console.html` to prevent DOM XSS vulnerabilities when interpolating variables sourced from JSON payloads directly into `innerHTML`.
   - Update `["Latest deploy-blocking",latest.deploy_blocking||0]` etc. to use `Number(latest.deploy_blocking)||0`.
   - Update `<td>${s.total}</td>` to `<td>${Number(s.total)||0}</td>`.
   - Update `data-id="${s.id}"` to `data-id="${esc(s.id)}"`.
   - Update `<table id="history">` generation.
2. Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.
3. Submit the change with a descriptive commit message.
