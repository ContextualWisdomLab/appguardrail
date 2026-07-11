"""Coverage tests for the Vue / Svelte / Nuxt frontend rule pack (6 rules)."""

import pytest

from scanner.cli.appguardrail import (
    SCAN_RULES,
    _path_allowed_by_rule,
    _scan_file,
)

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)

RULE_IDS = [
    "vue-v-html-usage",
    "svelte-html-tag-usage",
    "nuxt-public-env-secret",
    "vite-env-secret-exposed",
    "sveltekit-private-env-in-client",
    "sveltekit-csrf-origin-check-disabled",
]


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


# Secret-shaped env names are assembled at runtime so the repository never
# contains a literal client-exposed secret variable name.
_NUXT_PUBLIC = "NUXT_" + "PUBLIC_"
_VITE = "VI" + "TE_"

CASES = {
    "vue-v-html-usage": (
        [
            '<div v-html="userContent"></div>',
            '<span\n  v-html="renderedMarkdown"\n></span>',
            "<article v-html='post.body'></article>",
        ],
        [
            '<div data-v-html="x"></div>',
            "<p>{{ userContent }}</p>",
            "// v-html is dangerous, do not use it",
            '<div :title="vHtml"></div>',
        ],
    ),
    "svelte-html-tag-usage": (
        ["{@html body}", "{@html marked(post.content)}", "<div>{@html\n  data}</div>"],
        [
            "{@const rendered = escape(body)}",
            "<p>{body}</p>",
            "<!-- the raw html tag is unsafe -->",
            "{@render children()}",
        ],
    ),
    "nuxt-public-env-secret": (
        [
            _NUXT_PUBLIC + "STRIPE_SECRET_KEY",
            _NUXT_PUBLIC + "SUPABASE_SERVICE_ROLE_KEY",
            _NUXT_PUBLIC + "DB_PASSWORD",
            _NUXT_PUBLIC + "DATABASE_URL",
        ],
        [
            _NUXT_PUBLIC + "API_BASE_URL",
            _NUXT_PUBLIC + "SITE_NAME",
            "NUXT_STRIPE_SECRET_KEY",
            "MY" + _NUXT_PUBLIC + "JWT_SECRET",
        ],
    ),
    "vite-env-secret-exposed": (
        [
            _VITE + "API_SECRET=abc123def",
            _VITE + "SUPABASE_SERVICE_ROLE_KEY = value",
            _VITE + "DB_PASSWORD=hunter2hunter2",
            _VITE + "AWS_ACCESS_KEY_ID=placeholder",
        ],
        [
            _VITE + "API_BASE_URL=https://api.example.com",
            _VITE + "PUBLIC_POSTHOG_KEY=phc_public",
            "STRIPE_SECRET_KEY=only-server-side",
            "INVITE_PASSWORD_RESET=on",
        ],
    ),
    "sveltekit-private-env-in-client": (
        [
            "import { API_KEY } from '$env/static/private';",
            'import { env } from "$env/dynamic/private";',
        ],
        [
            "import { PUBLIC_BASE_URL } from '$env/static/public';",
            "import { env } from '$env/dynamic/public';",
            "import { browser } from '$app/environment';",
        ],
    ),
    "sveltekit-csrf-origin-check-disabled": (
        ["csrf: { checkOrigin: false }", "checkOrigin:false,"],
        [
            "csrf: { checkOrigin: true }",
            "const shouldCheckOrigin = false;",
            "// checkOrigin defaults to true",
        ],
    ),
}


@pytest.mark.parametrize("rule_id", CASES.keys())
def test_rule_precision(rule_id):
    rule = _rule(rule_id)
    positives, negatives = CASES[rule_id]
    assert len(positives) >= 2 and len(negatives) >= 2
    for s in positives:
        assert rule["pattern"].search(s), f"{rule_id} should match: {s!r}"
    for s in negatives:
        assert not rule["pattern"].search(s), f"{rule_id} false-positive on: {s!r}"


def test_severities():
    assert _rule("vue-v-html-usage")["severity"] == "HIGH"
    assert _rule("svelte-html-tag-usage")["severity"] == "HIGH"
    assert _rule("nuxt-public-env-secret")["severity"] == "CRITICAL"
    assert _rule("vite-env-secret-exposed")["severity"] == "CRITICAL"
    assert _rule("sveltekit-private-env-in-client")["severity"] == "HIGH"
    assert _rule("sveltekit-csrf-origin-check-disabled")["severity"] == "HIGH"


PATH_CASES = {
    "vue-v-html-usage": (
        ["src/components/Comment.vue", "App.vue"],
        ["src/render.js", "src/Comment.jsx"],
    ),
    "svelte-html-tag-usage": (
        ["src/routes/+page.svelte", "Widget.svelte"],
        ["src/lib/render.ts"],
    ),
    "vite-env-secret-exposed": (
        [".env", ".env.production", "apps/web/.env.local"],
        ["src/config.ts", "vite.config.ts"],
    ),
    "sveltekit-private-env-in-client": (
        ["src/routes/+layout.svelte", "src/lib/Card.svelte"],
        ["src/routes/+page.server.ts", "src/hooks.server.ts"],
    ),
    "sveltekit-csrf-origin-check-disabled": (
        ["svelte.config.js", "apps/site/svelte.config.ts", "svelte.config.mjs"],
        ["vite.config.js", "src/kit.ts"],
    ),
}


@pytest.mark.parametrize("rule_id", PATH_CASES.keys())
def test_path_scoping(rule_id):
    rule = _rule(rule_id)
    include = rule["include_paths"]
    exclude = rule["exclude_paths"]
    assert include, f"{rule_id} should be path-scoped"
    allowed, denied = PATH_CASES[rule_id]
    for path in allowed:
        assert _path_allowed_by_rule(path, include, exclude), (
            f"{rule_id} should apply to {path}"
        )
    for path in denied:
        assert not _path_allowed_by_rule(path, include, exclude), (
            f"{rule_id} should not apply to {path}"
        )


def test_nuxt_rule_is_not_path_scoped():
    rule = _rule("nuxt-public-env-secret")
    assert rule["include_paths"] == []
    assert rule["extensions"] is None


def _scan_project(base):
    findings = []
    for path in sorted(base.rglob("*")):
        if path.is_file():
            findings.extend(_scan_file(path, base))
    return findings


def test_e2e_scan_flags_vulnerable_frontend(tmp_path):
    (tmp_path / "src" / "routes").mkdir(parents=True)
    (tmp_path / "src" / "Comment.vue").write_text(
        '<template>\n  <div v-html="comment.body"></div>\n</template>\n',
        encoding="utf-8",
    )
    (tmp_path / "src" / "Post.svelte").write_text(
        "<script>export let body;</script>\n{@html body}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "routes" / "+page.svelte").write_text(
        "<script>\nimport { DB_URL } from '$env/static/private';\n</script>\n",
        encoding="utf-8",
    )
    (tmp_path / "svelte.config.js").write_text(
        "export default { kit: { csrf: { checkOrigin: false } } };\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        _VITE + "API_SECRET=abc123def456\n" + _NUXT_PUBLIC + "JWT_SECRET=change-me\n",
        encoding="utf-8",
    )

    findings = _scan_project(tmp_path)
    hits = {(f["rule_id"], f["file"]) for f in findings}

    assert ("vue-v-html-usage", "src/Comment.vue") in hits
    assert ("svelte-html-tag-usage", "src/Post.svelte") in hits
    assert ("sveltekit-private-env-in-client", "src/routes/+page.svelte") in hits
    assert ("sveltekit-csrf-origin-check-disabled", "svelte.config.js") in hits
    assert ("vite-env-secret-exposed", ".env") in hits
    assert ("nuxt-public-env-secret", ".env") in hits


def test_e2e_scan_clean_frontend_has_no_findings(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Comment.vue").write_text(
        "<template>\n  <p>{{ comment.body }}</p>\n</template>\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "Post.svelte").write_text(
        "<script>export let body;</script>\n<p>{body}</p>\n",
        encoding="utf-8",
    )
    (tmp_path / "svelte.config.js").write_text(
        "export default { kit: { csrf: { checkOrigin: true } } };\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        _VITE + "API_BASE_URL=https://api.example.com\n",
        encoding="utf-8",
    )

    findings = _scan_project(tmp_path)
    flagged = {f["rule_id"] for f in findings} & set(RULE_IDS)
    assert flagged == set(), f"clean project false-positives: {flagged}"
