"""Coverage tests for the Ruby on Rails rule pack (scanner/rules/rails.yml)."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RAILS_RULES = {}
for _r in SCAN_RULES:
    if _r["id"].startswith("rails-"):
        _RAILS_RULES.setdefault(_r["id"], []).append(_r)


def _rules(rule_id):
    assert rule_id in _RAILS_RULES, f"rule not loaded: {rule_id}"
    return _RAILS_RULES[rule_id]


def _matches(rule_id, text):
    return any(r["pattern"].search(text) for r in _rules(rule_id))


EXPECTED_SEVERITIES = {
    "rails-sql-injection-interpolation": "CRITICAL",
    "rails-raw-html-output": "HIGH",
    "rails-mass-assignment-permit-all": "HIGH",
    "rails-command-injection": "CRITICAL",
    "rails-skip-csrf": "HIGH",
    "rails-secrets-in-code": "CRITICAL",
}


CASES = {
    "rails-sql-injection-interpolation": (
        [
            'User.where("name = \'#{params[:name]}\'")',
            'Post.find_by_sql("SELECT * FROM posts WHERE id = #{id}")',
            'User.order("#{params[:sort]} ASC")',
            'scope.having("count(*) > #{params[:min]}")',
        ],
        [
            'User.where("name = ?", params[:name])',
            "User.where(name: params[:name])",
            'User.order("created_at DESC")',
            "User.find_by_sql([\"SELECT * FROM users WHERE id = ?\", id])",
            # Single-quoted Ruby strings do not interpolate.
            "User.where('name = #{params[:name]}')",
        ],
    ),
    "rails-raw-html-output": (
        [
            "<%= raw @comment.body %>",
            "raw(params[:snippet])",
            "params[:bio].html_safe",
            '"<b>#{params[:q]}</b>".html_safe',
        ],
        [
            "<%= @comment.body %>",
            "<%= sanitize @comment.body %>",
            "<%= raw_score %>",
            '"<br/>".html_safe if trusted_constant',
            "params[:bio].strip",
        ],
    ),
    "rails-mass-assignment-permit-all": (
        [
            "@user.update(params.permit!)",
            "User.new(params.permit!)",
        ],
        [
            "params.require(:user).permit(:name, :email)",
            "params.permit(:query, :page)",
        ],
    ),
    "rails-command-injection": (
        [
            'system("tar -czf backup.tgz #{params[:dir]}")',
            'exec("convert #{upload.path} out.png")',
            'IO.popen("grep #{pattern} log.txt")',
            'Open3.capture2("ping -c1 #{params[:host]}")',
            "`convert #{params[:file]} out.png`",
        ],
        [
            'system("tar", "-czf", "backup.tgz", dir)',
            'system("ls -la")',
            "`uptime`",
            "`echo #{Shellwords.escape(name)}`",  # backticks require params/request
        ],
    ),
    "rails-skip-csrf": (
        [
            "skip_before_action :verify_authenticity_token",
            "skip_before_filter :verify_authenticity_token, only: [:webhook]",
            "skip_before_action(:verify_authenticity_token)",
        ],
        [
            "before_action :verify_authenticity_token",
            "protect_from_forgery with: :exception",
            "skip_before_action :require_login",
        ],
    ),
    "rails-secrets-in-code": (
        [
            'secret_key_base = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c"',
            "config.secret_key_base = '0123456789ABCDEF0123456789abcdef'",
        ],
        [
            'secret_key_base = ENV["SECRET_KEY_BASE"]',
            "config.secret_key_base = Rails.application.credentials.secret_key_base",
            'secret_key_base = "abc123"',  # too short to be a real key
        ],
    ),
}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rails_rule_severity(rule_id):
    for rule in _rules(rule_id):
        assert rule["severity"] == EXPECTED_SEVERITIES[rule_id]


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rails_rule_positive_and_negative_snippets(rule_id):
    positives, negatives = CASES[rule_id]
    for snippet in positives:
        assert _matches(rule_id, snippet), f"{rule_id} should match: {snippet}"
    for snippet in negatives:
        assert not _matches(rule_id, snippet), f"{rule_id} must not match: {snippet}"


def test_rails_rules_scope_to_ruby_and_erb_paths():
    for rule_id, rules in _RAILS_RULES.items():
        for rule in rules:
            includes = rule["include_paths"]
            assert includes, f"{rule_id} must scope paths to Ruby sources"
            assert "**/*.rb" in includes
            for glob in includes:
                assert glob in ("**/*.rb", "**/*.erb"), f"{rule_id}: {glob}"


def _scan_ids(path, base):
    return {finding["rule_id"] for finding in _scan_file(path, base)}


def test_rails_rules_fire_end_to_end(tmp_path):
    controller = tmp_path / "app" / "controllers" / "users_controller.rb"
    controller.parent.mkdir(parents=True)
    controller.write_text(
        "class UsersController < ApplicationController\n"
        "  skip_before_action :verify_authenticity_token\n"
        "\n"
        "  def index\n"
        "    @users = User.where(\"name = '#{params[:name]}'\")\n"
        "  end\n"
        "\n"
        "  def update\n"
        "    @user.update(params.permit!)\n"
        "  end\n"
        "\n"
        "  def export\n"
        '    system("tar -czf /tmp/out.tgz #{params[:dir]}")\n'
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    view = tmp_path / "app" / "views" / "show.html.erb"
    view.parent.mkdir(parents=True)
    view.write_text("<div><%= raw @comment.body %></div>\n", encoding="utf-8")
    config = tmp_path / "config" / "secrets.rb"
    config.parent.mkdir(parents=True)
    config.write_text(
        'Rails.application.config.secret_key_base = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"\n',
        encoding="utf-8",
    )

    controller_ids = _scan_ids(controller, tmp_path)
    assert {
        "rails-skip-csrf",
        "rails-sql-injection-interpolation",
        "rails-mass-assignment-permit-all",
        "rails-command-injection",
    } <= controller_ids
    assert "rails-raw-html-output" in _scan_ids(view, tmp_path)
    assert "rails-secrets-in-code" in _scan_ids(config, tmp_path)


def test_rails_rules_stay_quiet_on_safe_ruby_end_to_end(tmp_path):
    safe = tmp_path / "app" / "controllers" / "safe_controller.rb"
    safe.parent.mkdir(parents=True)
    safe.write_text(
        "class SafeController < ApplicationController\n"
        "  def index\n"
        '    @users = User.where("name = ?", params[:name])\n'
        "  end\n"
        "\n"
        "  def update\n"
        "    @user.update(params.require(:user).permit(:name, :email))\n"
        "  end\n"
        "\n"
        "  def export\n"
        '    system("tar", "-czf", "backup.tgz", export_dir)\n'
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    assert not {
        rule_id for rule_id in _scan_ids(safe, tmp_path) if rule_id.startswith("rails-")
    }


def test_rails_rules_do_not_apply_outside_ruby_paths(tmp_path):
    other = tmp_path / "notes.txt"
    other.write_text(
        "skip_before_action :verify_authenticity_token\n"
        "@user.update(params.permit!)\n",
        encoding="utf-8",
    )
    assert not {
        rule_id
        for rule_id in _scan_ids(other, tmp_path)
        if rule_id.startswith("rails-")
    }
