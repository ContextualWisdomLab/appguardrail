"""Adversarial contracts for read-only GitHub workflow lifecycle evidence."""

from __future__ import annotations

import json
import runpy
import sys

import pytest

from appguardrail_core import workflow_lifecycle as lifecycle

SHA = "a" * 40
SHA_B = "b" * 40


def _workflow(workflow_id: int, path: str, state: str = "active") -> dict:
    return {
        "id": workflow_id,
        "name": path.rsplit("/", 1)[-1],
        "path": path,
        "state": state,
    }


def _record(
    *, workflows: list[dict], tree: list[str], pages: list[dict] | None = None
) -> dict:
    return {
        "name": "appguardrail",
        "archived": False,
        "default_branch": "develop",
        "default_branch_sha": SHA,
        "default_branch_sha_after": SHA,
        "tree_paths": tree,
        "workflow_pages": pages
        or [
            {"total_count": len(workflows), "workflows": workflows, "_link_next": False}
        ],
    }


def test_complete_inventory_separates_all_control_plane_classes() -> None:
    """Present, orphan, disabled, dynamic, and unresolved remain distinct."""
    workflows = [
        _workflow(1, ".github/workflows/ci.yml"),
        _workflow(2, ".github/workflows/old.yml"),
        _workflow(3, ".github/workflows/disabled.yml", "disabled_manually"),
        _workflow(4, "dynamic/pages/pages-build-deployment"),
        _workflow(5, ".GitHub/workflows/case.yml"),
    ]
    result = lifecycle.inventory_repository(
        _record(workflows=workflows, tree=[".github/workflows/ci.yml"])
    )
    assert [item["classification"] for item in result["records"]] == [
        "present_active",
        "orphan_active",
        "orphan_disabled",
        "dynamic_owned",
        "unresolved",
    ]
    assert result["records"][1]["workflow_id"] == 2
    assert result["records"][1]["default_branch_sha"] == SHA


def test_pagination_requires_every_page_and_unique_workflow_ids() -> None:
    """Missing pages and reused registry IDs fail closed."""
    first = {
        "total_count": 2,
        "workflows": [_workflow(7, ".github/workflows/a.yml")],
        "_link_next": True,
    }
    with pytest.raises(lifecycle.InventoryError, match="truncated"):
        lifecycle.collect_workflow_pages([first], per_page=1)
    second = {
        "total_count": 2,
        "workflows": [_workflow(7, ".github/workflows/renamed.yml")],
        "_link_next": False,
    }
    with pytest.raises(lifecycle.InventoryError, match="reused workflow id 7"):
        lifecycle.collect_workflow_pages([first, second], per_page=1)


@pytest.mark.parametrize("status", [403, 404, 500, 503])
def test_permission_missing_and_server_responses_never_become_clean(
    status: int,
) -> None:
    """Visibility loss and upstream failure are unresolved errors, not absence."""
    with pytest.raises(lifecycle.InventoryError):
        lifecycle.interpret_status(status, resource="workflow inventory")


def test_server_error_retries_once_but_permission_error_does_not() -> None:
    """Only 5xx receives the central contract's one bounded retry."""
    calls: list[str] = []

    def recover(url: str):
        calls.append(url)
        return (503, {}, {}) if len(calls) == 1 else (200, {"ok": True}, {})

    assert lifecycle.fetch_with_one_retry(recover, "https://api.github.com/test")[
        0
    ] == {"ok": True}
    assert len(calls) == 2

    calls.clear()

    def forbidden(url: str):
        calls.append(url)
        return 403, {}, {}

    with pytest.raises(lifecycle.InventoryError, match="permission"):
        lifecycle.fetch_with_one_retry(forbidden, "https://api.github.com/test")
    assert len(calls) == 1


def test_live_collection_retries_shared_client_5xx_shape_once() -> None:
    """The production collector recognizes AppGuardrail's shared client error."""

    class Client:
        calls = 0

        def request(self, _path: str):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("GitHub API GET /orgs failed: 503 unavailable")
            return {"ok": True}

    receipts: list[dict] = []
    assert lifecycle._live_get(Client(), "/orgs", receipts) == {"ok": True}
    assert len(receipts) == 1


def test_live_get_redacts_non_server_transport_failure() -> None:
    """Permission details do not escape the bounded live error."""

    class Client:
        def request(self, _path: str):
            raise RuntimeError("private permission detail")

    with pytest.raises(lifecycle.InventoryError, match="RuntimeError") as error:
        lifecycle._live_get(Client(), "/private", [])
    assert "private permission detail" not in str(error.value)


def test_read_only_adapter_rejects_every_mutating_shape() -> None:
    """The shared transport cannot be used for a workflow mutation."""

    class Client:
        def request(self, method: str, path: str):
            return {"method": method, "path": path}

    adapter = lifecycle._ReadOnlyGitHubAdapter(Client())
    assert adapter.request("/repos/example") == {
        "method": "GET",
        "path": "/repos/example",
    }
    with pytest.raises(lifecycle.InventoryError, match="read-only"):
        adapter.request("/repos/example/actions/workflows/1/disable", method="PUT")
    with pytest.raises(lifecycle.InventoryError, match="read-only"):
        adapter.request("/repos/example", payload={})


def test_live_main_writes_receipts_and_fail_closed_evidence(
    tmp_path, monkeypatch
) -> None:
    """The live CLI persists both successful and partial collection receipts."""
    from scripts.ci import commercial_readiness_loop

    class GitHub:
        def __init__(self, token: str):
            assert token == "test-token"

    monkeypatch.setattr(commercial_readiness_loop, "GitHub", GitHub)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    receipt_path = tmp_path / "receipts.json"
    failure_path = tmp_path / "failure.json"
    output_path = tmp_path / "ledger.json"
    ledger = {
        "counts": {"orphan_active": 0},
        "records": [],
    }

    def collect(_client, *, receipts):
        receipts.append({"method": "GET", "path": "/ok", "sha256": "a" * 64})
        return {"organization": "ContextualWisdomLab"}, receipts

    monkeypatch.setattr(lifecycle, "collect_live_organization", collect)
    monkeypatch.setattr(lifecycle, "inventory_organization", lambda _payload: ledger)
    assert (
        lifecycle.main(
            [
                "--live",
                "--output",
                str(output_path),
                "--receipt-output",
                str(receipt_path),
            ]
        )
        == 0
    )
    assert json.loads(receipt_path.read_text())[0]["path"] == "/ok"

    def fail(_client, *, receipts):
        receipts.append({"method": "GET", "path": "/partial", "sha256": "b" * 64})
        raise lifecycle.InventoryError("incomplete")

    monkeypatch.setattr(lifecycle, "collect_live_organization", fail)
    assert (
        lifecycle.main(
            [
                "--live",
                "--receipt-output",
                str(receipt_path),
                "--failure-output",
                str(failure_path),
            ]
        )
        == 2
    )
    assert json.loads(receipt_path.read_text())[0]["path"] == "/partial"
    assert json.loads(failure_path.read_text())["status"] == "failed"


def test_live_main_requires_a_token(tmp_path, monkeypatch) -> None:
    """Missing credentials fail before any GitHub request."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert lifecycle.main(["--live"]) == 2
    assert (
        lifecycle.main(["--live", "--receipt-output", str(tmp_path / "receipts.json")])
        == 2
    )


def test_branch_movement_case_encoding_and_malformed_paths_fail_closed() -> None:
    """A moved head or ambiguous registry path cannot prove an orphan."""
    with pytest.raises(lifecycle.InventoryError, match="moved"):
        lifecycle.assert_default_branch_bound(SHA, SHA_B)
    with pytest.raises(lifecycle.InventoryError, match="percent-encoded"):
        lifecycle.decode_registry_path(".github/workflows/%6f%6ece.yml")
    assert not lifecycle.is_repository_workflow_path(".GitHub/workflows/once.yml")


def test_supported_once_file_is_present_not_a_name_heuristic() -> None:
    """A live reviewed one-shot name stays present_active."""
    path = ".github/workflows/apply-reviewed-once.yml"
    result = lifecycle.inventory_repository(
        _record(workflows=[_workflow(9, path)], tree=[path])
    )
    assert result["records"][0]["classification"] == "present_active"


def test_inventory_api_has_no_registry_mutation_primitive() -> None:
    """The package exposes detection only, never exact-ID disablement."""
    assert not hasattr(lifecycle, "disable_workflow")
    assert not hasattr(lifecycle, "delete_workflow")


@pytest.mark.filterwarnings("ignore:.*found in sys.modules.*:RuntimeWarning")
def test_module_entrypoint_executes_read_only_fixture(tmp_path, monkeypatch) -> None:
    """The packaged module entry point exits successfully for clean evidence."""
    payload = {
        "organization": "ContextualWisdomLab",
        "observed_at": "2026-09-23T00:00:00Z",
        "repository_inventory_complete": True,
        "repositories": [_record(workflows=[], tree=[])],
    }
    source = tmp_path / "inventory.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["workflow_lifecycle", "--payload", str(source)])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_module("appguardrail_core.workflow_lifecycle", run_name="__main__")
    assert stopped.value.code == 0
