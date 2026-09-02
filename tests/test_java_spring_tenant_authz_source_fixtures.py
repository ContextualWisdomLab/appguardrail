"""Immutable source-fixture checks for the Clearfolio tenant-authorization replay."""

import hashlib
from pathlib import Path

_FIXTURE_DIR = Path(__file__).parent / "fixtures"
_VULNERABLE_FIXTURE = _FIXTURE_DIR / "clearfolio_admin_controller_vulnerable.java"
_FIXED_FIXTURE = _FIXTURE_DIR / "clearfolio_admin_controller_fixed.java"
_VULNERABLE_BLOB_SHA = "5086b1d3797a9c32831900d09d93d8df44c5e13a"
_FIXED_BLOB_SHA = "872f0a66ea6dc8da95f8327e3d4cf40d3c08689f"


def _git_blob_sha(path: Path) -> str:
    """Return the Git blob object ID for one pinned UTF-8 fixture."""
    payload = path.read_bytes()
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def test_clearfolio_vulnerable_fixture_matches_collector_head_blob() -> None:
    """Prove the positive oracle bytes match Clearfolio PR 240's collected head."""
    assert _git_blob_sha(_VULNERABLE_FIXTURE) == _VULNERABLE_BLOB_SHA
    source = _VULNERABLE_FIXTURE.read_text(encoding="utf-8")
    assert "tenantAccessService.require(headers, TenantPermissions.ADMIN_READ);" in source
    assert "Iterable<ConversionJob> allJobs = conversionService.getAllJobs();" in source
    assert "tenantAccessService.require(headers, TenantPermissions.ADMIN_WRITE);" in source
    assert "conversionService.deleteJob(jobId);" in source


def test_clearfolio_fixed_fixture_matches_superseding_reviewed_blob() -> None:
    """Prove the negative oracle bytes match the source PR 240 names as superseding."""
    assert _git_blob_sha(_FIXED_FIXTURE) == _FIXED_BLOB_SHA
    source = _FIXED_FIXTURE.read_text(encoding="utf-8")
    assert "TenantContext context = authorize(" in source
    assert "job.belongsToTenant(context.tenantId())" in source
    assert "conversionService.deleteJob(jobId, context)" in source
    assert "tenantAccessService.requireSigned(headers, permission)" in source
