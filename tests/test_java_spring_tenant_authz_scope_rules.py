"""Source-backed regressions for discarded Spring tenant authorization context."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "java-spring-admin-discarded-tenant-context"
_SOURCE_REPOSITORY = "ContextualWisdomLab/clearfolio"
_SOURCE_PR = 240
_VULNERABLE_HEAD_SHA = "0eb7fa9cfc56062983f5337228ca3a7317cf17a8"
_VULNERABLE_BLOB_SHA = "5086b1d3797a9c32831900d09d93d8df44c5e13a"
_FIXED_PR = 172
_FIXED_HEAD_SHA = "f4ae8dd695afe1dd41decbc7e6b2a11d0ee5e461"
_FIXED_BLOB_SHA = "872f0a66ea6dc8da95f8327e3d4cf40d3c08689f"
_FIXTURE_DIR = Path(__file__).parent / "fixtures"
_VULNERABLE_FIXTURE = _FIXTURE_DIR / "clearfolio_admin_controller_vulnerable.java"
_FIXED_FIXTURE = _FIXTURE_DIR / "clearfolio_admin_controller_fixed.java"

_VULNERABLE_LIST_SOURCE = """
@RestController
public class AdminController {
    @GetMapping("/api/v1/admin/convert/jobs")
    public AdminJobListResponse getAllJobs(
            @RequestParam(required = false) Boolean deadLettered,
            @RequestHeader HttpHeaders headers) {
        tenantAccessService.require(headers, TenantPermissions.ADMIN_READ);
        Iterable<ConversionJob> allJobs = conversionService.getAllJobs();
        return AdminJobListResponse.from(allJobs);
    }
}
"""

_VULNERABLE_DELETE_SOURCE = """
@RestController
public class AdminController {
    @DeleteMapping("/api/v1/admin/convert/jobs/{jobId}")
    public ResponseEntity<Void> deleteJob(
            @PathVariable UUID jobId,
            @RequestHeader HttpHeaders headers) {
        tenantAccessService.require(headers, TenantPermissions.ADMIN_WRITE);
        conversionService.deleteJob(jobId);
        return ResponseEntity.noContent().build();
    }
}
"""

_FIXED_SERVICE_SCOPE_SOURCE = """
@RestController
public class AdminController {
    @DeleteMapping("/api/v1/admin/convert/jobs/{jobId}")
    public ResponseEntity<Void> deleteJob(
            @PathVariable UUID jobId,
            @RequestHeader HttpHeaders headers) {
        TenantContext context = tenantAccessService.require(
                headers, TenantPermissions.ADMIN_WRITE);
        if (!conversionService.deleteJob(jobId, context)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "job not found");
        }
        return ResponseEntity.noContent().build();
    }
}
"""

_FIXED_CONTROLLER_FILTER_SOURCE = """
@RestController
public class AdminController {
    @GetMapping("/api/v1/admin/convert/jobs")
    public AdminJobListResponse getAllJobs(
            @RequestHeader HttpHeaders headers) {
        TenantContext context = tenantAccessService.require(
                headers, TenantPermissions.ADMIN_READ);
        List<ConversionJob> filtered = new ArrayList<>();
        for (ConversionJob job : conversionService.getAllJobs()) {
            if (job.belongsToTenant(context.tenantId())) {
                filtered.add(job);
            }
        }
        return AdminJobListResponse.from(filtered);
    }
}
"""

_PLATFORM_ADMIN_SOURCE = """
@RestController
public class PlatformAdminController {
    @GetMapping("/api/v1/admin/system/jobs")
    public AdminJobListResponse getAllJobs(@RequestHeader HttpHeaders headers) {
        platformAccessService.require(headers, PlatformPermissions.SYSTEM_ADMIN);
        return AdminJobListResponse.from(conversionService.getAllJobs());
    }
}
"""

_NON_ADMIN_SOURCE = """
@RestController
public class ProfileController {
    @GetMapping("/api/v1/profile/jobs")
    public AdminJobListResponse getJobs(@RequestHeader HttpHeaders headers) {
        tenantAccessService.require(headers, TenantPermissions.ADMIN_READ);
        return AdminJobListResponse.from(conversionService.getAllJobs());
    }
}
"""

_ADJACENT_METHODS_SOURCE = """
@RestController
public class AdminController {
    @GetMapping("/api/v1/admin/status")
    public Status status(@RequestHeader HttpHeaders headers) {
        tenantAccessService.require(headers, TenantPermissions.ADMIN_READ);
        return Status.ok();
    }

    @GetMapping("/api/v1/internal/jobs")
    public AdminJobListResponse internalJobs() {
        return AdminJobListResponse.from(conversionService.getAllJobs());
    }
}
"""


def _rule() -> dict:
    """Return the one packaged tenant-authorization rule under test."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Run the production scanner over one Java controller replay."""
    source_file = tmp_path / "AdminController.java"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_pins_clearfolio_security_transition() -> None:
    """Keep detector claims bound to exact collector and reviewed source objects."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/clearfolio"
    assert _SOURCE_PR == 240
    assert _VULNERABLE_HEAD_SHA == "0eb7fa9cfc56062983f5337228ca3a7317cf17a8"
    assert _VULNERABLE_BLOB_SHA == "5086b1d3797a9c32831900d09d93d8df44c5e13a"
    assert _FIXED_PR == 172
    assert _FIXED_HEAD_SHA == "f4ae8dd695afe1dd41decbc7e6b2a11d0ee5e461"
    assert _FIXED_BLOB_SHA == "872f0a66ea6dc8da95f8327e3d4cf40d3c08689f"


def test_rule_detects_discarded_tenant_context_before_list() -> None:
    """Detect a tenant guard whose result is discarded before a global list read."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_VULNERABLE_LIST_SOURCE)


def test_rule_detects_discarded_tenant_context_before_object_mutation() -> None:
    """Detect a tenant guard whose result is discarded before ID-based deletion."""
    assert _rule()["pattern"].search(_VULNERABLE_DELETE_SOURCE)


def test_rule_ignores_context_passed_to_service_boundary() -> None:
    """Do not flag a controller that carries tenant context into the mutation layer."""
    assert not _rule()["pattern"].search(_FIXED_SERVICE_SCOPE_SOURCE)


def test_rule_ignores_context_used_for_controller_side_tenant_filter() -> None:
    """Do not flag the reviewed Clearfolio shape that consumes tenant identity locally."""
    assert not _rule()["pattern"].search(_FIXED_CONTROLLER_FILTER_SOURCE)


def test_rule_does_not_infer_tenant_scope_for_platform_admin_authority() -> None:
    """Keep global platform-admin semantics outside this tenant-specific signature."""
    assert not _rule()["pattern"].search(_PLATFORM_ADMIN_SOURCE)


def test_rule_requires_admin_route_scope() -> None:
    """Avoid broad matching of similarly named services on non-admin routes."""
    assert not _rule()["pattern"].search(_NON_ADMIN_SOURCE)


def test_rule_does_not_cross_spring_mapping_boundaries() -> None:
    """Never pair a tenant guard in one handler with a sink in another handler."""
    assert not _rule()["pattern"].search(_ADJACENT_METHODS_SOURCE)


def test_rule_handles_large_admin_handler_without_unbounded_backtracking() -> None:
    """Keep unrelated long handler text from creating a regex denial of service."""
    source = (
        '@GetMapping("/api/v1/admin/convert/jobs")\n'
        "public AdminJobListResponse getAllJobs() {\n"
        + "".join(
            f'    String value_{index} = "unrelated";\n'
            for index in range(3000)
        )
        + "}\n"
    )
    assert not _rule()["pattern"].search(source)


def test_rule_declares_bounded_prefilters() -> None:
    """Avoid multiline evaluation unless the observed tenant-admin signals are present."""
    assert _rule()["required_substrings"] == (
        "/admin/",
        "tenantAccessService",
        "TenantPermissions.ADMIN_",
    )


def test_scan_file_emits_normalized_authorization_finding(tmp_path: Path) -> None:
    """Exercise the production AppGuardrail entrypoint on the source-derived weakness."""
    findings = _scan(_VULNERABLE_DELETE_SOURCE, tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["source"] == "appguardrail-rule"
    assert finding["category"] == "authz"
    assert finding["confidence"] == "high"
    assert finding["file"] == "AdminController.java"
    assert finding["cwe"] == ("CWE-863 - Incorrect Authorization",)
    assert "Capture the returned TenantContext" in finding["message"]


def test_scan_file_replays_pinned_clearfolio_source_fixtures(tmp_path: Path) -> None:
    """Bind production scanner evidence directly to the immutable source fixtures."""
    vulnerable_source = _VULNERABLE_FIXTURE.read_text(encoding="utf-8")
    vulnerable_findings = _scan(vulnerable_source, tmp_path)

    assert len(vulnerable_findings) == 3
    assert all(finding["severity"] == "HIGH" for finding in vulnerable_findings)
    assert all(finding["source"] == "appguardrail-rule" for finding in vulnerable_findings)
    assert all(finding["category"] == "authz" for finding in vulnerable_findings)
    assert all(finding["confidence"] == "high" for finding in vulnerable_findings)
    assert all(
        finding["cwe"] == ("CWE-863 - Incorrect Authorization",)
        for finding in vulnerable_findings
    )
    assert all(
        "Capture the returned TenantContext" in finding["message"]
        for finding in vulnerable_findings
    )

    fixed_source = _FIXED_FIXTURE.read_text(encoding="utf-8")
    assert _scan(fixed_source, tmp_path) == []


def test_scan_file_keeps_reviewed_scope_repairs_clean(tmp_path: Path) -> None:
    """Keep both service-scoped and controller-filtered fixed shapes clean."""
    assert _scan(_FIXED_SERVICE_SCOPE_SOURCE, tmp_path) == []
    assert _scan(_FIXED_CONTROLLER_FILTER_SOURCE, tmp_path) == []
