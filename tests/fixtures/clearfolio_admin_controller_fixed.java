package com.clearfolio.viewer.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.clearfolio.viewer.api.AdminJobListResponse;
import com.clearfolio.viewer.audit.AdministrativeAuditLogger;
import com.clearfolio.viewer.audit.AdministrativeAuditLogger.Action;
import com.clearfolio.viewer.audit.AdministrativeAuditLogger.Outcome;
import com.clearfolio.viewer.auth.TenantAccessService;
import com.clearfolio.viewer.auth.TenantContext;
import com.clearfolio.viewer.auth.TenantPermissions;
import com.clearfolio.viewer.model.ConversionJob;
import com.clearfolio.viewer.service.DocumentConversionService;
import com.clearfolio.viewer.service.RetryDeadLetterResult;

/**
 * Exposes tenant-scoped administrative conversion-job operations.
 *
 * <p>Every endpoint requires strongly configured signed gateway claims,
 * evaluates a least-privilege permission, and delegates object-level tenant
 * authorization to the same service boundary that performs each mutation.
 * Missing and cross-tenant objects intentionally share the same not-found
 * response.</p>
 */
@RestController
public class AdminController {

    private final DocumentConversionService conversionService;
    private final TenantAccessService tenantAccessService;
    private final AdministrativeAuditLogger auditLogger;

    /**
     * Creates a controller for authenticated tenant-administrator operations.
     *
     * @param conversionService conversion service
     * @param tenantAccessService signed-claim authorization service
     * @param auditLogger privacy-safe administrative evidence logger
     */
    public AdminController(
            DocumentConversionService conversionService,
            TenantAccessService tenantAccessService,
            AdministrativeAuditLogger auditLogger
    ) {
        this.conversionService = conversionService;
        this.tenantAccessService = tenantAccessService;
        this.auditLogger = auditLogger;
    }

    /**
     * Retrieves conversion jobs owned by the authenticated tenant.
     *
     * @param deadLettered optional dead-letter status filter
     * @param headers signed gateway claim headers
     * @return tenant-scoped list of conversion jobs
     */
    @GetMapping("/api/v1/admin/convert/jobs")
    public AdminJobListResponse getAllJobs(
            @RequestParam(required = false) Boolean deadLettered,
            @RequestHeader HttpHeaders headers
    ) {
        TenantContext context = authorize(
                headers,
                TenantPermissions.ADMIN_READ,
                Action.LIST_JOBS,
                null
        );

        try {
            List<ConversionJob> filtered = new ArrayList<>();
            for (ConversionJob job : conversionService.getAllJobs()) {
                boolean tenantOwned = job.belongsToTenant(context.tenantId());
                boolean deadLetterMatches = deadLettered == null
                        || job.isDeadLettered() == deadLettered;
                if (tenantOwned && deadLetterMatches) {
                    filtered.add(job);
                }
            }
            auditLogger.record(
                    context,
                    Action.LIST_JOBS,
                    Outcome.ALLOWED,
                    HttpStatus.OK,
                    null,
                    filtered.size()
            );
            return AdminJobListResponse.from(filtered);
        } catch (RuntimeException ex) {
            auditLogger.record(
                    context,
                    Action.LIST_JOBS,
                    Outcome.FAILED,
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    null,
                    null
            );
            throw ex;
        }
    }

    /**
     * Deletes one conversion job owned by the authenticated tenant.
     *
     * @param jobId conversion job identifier
     * @param headers signed gateway claim headers
     * @return no content on success
     */
    @DeleteMapping("/api/v1/admin/convert/jobs/{jobId}")
    public ResponseEntity<Void> deleteJob(
            @PathVariable UUID jobId,
            @RequestHeader HttpHeaders headers
    ) {
        TenantContext context = authorize(
                headers,
                TenantPermissions.ADMIN_WRITE,
                Action.DELETE_JOB,
                jobId
        );

        boolean deleted;
        try {
            deleted = conversionService.deleteJob(jobId, context);
        } catch (RuntimeException ex) {
            auditLogger.record(
                    context,
                    Action.DELETE_JOB,
                    Outcome.FAILED,
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    jobId,
                    null
            );
            throw ex;
        }

        if (!deleted) {
            auditLogger.record(
                    context,
                    Action.DELETE_JOB,
                    Outcome.NOT_FOUND,
                    HttpStatus.NOT_FOUND,
                    jobId,
                    null
            );
            throw notFound();
        }

        auditLogger.record(
                context,
                Action.DELETE_JOB,
                Outcome.ALLOWED,
                HttpStatus.NO_CONTENT,
                jobId,
                null
        );
        return ResponseEntity.noContent().build();
    }

    /**
     * Retries one dead-lettered conversion job owned by the authenticated tenant.
     *
     * @param jobId conversion job identifier
     * @param headers signed gateway claim headers
     * @return accepted response on success
     */
    @PostMapping("/api/v1/admin/convert/jobs/{jobId}/retry")
    public ResponseEntity<Void> retryDeadLettered(
            @PathVariable UUID jobId,
            @RequestHeader HttpHeaders headers
    ) {
        TenantContext context = authorize(
                headers,
                TenantPermissions.ADMIN_WRITE,
                Action.RETRY_JOB,
                jobId
        );

        RetryDeadLetterResult result;
        try {
            result = conversionService.retryDeadLettered(
                    jobId,
                    context,
                    auditLogger.actorFingerprint(context)
            );
        } catch (RuntimeException ex) {
            auditLogger.record(
                    context,
                    Action.RETRY_JOB,
                    Outcome.FAILED,
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    jobId,
                    null
            );
            throw ex;
        }

        return switch (result) {
            case ACCEPTED -> {
                auditLogger.record(
                        context,
                        Action.RETRY_JOB,
                        Outcome.ALLOWED,
                        HttpStatus.ACCEPTED,
                        jobId,
                        null
                );
                yield ResponseEntity.accepted().build();
            }
            case NOT_FOUND -> {
                auditLogger.record(
                        context,
                        Action.RETRY_JOB,
                        Outcome.NOT_FOUND,
                        HttpStatus.NOT_FOUND,
                        jobId,
                        null
                );
                throw notFound();
            }
            case NOT_ELIGIBLE -> {
                auditLogger.record(
                        context,
                        Action.RETRY_JOB,
                        Outcome.NOT_ELIGIBLE,
                        HttpStatus.CONFLICT,
                        jobId,
                        null
                );
                throw new ResponseStatusException(
                        HttpStatus.CONFLICT,
                        "job is not eligible for retry"
                );
            }
        };
    }

    private TenantContext authorize(
            HttpHeaders headers,
            String permission,
            Action action,
            UUID jobId
    ) {
        try {
            return tenantAccessService.requireSigned(headers, permission);
        } catch (ResponseStatusException ex) {
            auditLogger.recordHeaders(
                    headers,
                    action,
                    Outcome.DENIED,
                    ex.getStatusCode(),
                    jobId
            );
            throw ex;
        }
    }

    private ResponseStatusException notFound() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, "job not found");
    }
}
