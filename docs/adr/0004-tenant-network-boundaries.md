# ADR-0004: Treat tenant authority and outbound destinations as explicit security boundaries

**Status:** Accepted  
**Date:** 2026-08-09

Control-plane organization authority derives from authenticated API-key/role context, never from untrusted request repository/organization strings. Webhook, callback, ZAP, and other outbound destinations are separately authorized/validated network boundaries. Stored destinations must be validated before persistence and rechecked as needed before execution because DNS/redirect/network conditions can change.