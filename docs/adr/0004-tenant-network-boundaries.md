# ADR-0004: Treat tenant authority and outbound destinations as explicit security boundaries

**Status:** Accepted  
**Date:** 2026-08-09

Control-plane organization authority derives from authenticated API-key/role context, never from untrusted request repository/organization strings. Webhook, callback, ZAP, and other outbound destinations are separately authorized/validated network boundaries. Stored destinations must be validated before persistence and rechecked as needed before execution because DNS/redirect/network conditions can change.

## References

OWASP Foundation. (n.d.). *Server-Side Request Forgery Prevention Cheat Sheet*. OWASP Cheat Sheet Series. Retrieved August 25, 2026, from https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero trust architecture* (NIST SP 800-207). National Institute of Standards and Technology. https://csrc.nist.gov/pubs/sp/800/207/final