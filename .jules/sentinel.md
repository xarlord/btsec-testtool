## 2026-02-07 - Path Traversal in Consent Repository
**Vulnerability:** Found a path traversal vulnerability in `ConsentRepositoryImpl.kt` where `exportAuditLog` used user input (`outputPath`) directly in `File(outputPath)`, potentially allowing arbitrary file writes.
**Learning:** Always validate paths before using them. Ensure they resolve to an allowed base directory using `canonicalPath` to prevent `../` attacks.
**Prevention:** Implement and reuse methods like `getSafeFile` that check if the `canonicalPath` starts with an allowed base directory path.
