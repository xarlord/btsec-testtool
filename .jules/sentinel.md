## 2026-02-07 - Path Traversal Vulnerability in Export Endpoints
**Vulnerability:** The `ConsentRepositoryImpl.exportAuditLog` endpoint was vulnerable to path traversal because it used user-provided `outputPath` directly when instantiating `File(outputPath)`.
**Learning:** Even internal functionality like report/audit logging needs path sanitization since paths can originate from user intents or exported content provider inputs.
**Prevention:** Always validate file paths resolving their canonical paths against a whitelist of allowed application directories using `canonicalPath.startsWith(allowedDir + File.separator) || canonicalPath == allowedDir`. Never pass unsanitized paths directly to `File()`.
