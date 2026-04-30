## 2024-05-18 - Prevent Path Traversal in Export Audit Logs
**Vulnerability:** Found arbitrary file write via unsanitized output path passed directly to `File()` in `ConsentRepositoryImpl.exportAuditLog()`.
**Learning:** `outputPath` passed from higher layers lacked safety checks, allowing writing out-of-bounds to arbitrary locations like `/tmp/../../../etc/passwd`.
**Prevention:** Always validate `File(outputPath).canonicalPath` starts with an allowed base directory like `context.filesDir` or `context.cacheDir` before proceeding with any file write operation.
