## 2024-05-20 - Prevent Path Traversal in File Exports
**Vulnerability:** The `ConsentRepositoryImpl.exportAuditLog` method directly created a `File` from user-provided `outputPath` without validation, exposing a path traversal risk.
**Learning:** Even internal tools or non-user-facing exports can be vulnerable if inputs are not sanitized. The `ReportRepositoryImpl` had a proper implementation using canonical path validation against allowed base directories, but it wasn't uniformly applied.
**Prevention:** Always resolve the `canonicalPath` of user-provided paths and verify they strictly begin with an allowed base directory plus a separator (`canonicalPath.startsWith(base + File.separator)`) or match it exactly. Do not pass unsanitized paths directly to `File()`.
