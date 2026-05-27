## 2024-05-24 - Path Traversal in File Export
**Vulnerability:** The `exportAuditLog` method in `ConsentRepositoryImpl` accepted a user-provided `outputPath` string and passed it directly to `File(outputPath)` without validation, allowing path traversal (e.g., `../../etc/passwd`).
**Learning:** While other components (like `ReportRepositoryImpl`) implemented explicit sanitization via a `getSafeFile` method checking canonical paths against allowed base directories, this pattern was inconsistently applied across the codebase, leaving specific file-writing endpoints vulnerable.
**Prevention:** Always validate user-provided file paths by resolving their `canonicalPath` and ensuring they reside entirely within an allowed base directory before performing any filesystem operations.
