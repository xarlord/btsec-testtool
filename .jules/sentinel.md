## 2024-05-18 - Path Traversal in Audit Log Export
**Vulnerability:** Path traversal vulnerability in `exportAuditLog` allowing arbitrary file writes outside the intended sandbox directories.
**Learning:** Passing an unsanitized `outputPath` string directly to `File()` exposes the application to path traversal attacks if the path contains `../` or starts with `/`.
**Prevention:** Always resolve the canonical path of a user-provided file location and ensure it strictly falls within permitted application directories (like `context.filesDir` or `context.cacheDir`) before writing.
