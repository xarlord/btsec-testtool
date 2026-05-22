## 2024-05-18 - Path traversal in AuditLogExport
**Vulnerability:** Path traversal in `ConsentRepositoryImpl.exportAuditLog` allowed arbitrary file writes based on `outputPath`.
**Learning:** Hardcoded file creation in repository implementations using unsanitized inputs from domain layer.
**Prevention:** Always use canonical path checks and restrict to allowed application directories (filesDir, cacheDir, tmp).
