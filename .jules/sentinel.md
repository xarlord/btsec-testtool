## 2026-05-18 - Prevent Path Traversal in Export Paths
**Vulnerability:** Path traversal vulnerability existed in `ConsentRepositoryImpl.exportAuditLog` allowing arbitrary file writes via unsanitized `outputPath`.
**Learning:** Returning `File(outputPath)` directly without validating the canonical path allows attackers to bypass intended directories (e.g., using `../../etc/passwd`).
**Prevention:** Always extract `file.canonicalPath` and strictly verify it either equals an allowed directory base or starts with `base + File.separator` to avoid partial-directory bypasses.
