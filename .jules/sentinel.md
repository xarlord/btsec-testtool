## 2025-02-18 - Path Traversal Vulnerability in Consent Export
**Vulnerability:** The `exportAuditLog` method in `ConsentRepositoryImpl` directly created a `File` object using an unsanitized `outputPath` string provided by the caller, allowing arbitrary file writes via path traversal (e.g., `../../../etc/shadow`).
**Learning:** This existed because file export APIs often assume paths are trusted or pre-validated by the UI, bypassing explicit backend/repository-level validation.
**Prevention:** Always validate user-provided file paths by resolving their `canonicalPath` and ensuring it strictly matches or begins with a permitted base directory (like `context.filesDir` or `context.cacheDir` + `File.separator`). Never pass unsanitized strings directly to `File()`.
