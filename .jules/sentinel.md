## 2023-10-27 - Path Traversal in File Export
**Vulnerability:** Found a path traversal vulnerability in `ConsentRepositoryImpl.kt` where a user-provided file path was written directly without validation (`File(outputPath)`).
**Learning:** This exposes the application to arbitrary file writes. This existed because the file was missing path validation logic that was present in `ReportRepositoryImpl.kt` via `getSafeFile`.
**Prevention:** Always validate user-provided file paths against allowed base directories (e.g., `context.filesDir`, `context.cacheDir`) before proceeding with any file operations to prevent partial-directory bypasses or traversing.
