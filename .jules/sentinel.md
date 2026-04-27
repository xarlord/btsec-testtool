## 2024-05-18 - Path Traversal in File Export
**Vulnerability:** Found a Path Traversal vulnerability in `ConsentRepositoryImpl.exportAuditLog` where it directly instantiates `File(outputPath)` with unsanitized user input.
**Learning:** Functions that accept file paths for writing or exporting logs without sanitizing them allow attackers to write files to unintended or restricted directories outside the expected base path.
**Prevention:** To prevent path traversal vulnerabilities during file generation (like exports), always resolve the `canonicalPath` of user-provided paths and verify they strictly begin with permitted application directories (e.g., `context.filesDir`, `context.cacheDir`, or `/tmp`) before writing, instead of directly passing unsanitized paths to `File()`.
