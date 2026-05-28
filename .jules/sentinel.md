## 2024-05-24 - Path Traversal in Audit Log Export
**Vulnerability:** Found a Path Traversal vulnerability in `ConsentRepositoryImpl.kt` where `exportAuditLog` uses `File(outputPath)` directly without any validation.
**Learning:** We need to validate all file paths constructed from input strings. The `ReportRepositoryImpl.kt` file already implements a good pattern with `getSafeFile` to prevent path traversal, which limits file writing to allowed directories.
**Prevention:** Apply the `getSafeFile` approach from `ReportRepositoryImpl` to `ConsentRepositoryImpl` and other places writing files, strictly checking canonical paths against allowed base directories.
