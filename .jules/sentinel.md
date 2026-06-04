## 2024-06-04 - Fix Path Traversal in Consent Repository
**Vulnerability:** Found a Path Traversal vulnerability in `exportAuditLog` inside `ConsentRepositoryImpl.kt` where unsanitized user input (`outputPath`) was passed directly to the `File` constructor.
**Learning:** The vulnerability existed because the mock implementation bypassed path validation before writing files. It's critical to validate that resolved paths reside within expected safe directories.
**Prevention:** Always use `canonicalPath` to resolve `../` segments and check if the resulting path `startsWith()` a known safe base directory (like `context.filesDir` or `context.cacheDir`) before performing any file operations.
