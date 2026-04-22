## 2024-05-24 - [Path traversal protection added to export functions]
**Vulnerability:** The `exportAuditLog` function in `ConsentRepositoryImpl` took a raw `outputPath` string and directly instantiated a `File` with it, creating a path traversal vulnerability.
**Learning:** Any file output function must validate that the canonical path of the intended output file falls within an allowed, safe directory (like `context.filesDir` or `context.cacheDir`).
**Prevention:** Always validate file paths by computing `file.canonicalPath` and checking that it begins with the canonical path of an allowed directory. Do not trust raw strings from potentially uncontrolled sources for file creation.
