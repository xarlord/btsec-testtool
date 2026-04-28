## 2024-10-24 - Path Traversal Vulnerability in File Export
**Vulnerability:** The application directly constructed a `File` object using unsanitized user input in `ConsentRepositoryImpl.kt` (`File(outputPath)`), allowing an attacker to write files anywhere on the system (path traversal vulnerability).
**Learning:** File path generation based on user input, like when exporting files, is a high-risk operation that requires validation to ensure the generated file remains inside permitted application directories.
**Prevention:** Always resolve the `canonicalPath` of user-provided paths and verify they strictly begin with permitted application directories (e.g., `context.filesDir`, `context.cacheDir`, or `/tmp`) before writing, instead of directly passing unsanitized paths to `File()`.
