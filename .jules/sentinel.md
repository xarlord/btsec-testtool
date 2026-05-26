## 2026-05-26 - Fix Path Traversal in ConsentRepositoryImpl
**Vulnerability:** Found a critical path traversal vulnerability in `ConsentRepositoryImpl.exportAuditLog` where `File(outputPath)` was constructed directly from unsanitized user input.
**Learning:** Even internal logging mechanisms and exports often take user-specified paths without adequate validation, exposing the application to path traversal or writing arbitrary files outside intended sandbox directories (like `filesDir` or `cacheDir`).
**Prevention:** Always validate that the canonical path of a generated file strictly starts with or equals the canonical path of the allowed base directory before performing any file operations.
