## 2026-05-15 - Path Traversal in Export
**Vulnerability:** Path traversal vulnerability found in export Audit Log where unsanitized user input was passed directly to File() constructor.
**Learning:** Relying purely on File object creation without path validation allows escaping safe directories via ../ attacks.
**Prevention:** Always resolve canonicalPath and verify it strictly starts with the allowed base directory before creating files from user input.
