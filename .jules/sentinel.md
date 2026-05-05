## 2026-05-18 - Path Traversal Vulnerability in File Export
**Vulnerability:** The `exportAuditLog` method in `ConsentRepositoryImpl` accepted an unsanitized `outputPath` string from the user and passed it directly to `File(outputPath)`, enabling a path traversal vulnerability.
**Learning:** This vulnerability existed because there was no validation to verify if the resolved path was within safe, allowed application directories before creating the file object.
**Prevention:** To prevent this, always resolve the `canonicalPath` of user-provided paths and verify they match an allowed base directory exactly (`canonicalPath == base`) or strictly begin with the directory plus a separator (`canonicalPath.startsWith(base + File.separator)`) before instantiating or writing to the file.
