## 2024-05-25 - Prevent Path Traversal in Consent Repository File Export
**Vulnerability:** The `exportAuditLog` method in `ConsentRepositoryImpl` took a user-provided `outputPath` as a string and blindly passed it to `File()` which created an arbitrary file anywhere on the system, introducing a potential path traversal / arbitrary file write vulnerability.
**Learning:** `exportAuditLog` missed the explicit verification step `getSafeFile` used by `ReportRepositoryImpl.kt` to bound exported files to valid app-specific caching / tmp directories.
**Prevention:** When saving user-requested files based on untrusted paths, always resolve to the `canonicalPath` and strictly verify it exists within a whitelist of application directories (`filesDir`, `cacheDir`, etc.) before using the file.
