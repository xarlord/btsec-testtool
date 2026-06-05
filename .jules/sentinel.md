## 2024-06-12 - Prevent Path Traversal by removing unconditional /tmp allowed directory
**Vulnerability:** The `getSafeFile` function used to validate export output paths explicitly allowed world-writable directories such as `/tmp` in its validation list via a hardcoded `File("/tmp")` fallback.
**Learning:** Hardcoding a fallback to `/tmp` completely bypasses sandbox isolation if an attacker can write an output target starting with `/tmp/` on systems where `/tmp` is accessible, breaking Android's scoped storage guarantees.
**Prevention:** Avoid statically allowing temporary or globally-writable paths outside of the application's assigned cache or files directories. When falling back, use safe calls (`?.let`) on JVM properties to ensure directories are created dynamically if valid.
