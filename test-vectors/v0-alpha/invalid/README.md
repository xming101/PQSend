# Invalid v0-alpha Vectors

These vectors are expected to be rejected by implementations supporting the
named experimental v0-alpha behavior. They cover:

- bad or unsupported public-envelope fields and invalid payload lengths
- malformed authenticated inner plaintext, including unsafe filename, hash,
  and trailing-data cases
- trailing, tampered, and truncated encrypted packages

Expected failure reasons and SHA-256 hashes of the exact vector bytes are
recorded in [`../manifest.toml`](../manifest.toml). Implementations must reject
these vectors without permissive recovery parsing.
