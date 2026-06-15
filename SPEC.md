# PQSend Specification Pointer

> [!WARNING]
> PQSend is experimental and unaudited. The current backend is X25519-only and
> not post-quantum-secure. The pre-`v1.0.0` format is unstable.

The sole source of truth for the currently implemented `.pqsend` package byte
format is [docs/FORMAT.md](docs/FORMAT.md).

This file is retained only for compatibility with existing links, contributor
workflows, and tools that expect a top-level `SPEC.md`. Do not maintain a
second wire-format specification or high-level format summary here.

Related canonical documents:

- [Security model](docs/SECURITY-MODEL.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Compatibility rules](docs/COMPATIBILITY.md)
