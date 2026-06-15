# Future Design Notes

> [!WARNING]
> PQSend is experimental and unaudited. The current backend is X25519-only and
> not post-quantum-secure. The pre-`v1.0.0` format is unstable.

These documents collect questions and constraints for work that is not part of
the current `.pqsend` format or Rust reference CLI.

They are not specifications, compatibility promises, implementation plans, or
evidence that a feature is supported. Any future behavior requires its own
reviewed milestone, security and threat-model updates, format changes where
needed, and security-sensitive tests.

- [Multi-file packages](multi-file-packages.md)
- [Backend agility and post-quantum evaluation](backend-agility-and-pqc.md)
- [Reference GUI](reference-gui.md)

Current implemented behavior is documented in the main
[documentation index](../README.md).
