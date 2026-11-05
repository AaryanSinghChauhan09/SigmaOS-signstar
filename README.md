# SigmaOS-signstar

Secure enclave package signing service

Part of the [SigmaOS](https://github.com/AaryanSinghChauhan09) modular operating-system
ecosystem, inspired by the Arch Linux project layout (`archlinux/signstar`).

## Principles

- Single Responsibility — one component, one repository
- Secure by default, fail-fast, defensive programming
- Memory-safe Rust implementation
- Deterministic, self-validating tests (arrange-act-assert)
- Stable API surface, loose coupling, high cohesion

## Build & Test

```sh
cargo build
cargo test
```

## License

MIT — see [LICENSE](LICENSE).
