# Copilot Instructions for nexus

## Project Overview
`nexus` is a Rust-based VPN implementation. Early-stage project using Rust 2024 edition with minimal external dependencies (builds on std lib and common async patterns).

## Architecture & Code Organization
- **src/main.rs** - Entry point; currently basic template
- **Expected structure**: As the project grows, separate modules for:
  - `crypto/` - Encryption and cryptographic operations
  - `network/` - Network I/O, packet handling, protocol implementation
  - `config/` - Configuration parsing and management
  - `client/` / `server/` - Client and server implementations

## Build & Testing
- **Build**: `cargo build` (debug) or `cargo build --release` (optimized)
- **Run**: `cargo run` or `cargo run --release`
- **Tests**: `cargo test` (tests embedded in src files with `#[cfg(test)]`)
- **Linting**: `cargo clippy` to catch common mistakes
- **Formatting**: `cargo fmt` for code style consistency

## Rust Conventions in This Project
- Use **error handling**: leverage `Result<T, E>` and `?` operator; avoid panics in production code
- **Async patterns**: Expect async/await usage for network operations (when async runtime is added)
- **Naming**: snake_case for functions/variables, PascalCase for types
- **Comments**: Document public APIs and non-obvious algorithmic choices

## Key Development Workflows
1. **Adding dependencies**: Always run `cargo tree` after updating Cargo.toml to verify the dependency graph
2. **Security-sensitive code**: Network and crypto modules are critical-path; prioritize correctness and use well-tested libraries
3. **Incremental development**: Build features modularly (e.g., basic protocol → encryption → authentication)

## Common Patterns
- Use `Result` for fallible operations; propagate errors upward
- Leverage Rust's type system to make invalid states unrepresentable
- For network code, favor async/await over threads when bandwidth/latency-sensitive

## Resources
- [Rust Book](https://doc.rust-lang.org/book/) for language fundamentals
- [Tokio](https://tokio.rs/) - async runtime (likely needed for VPN networking)
- [rustls](https://github.com/rustls/rustls) - for TLS if needed
