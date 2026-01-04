# Project Development Standards

## Chainlink Issue Tracking (MANDATORY)

All development work MUST be tracked using chainlink. No exceptions.

### Session Workflow
```bash
# Start every work session
chainlink session start

# Mark what you're working on
chainlink session work <issue_id>

# Add discoveries/notes as you work
chainlink comment <issue_id> "Found: ..."

# End session with handoff notes
chainlink session end --notes "Completed X, Y pending"
```

### Issue Management
```bash
# Create issues
chainlink create "Issue title" -p <low|medium|high|critical>
chainlink subissue <parent_id> "Subtask title"

# Track dependencies
chainlink block <blocked_id> <blocker_id>
chainlink unblock <blocked_id> <blocker_id>

# Find work
chainlink ready          # Issues with no open blockers
chainlink next           # Suggested next issue
chainlink list           # All open issues
chainlink tree           # Hierarchical view

# Update progress
chainlink update <id> -s <open|in_progress|review|closed>
chainlink close <id>
chainlink comment <id> "Progress update..."

# Milestones
chainlink milestone create "v1.0"
chainlink milestone add <milestone_id> <issue_id>
```

### Rules
1. **Create issues BEFORE starting work** - No undocumented changes
2. **Use `session work`** - Always mark current focus
3. **Add comments** - Document discoveries, blockers, decisions
4. **Close with notes** - Future you will thank present you
5. **Large features** - Break into subissues, never exceed 500 lines per file

---

## Rust Best Practices (MANDATORY)

### Code Style
- Use `rustfmt` defaults - no custom configuration unless team-approved
- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Prefer `&str` over `String` in function parameters when ownership isn't needed
- Use `impl Trait` for return types when concrete type is irrelevant
- Prefer iterators over indexed loops
- Use `?` operator for error propagation, avoid `.unwrap()` in library code

### Error Handling
```rust
// DO: Use thiserror for library errors
#[derive(Debug, thiserror::Error)]
pub enum MyError {
    #[error("failed to read config: {0}")]
    Config(#[from] std::io::Error),
    #[error("invalid input: {msg}")]
    InvalidInput { msg: String },
}

// DO: Use anyhow for application errors
fn main() -> anyhow::Result<()> {
    // ...
}

// DON'T: Use .unwrap() or .expect() in production code paths
// EXCEPTION: Tests and provably infallible cases with comments
```

### Memory & Performance
- Avoid unnecessary allocations - use `&[T]` over `Vec<T>` when possible
- Use `Cow<'_, str>` for conditionally owned strings
- Prefer `Box<[T]>` over `Vec<T>` for fixed-size heap allocations
- Use `#[inline]` sparingly - trust the compiler
- Profile before optimizing - use `cargo flamegraph`

### Async Code
- Use `tokio` as the async runtime (unless project specifies otherwise)
- Avoid `block_on` inside async contexts
- Use `tokio::select!` for concurrent operations
- Prefer channels over shared state with locks

### Unsafe Code
- Minimize `unsafe` blocks - justify each with a `// SAFETY:` comment
- Encapsulate unsafe in safe abstractions
- Document all invariants that must be upheld
- Use `#[deny(unsafe_op_in_unsafe_fn)]` in unsafe modules

---

## Test Coverage (MANDATORY)

### Requirements
- **Minimum 80% line coverage** for all new code
- **100% coverage** for public API functions
- **All bug fixes** must include a regression test

### Test Organization
```
src/
  lib.rs
  module.rs
tests/
  integration_test.rs    # Integration tests
  fixtures/              # Test data files
```

### Running Tests
```bash
# Run all tests
cargo test

# Run with coverage (using cargo-llvm-cov)
cargo llvm-cov --html

# Run specific test
cargo test test_name

# Run ignored/expensive tests
cargo test -- --ignored
```

### Test Patterns
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_case() {
        // Arrange
        let input = "valid";

        // Act
        let result = process(input);

        // Assert
        assert_eq!(result, expected);
    }

    #[test]
    fn test_error_case() {
        let result = process("invalid");
        assert!(matches!(result, Err(MyError::InvalidInput { .. })));
    }

    // Property-based testing with proptest
    proptest! {
        #[test]
        fn doesnt_crash(s in "\\PC*") {
            let _ = process(&s);
        }
    }
}
```

### Required Test Types
1. **Unit tests** - Test individual functions in isolation
2. **Integration tests** - Test module interactions
3. **Doc tests** - All public API examples must be tested
4. **Fuzzing** - Security-critical parsing code (use `cargo-fuzz`)

---

## Supply Chain Security (MANDATORY)

### Dependency Auditing
```bash
# Install audit tools
cargo install cargo-audit cargo-deny cargo-vet

# Run before every commit
cargo audit                    # Check for known vulnerabilities
cargo deny check              # Policy enforcement
cargo vet                     # Supply chain verification
```

### cargo-deny Configuration
Create `deny.toml` in project root:
```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Zlib"]
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

### Dependency Rules
1. **Pin versions** - Use exact versions in `Cargo.toml` for direct dependencies
2. **Review new deps** - Check crate reputation, maintenance status, download count
3. **Minimize deps** - Prefer std library; justify each external crate
4. **Lock file** - Always commit `Cargo.lock`
5. **Regular updates** - Run `cargo update` weekly, audit after

### Before Adding Dependencies
```bash
# Check crate info
cargo info <crate_name>

# Check reverse dependencies (popularity)
# Visit: https://crates.io/crates/<name>/reverse_dependencies

# Check security history
cargo audit --package <crate_name>
```

---

## Code Quality Analysis (MANDATORY)

### Linting with Clippy
```bash
# Run clippy (MUST pass with no warnings)
cargo clippy -- -D warnings

# Pedantic mode for thorough review
cargo clippy -- -W clippy::pedantic
```

### Required Clippy Lints
Add to `Cargo.toml` or `lib.rs`:
```rust
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
)]
```

### Formatting
```bash
# Format code (MUST be run before commit)
cargo fmt

# Check formatting in CI
cargo fmt -- --check
```

### Additional Analysis Tools
```bash
# Install tools
cargo install cargo-machete cargo-bloat cargo-outdated

# Find unused dependencies
cargo machete

# Analyze binary size
cargo bloat --release

# Check for outdated deps
cargo outdated
```

### Pre-commit Checklist
```bash
cargo fmt                     # Format code
cargo clippy -- -D warnings   # Lint
cargo test                    # Run tests
cargo audit                   # Security check
cargo deny check             # Policy check
```

---

## CI/CD Requirements

All pull requests MUST pass:
1. `cargo fmt -- --check`
2. `cargo clippy -- -D warnings`
3. `cargo test`
4. `cargo audit`
5. `cargo deny check`
6. Coverage threshold (80%+)

### Recommended CI Workflow
```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - name: Format
        run: cargo fmt -- --check

      - name: Clippy
        run: cargo clippy -- -D warnings

      - name: Test
        run: cargo test

      - name: Audit
        run: |
          cargo install cargo-audit
          cargo audit

      - name: Deny
        run: |
          cargo install cargo-deny
          cargo deny check
```

---

## Summary Checklist

Before ANY code change:
- [ ] `chainlink session start`
- [ ] `chainlink create` or `chainlink session work <id>`

Before committing:
- [ ] `cargo fmt`
- [ ] `cargo clippy -- -D warnings`
- [ ] `cargo test` (80%+ coverage)
- [ ] `cargo audit`
- [ ] `cargo deny check`
- [ ] `chainlink comment <id> "..."` with summary

Before PR:
- [ ] `chainlink tested` (mark tests as run)
- [ ] All chainlink issues updated
- [ ] `chainlink session end --notes "..."`
