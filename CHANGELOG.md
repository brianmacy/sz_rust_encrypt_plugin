# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.6.0] - 2026-05-02

### Added

- `sz_dummy_plugin` passthrough mode — `SZ_DUMMY_KEY=""` (set but empty)
  selects no-XOR / no-base64 output: `"ENC:" + plaintext` verbatim. Lets test
  fixtures whose corpus expected values are plaintext (e.g. a cleartext-style
  reference) exercise the plugin end-to-end without transforming on-disk
  bytes. Unset `SZ_DUMMY_KEY` still errors so the plugin can't be silently
  no-op'd.
- `declare_c_interface!` macro in `sz_common` — eliminates ~600 lines of duplicated C FFI boilerplate
- `parse_hex_string()` utility in `sz_common` — shared hex parsing for all plugins
- `init_with_key()`/`init_with_key_iv()` test helpers — avoids `unsafe { env::set_var() }` race conditions
- Single shared C header `include/sz_encrypt_plugin.h` for all plugins
- `deny.toml` for license policy enforcement
- GitHub Actions CI workflow (fmt, clippy, test, build, doc)
- GitHub Actions security workflow (cargo-audit, cargo-deny license check, weekly schedule)
- `CHANGELOG.md`

### Fixed

- `string_to_c_buffer` reported `actual_size = bytes.len() + 1`, including
  the trailing null terminator in the byte count returned to the engine.
  C++ reference plugins follow the spec and report `bytes.len()` (payload
  only). Engine consumers reading `actual_size` bytes therefore stored
  `<value>\0` rows on disk, mismatching SQL_TABLE comparisons against
  C++ baselines and breaking any consumer that derived a string length
  from this field. Affects every Rust plugin built on `sz_common`.
- Error codes now match the Senzing encryption plugin spec (0, -1, -5, -20, -30)
- Return type changed from `int`/`i32` to `int64_t`/`i64` per spec
- `InitPlugin` first parameter changed from `void*` to `const struct CParameterList*` per spec

### Changed

- Updated `thiserror` from 1.x to 2.x
- Updated `zeroize` minimum from 1.7 to 1.8
- Updated `proptest` minimum from 1.4 to 1.10
- Added `license = "Apache-2.0"` and `rust-version = "1.85"` workspace metadata
- Committed `Cargo.lock` (removed from `.gitignore`)
- Added `build/` and `COMMIT_MESSAGE.txt` to `.gitignore`
- Updated `CMakeLists.txt` to reference shared header location
- Rewrote README for two audiences: plugin users and plugin implementors
- AES plugin docs now honestly describe the reference implementation:
  both `encrypt()` and `encrypt_deterministic()` use the same fixed IV
  configured at init time (the spec's non-deterministic / deterministic
  split is collapsed). Updated top-level `README.md`, `sz_aes_plugin/README.md`,
  module/struct doc in `sz_aes_plugin/src/aes_encryption.rs` and `lib.rs`,
  and renamed `test_aes_non_deterministic_encryption` to
  `test_aes_encrypt_collapses_to_deterministic` to pin the actual behavior.
  No code/behavior change; documentation only.

### Removed

- Per-plugin `build.rs` files (no longer needed without cbindgen)
- Per-plugin `include/` directories (replaced by shared header)
- `cbindgen` build dependency
