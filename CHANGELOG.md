# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- `declare_c_interface!` macro in `sz_common` — eliminates ~600 lines of duplicated C FFI boilerplate
- `parse_hex_string()` utility in `sz_common` — shared hex parsing for all plugins
- `init_with_key()`/`init_with_key_iv()` test helpers — avoids `unsafe { env::set_var() }` race conditions
- Single shared C header `include/sz_encrypt_plugin.h` for all plugins
- `deny.toml` for license policy enforcement
- GitHub Actions CI workflow (fmt, clippy, test, build, doc)
- GitHub Actions security workflow (cargo-audit, cargo-deny license check, weekly schedule)
- `CHANGELOG.md`

### Changed

- Updated `thiserror` from 1.x to 2.x
- Updated `zeroize` minimum from 1.7 to 1.8
- Updated `proptest` minimum from 1.4 to 1.10
- Added `license = "Apache-2.0"` and `rust-version = "1.85"` workspace metadata
- Committed `Cargo.lock` (removed from `.gitignore`)
- Added `build/` and `COMMIT_MESSAGE.txt` to `.gitignore`
- Updated `CMakeLists.txt` to reference shared header location
- Rewrote README for two audiences: plugin users and plugin implementors

### Removed

- Per-plugin `build.rs` files (no longer needed without cbindgen)
- Per-plugin `include/` directories (replaced by shared header)
- `cbindgen` build dependency
