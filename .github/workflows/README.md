# Workflows

## add-labels-standardized.yaml

When issues are opened,
this action adds appropriate labels to the issue.
(e.g. "triage", "customer-submission")

- [Add Labels Standardized GitHub Action]
  - Uses: [senzing-factory/build-resources/.../add-labels-to-issue.yaml]

## add-to-project-senzing-dependabot.yaml

When a Dependabot Pull Request (PR) is made against `main` branch,
this action adds the PR to the senzing organization project board as "In Progress".

- [Add to Project Senzing Dependabot GitHub Action]
  - Uses: [senzing-factory/build-resources/.../add-to-project-dependabot.yaml]

## add-to-project-senzing.yaml

When an issue is created,
this action adds the issue to the senzing organization project board as "Backlog".

- [Add to Project Senzing GitHub Action]
  - Uses: [senzing-factory/build-resources/.../add-to-project.yaml]

## claude-pr-review.yaml

When a Pull Request is opened or updated,
this action runs an automated Claude code review.

- [claude-pr-review.yaml]

## dependabot-approve-and-merge.yaml

When a Dependabot Pull Request (PR) is made against the `main` branch,
this action determines if it should be automatically approved and merged.

- [Dependabot Approve and Merge GitHub Action]
  - Uses: [senzing-factory/build-resources/.../dependabot-approve-and-merge.yaml]

## link-issues-to-pr-post-merge.yaml

When a Pull Request is merged,
this action links the referenced issues to the PR.

## lint-workflows.yaml

When a change is committed to GitHub or a Pull Request is made against the `main` branch,
this action runs [super-linter] to run multiple linters against the code.

- [Lint Workflows GitHub Action]
  - Configuration:
    - [.checkov.yaml]
    - [.jscpd.json]
    - [.yaml-lint.yml]
  - Uses: [senzing-factory/build-resources/.../lint-workflows.yaml]

## move-pr-to-done-dependabot.yaml

When a Pull Request is merged into the `main` branch,
this action moves the PR on the senzing organization project board to "Done".

- [Move PR to Done Dependabot GitHub Action]
  - Uses: [senzing-factory/build-resources/.../move-pr-to-done-dependabot.yaml]

## Rust quality gate

The Rust quality gate is split into one workflow per tool, mirroring the
per-tool layout of `template-python` (`black.yaml`, `flake8.yaml`, …). Each
runs on Pull Requests against the `main` branch. All cargo invocations use
`--locked` so CI never drifts off the committed `Cargo.lock`.

### cargo-audit.yaml

Runs [cargo-audit] to fail on crates with known RUSTSEC advisories.
Honors `.cargo/audit.toml` for ignored advisories.

- [cargo-audit.yaml]

### cargo-build.yaml

Runs `cargo build --workspace --locked` across a feature matrix
(`default`, `all-features`).

- [cargo-build.yaml]

### cargo-deny.yaml

Runs [cargo-deny] against `deny.toml` (advisories, licenses, bans, sources).

- [cargo-deny.yaml]

### cargo-doc.yaml

Runs `cargo doc --no-deps --workspace --all-features --locked` with
`RUSTDOCFLAGS=-Dwarnings` so broken doc links fail CI.

- [cargo-doc.yaml]

### cargo-machete.yaml

Runs [cargo-machete] (`--with-metadata`) to detect unused dependencies.

- [cargo-machete.yaml]

### cargo-test.yaml

Runs `cargo test --workspace --all-features --locked`.

- [cargo-test.yaml]

### cargo-vet.yaml

Runs [cargo-vet] to audit the dependency supply chain against the
`supply-chain/` configuration.

- [cargo-vet.yaml]

### clippy.yaml

Runs `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`.
Warnings are errors — keep clippy clean.

- [clippy.yaml]

### rustfmt.yaml

Runs `cargo fmt --all --check`.

- [rustfmt.yaml]

## spellcheck.yaml

When a change is committed to GitHub or a Pull Request is made against the `main` branch,
this action runs [cspell] to spell-check the repository.

[.checkov.yaml]: ../linters/README.md#checkovyaml
[.jscpd.json]: ../linters/README.md#jscpdjson
[.yaml-lint.yml]: ../linters/README.md#yaml-lintyml
[Add Labels Standardized GitHub Action]: add-labels-standardized.yaml
[Add to Project Senzing Dependabot GitHub Action]: add-to-project-senzing-dependabot.yaml
[Add to Project Senzing GitHub Action]: add-to-project-senzing.yaml
[cargo-audit]: https://github.com/rustsec/rustsec/tree/main/cargo-audit
[cargo-deny]: https://github.com/EmbarkStudios/cargo-deny
[cargo-machete]: https://github.com/bnjbvr/cargo-machete
[cargo-vet]: https://github.com/mozilla/cargo-vet
[claude-pr-review.yaml]: claude-pr-review.yaml
[cspell]: https://cspell.org/
[Dependabot Approve and Merge GitHub Action]: dependabot-approve-and-merge.yaml
[Lint Workflows GitHub Action]: lint-workflows.yaml
[Move PR to Done Dependabot GitHub Action]: move-pr-to-done-dependabot.yaml
[cargo-audit.yaml]: cargo-audit.yaml
[cargo-build.yaml]: cargo-build.yaml
[cargo-deny.yaml]: cargo-deny.yaml
[cargo-doc.yaml]: cargo-doc.yaml
[cargo-machete.yaml]: cargo-machete.yaml
[cargo-test.yaml]: cargo-test.yaml
[cargo-vet.yaml]: cargo-vet.yaml
[clippy.yaml]: clippy.yaml
[rustfmt.yaml]: rustfmt.yaml
[senzing-factory/build-resources/.../add-labels-to-issue.yaml]: https://github.com/senzing-factory/build-resources/blob/main/.github/workflows/add-labels-to-issue.yaml
[senzing-factory/build-resources/.../add-to-project-dependabot.yaml]: https://github.com/senzing-factory/build-resources/blob/main/.github/workflows/add-to-project-dependabot.yaml
[senzing-factory/build-resources/.../add-to-project.yaml]: https://github.com/senzing-factory/build-resources/blob/main/.github/workflows/add-to-project.yaml
[senzing-factory/build-resources/.../dependabot-approve-and-merge.yaml]: https://github.com/senzing-factory/build-resources/blob/main/.github/workflows/dependabot-approve-and-merge.yaml
[senzing-factory/build-resources/.../lint-workflows.yaml]: https://github.com/senzing-factory/build-resources/blob/main/.github/workflows/lint-workflows.yaml
[senzing-factory/build-resources/.../move-pr-to-done-dependabot.yaml]: https://github.com/senzing-factory/build-resources/blob/main/.github/workflows/move-pr-to-done-dependabot.yaml
[super-linter]: https://github.com/super-linter/super-linter
