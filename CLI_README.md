> **Rust edition.** This is the Rust port of the `mjksig` CLI. Install with
> `cargo install majik-signature --features cli`; every command, flag, exit code and JSON shape below
> is the same as the TypeScript CLI. Where the text says `npx @majikah/majik-signature` or `npm`,
> run `mjksig` instead. PNG key backups remain unsupported (use the `.json` backup).

# Majik Signature CLI

`mjksig` is the command-line interface for **Majik Signature**, providing local, scriptable workflows for signing, verifying, sealing, inspecting, and co-signing digitally signed content.

It uses the same hybrid signature architecture as the Majik Signature SDK:

- **Ed25519** for classical public-key signatures
- **ML-DSA-87 (FIPS-204)** for post-quantum signatures
- Real filesystem inputs and outputs
- Embedded signatures for self-contained files
- Detached `.mjksig` signature envelopes
- `.mjksmap` folder manifests for multi-file integrity
- Multi-signer allowlists and map co-signing
- Sealing to prevent further signing
- Machine-readable JSON output
- Non-interactive signing through `MAJIK_KEY_PASSPHRASE`

The npm package is:

```text
@majikah/majik-signature
```

The executable exposed by the package is:

```text
mjksig
```

---

## Table of Contents

- [Majik Signature CLI](#majik-signature-cli)
  - [Table of Contents](#table-of-contents)
  - [Quick Start](#quick-start)
    - [Run directly with `npx`](#run-directly-with-npx)
    - [Install globally](#install-globally)
- [Feature Overview](#feature-overview)
- [Available Commands](#available-commands)
- [Key Handling](#key-handling)
  - [Passphrase resolution](#passphrase-resolution)
    - [Interactive use](#interactive-use)
    - [Non-interactive use](#non-interactive-use)
  - [Supported key backup format](#supported-key-backup-format)
- [`sign`](#sign)
  - [Basic syntax](#basic-syntax)
    - [Example](#example)
  - [`sign` options](#sign-options)
- [Supported `sign` Workflows and Combinations](#supported-sign-workflows-and-combinations)
    - [Combining independent metadata options](#combining-independent-metadata-options)
- [Invalid `sign` Combinations](#invalid-sign-combinations)
- [`verify`](#verify)
  - [Syntax](#syntax)
  - [Options](#options)
- [`verify` Examples](#verify-examples)
- [Verification Outcomes and Exit Codes](#verification-outcomes-and-exit-codes)
- [`seal`](#seal)
  - [Syntax](#syntax-1)
  - [Options](#options-1)
  - [Examples](#examples)
- [`can-sign`](#can-sign)
  - [Syntax](#syntax-2)
  - [Options](#options-2)
  - [Examples](#examples-1)
- [`inspect`](#inspect)
  - [Syntax](#syntax-3)
  - [Options](#options-3)
  - [Examples](#examples-2)
- [MJKSMAP Workflows](#mjksmap-workflows)
  - [Create a map](#create-a-map)
  - [Verify the map](#verify-the-map)
  - [Create a map and bundle](#create-a-map-and-bundle)
  - [Establish an allowlist during map creation](#establish-an-allowlist-during-map-creation)
- [Multi-Signature and Allowlists](#multi-signature-and-allowlists)
  - [Establish an allowlist](#establish-an-allowlist)
  - [Check permission](#check-permission)
  - [Co-sign an MJKSMAP](#co-sign-an-mjksmap)
- [Batch Detached Signing](#batch-detached-signing)
  - [Basic batch signing](#basic-batch-signing)
  - [Continue after individual failures](#continue-after-individual-failures)
  - [Continue and overwrite](#continue-and-overwrite)
- [JSON Output](#json-output)
- [Common End-to-End Recipes](#common-end-to-end-recipes)
  - [1. Sign a document for self-contained verification](#1-sign-a-document-for-self-contained-verification)
  - [2. Create and verify a detached signature](#2-create-and-verify-a-detached-signature)
  - [3. Sign and expire a document](#3-sign-and-expire-a-document)
  - [4. Sign and seal a final document](#4-sign-and-seal-a-final-document)
  - [5. Sign an entire project folder](#5-sign-an-entire-project-folder)
  - [6. Create a portable map bundle](#6-create-a-portable-map-bundle)
  - [7. Authorize a second signer and co-sign a map](#7-authorize-a-second-signer-and-co-sign-a-map)
  - [8. Run in CI without an interactive terminal](#8-run-in-ci-without-an-interactive-terminal)
- [`npx` Usage](#npx-usage)
- [Complete Command Cheat Sheet](#complete-command-cheat-sheet)
- [Operational Notes](#operational-notes)
    - [Use JSON output for automation](#use-json-output-for-automation)
    - [Use `--overwrite` deliberately](#use---overwrite-deliberately)
    - [Protect private key backups](#protect-private-key-backups)
    - [Prefer pinned versions in reproducible automation](#prefer-pinned-versions-in-reproducible-automation)
    - [Verify before distribution](#verify-before-distribution)
- [Summary](#summary)



---

## Quick Start

### Run directly with `npx`

```bash
npx @majikah/majik-signature --help
```

Pin a specific version for reproducible automation:

```bash
npx @majikah/majik-signature --help
```

### Install globally

```bash
npm install -g @majikah/majik-signature
```

Then use:

```bash
mjksig --help
mjksig --version
```

---

# Feature Overview

| Feature                 | CLI support | Purpose                                                     |
| ----------------------- | ----------- | ----------------------------------------------------------- |
| Embedded signing        | Yes         | Store the signature envelope inside the original file.      |
| Detached signing        | Yes         | Create a separate `.mjksig` signature envelope.             |
| Folder signing          | Yes         | Create a `.mjksmap` manifest for a directory.               |
| MJKSMAP verification    | Yes         | Detect tampered, missing, and relocated files.              |
| Multi-signer allowlists | Yes         | Restrict who may add later signatures.                      |
| Map co-signing          | Yes         | Add an authorized second signature to every map entry.      |
| Sealing                 | Yes         | Prevent further signing of a signed envelope.               |
| JSON output             | Yes         | Consume results programmatically in scripts and CI.         |
| Batch continuation      | Yes         | Continue folder detached signing after individual failures. |
| TSA token input         | Yes         | Supply a TSA token in supported detached/co-sign workflows. |
| Interactive passphrase  | Yes         | Prompt for a hidden Majik Key passphrase in a terminal.     |
| Environment passphrase  | Yes         | Use `MAJIK_KEY_PASSPHRASE` in CI/non-interactive execution. |
| PNG Majik Key restore   | No          | The npm CLI currently accepts JSON key backups only.        |

---

# Available Commands

| Command                   | Main purpose               | Typical output                               |
| ------------------------- | -------------------------- | -------------------------------------------- |
| `mjksig --help`           | Show CLI help              | Help text                                    |
| `mjksig --version`        | Show installed CLI version | Version string                               |
| `mjksig sign <input>`     | Sign a file or folder      | Embedded signature, `.mjksig`, or `.mjksmap` |
| `mjksig verify <input>`   | Verify signed content      | Exit status plus verification result         |
| `mjksig seal <input>`     | Seal an existing envelope  | Updated signed file or `.mjksig`             |
| `mjksig can-sign <input>` | Check signing permission   | Permission result                            |
| `mjksig inspect <input>`  | Inspect signature metadata | Envelope information                         |

---

# Key Handling

The npm CLI uses **Majik Key JSON backups**.

Example:

```bash
mjksig sign report.pdf --key alice.json
```

The JSON backup is loaded and, when necessary, unlocked before signing.

## Passphrase resolution

For signing-capable operations, the CLI checks for a passphrase in this order:

1. `MAJIK_KEY_PASSPHRASE`
2. Interactive hidden terminal prompt

### Interactive use

```bash
mjksig sign report.pdf --key alice.json
```

The CLI prompts for:

```text
Majik Key passphrase:
```

### Non-interactive use

PowerShell:

```powershell
$env:MAJIK_KEY_PASSPHRASE="your-passphrase"
```

Bash/Zsh:

```bash
export MAJIK_KEY_PASSPHRASE="your-passphrase"
```

Then:

```bash
mjksig sign report.pdf --key alice.json
```

> **Security note:** environment variables can be exposed by process inspection, CI configuration, logs, or debugging tools. Use your CI platform's secret mechanism for production automation.

## Supported key backup format

The npm CLI currently accepts:

```text
.json
```

PNG Majik Key backups are rejected by the CLI because the npm package does not use the desktop application's PNG restore path.

---

# `sign`

## Basic syntax

```bash
mjksig sign <input> --key <path>
```

Embedded signing is the default when no alternate workflow flag is supplied.

### Example

```bash
mjksig sign ./contract.pdf --key ./alice.json
```

---

## `sign` options

| Option                  | Argument      | Description                                                               |
| ----------------------- | ------------- | ------------------------------------------------------------------------- |
| `-k, --key <path>`      | Path          | Majik Key JSON backup used for signing. Required.                         |
| `-o, --output <path>`   | Path          | Custom output file or directory where supported by the selected workflow. |
| `--detached`            | None          | Use detached `.mjksig` signing instead of embedding the envelope.         |
| `--map`                 | None          | Use MJKSMAP folder-signing mode.                                          |
| `--mjksmap`             | None          | Alias for `--map`.                                                        |
| `--as-map`              | None          | Alias for `--map`.                                                        |
| `--cosign <path>`       | Path          | Co-sign an existing MJKSMAP.                                              |
| `--cosign-map <path>`   | Path          | Explicit alias/path form for MJKSMAP co-signing.                          |
| `--bundle`              | None          | Create a ZIP bundle in supported map/co-sign workflows.                   |
| `--seal`                | None          | Seal the resulting signed envelope in workflows that support sealing.     |
| `--content-type <mime>` | MIME type     | Set the signature content type metadata.                                  |
| `--timestamp <iso>`     | ISO timestamp | Set an explicit signature timestamp.                                      |
| `--valid-until <iso>`   | ISO timestamp | Add an expiration timestamp to the signature metadata.                    |
| `--allow-key <path>`    | Path          | Add an additional authorized signer to the signing allowlist. Repeatable. |
| `--tsa-token <path>`    | Path          | Supply a TSA token in supported detached/co-sign workflows.               |
| `--continue-on-error`   | None          | Continue folder processing after an individual failure.                   |
| `--overwrite`           | None          | Replace an existing output where supported.                               |
| `--json`                | None          | Emit machine-readable JSON instead of human-readable output.              |

---

# Supported `sign` Workflows and Combinations

The following table covers the meaningful CLI workflow combinations exposed by the current command parser and exercised by the test suite.

| Workflow                               | Example                                                                                                              | What it does                                                                 |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Embedded signing                       | `mjksig sign report.pdf --key alice.json`                                                                            | Signs the file and embeds the signature envelope into the file.              |
| Embedded + JSON                        | `mjksig sign report.pdf --key alice.json --json`                                                                     | Same as embedded signing, with JSON result output.                           |
| Embedded + content type                | `mjksig sign data.bin --key alice.json --content-type application/octet-stream`                                      | Stores the supplied MIME type in signature metadata.                         |
| Embedded + fixed timestamp             | `mjksig sign report.pdf --key alice.json --timestamp 2026-10-01T12:00:00.000Z`                                       | Uses a deterministic signature timestamp.                                    |
| Embedded + expiration                  | `mjksig sign report.pdf --key alice.json --valid-until 2027-01-01T00:00:00.000Z`                                     | Adds `validUntil` metadata.                                                  |
| Embedded + allowlist                   | `mjksig sign contract.pdf --key alice.json --allow-key bob.json`                                                     | Alice signs first and establishes an allowlist that includes Bob.            |
| Embedded + multiple allowlist keys     | `mjksig sign contract.pdf --key alice.json --allow-key bob.json --allow-key carol.json`                              | Establishes an allowlist containing multiple authorized signers.             |
| Embedded + seal                        | `mjksig sign final.pdf --key alice.json --seal`                                                                      | Signs and seals the resulting envelope.                                      |
| Embedded + metadata + JSON             | `mjksig sign report.pdf --key alice.json --content-type application/pdf --timestamp 2026-10-01T12:00:00.000Z --json` | Signs with explicit metadata and machine-readable output.                    |
| Detached signing                       | `mjksig sign report.pdf --key alice.json --detached`                                                                 | Creates `report.pdf.mjksig` and leaves the source file unchanged.            |
| Detached + custom output               | `mjksig sign report.pdf --key alice.json --detached --output ./signatures/report.mjksig`                             | Writes the detached envelope to a custom path.                               |
| Detached + overwrite                   | `mjksig sign report.pdf --key alice.json --detached --output ./report.mjksig --overwrite`                            | Replaces an existing detached output.                                        |
| Detached + allowlist                   | `mjksig sign contract.pdf --key alice.json --detached --allow-key bob.json`                                          | Creates a detached envelope with an allowlist.                               |
| Detached + JSON                        | `mjksig sign report.pdf --key alice.json --detached --json`                                                          | Detached signing with JSON result output.                                    |
| Detached + TSA token                   | `mjksig sign report.pdf --key alice.json --detached --tsa-token ./token.bin`                                         | Supplies a TSA token to a supported detached signing flow.                   |
| Folder MJKSMAP signing                 | `mjksig sign ./project --key alice.json --map`                                                                       | Signs the folder into `signatures.mjksmap`.                                  |
| Folder MJKSMAP via alias               | `mjksig sign ./project --key alice.json --mjksmap`                                                                   | Same as `--map`.                                                             |
| Folder MJKSMAP via alias               | `mjksig sign ./project --key alice.json --as-map`                                                                    | Same as `--map`.                                                             |
| MJKSMAP + allowlist                    | `mjksig sign ./project --key alice.json --map --allow-key bob.json`                                                  | Creates mapped entries while authorizing Bob to co-sign.                     |
| MJKSMAP + multiple allowlist keys      | `mjksig sign ./project --key alice.json --map --allow-key bob.json --allow-key carol.json`                           | Establishes a multi-signer allowlist on map entries.                         |
| MJKSMAP + bundle                       | `mjksig sign ./project --key alice.json --map --bundle`                                                              | Creates the map plus a ZIP bundle.                                           |
| MJKSMAP + JSON                         | `mjksig sign ./project --key alice.json --map --json`                                                                | Creates the map with machine-readable output.                                |
| MJKSMAP + allowlist + bundle           | `mjksig sign ./project --key alice.json --map --allow-key bob.json --bundle`                                         | Creates an authorized map and a ZIP bundle.                                  |
| MJKSMAP co-sign                        | `mjksig sign ./project --key bob.json --cosign ./project/signatures.mjksmap --overwrite`                             | Bob adds a signature to each map entry for which Bob is authorized.          |
| MJKSMAP co-sign via `--cosign-map`     | `mjksig sign ./project --key bob.json --cosign-map ./project/signatures.mjksmap --overwrite`                         | Same co-signing workflow using the explicit `--cosign-map` option.           |
| MJKSMAP co-sign + bundle               | `mjksig sign ./project --key bob.json --cosign ./project/signatures.mjksmap --bundle --overwrite`                    | Co-signs the map and produces the supported bundle output.                   |
| MJKSMAP co-sign + JSON                 | `mjksig sign ./project --key bob.json --cosign ./project/signatures.mjksmap --overwrite --json`                      | Co-signs with machine-readable output.                                       |
| Folder detached signing                | `mjksig sign ./documents --key alice.json --detached`                                                                | Processes signable files in a directory using detached sidecars.             |
| Folder detached + continue             | `mjksig sign ./documents --key alice.json --detached --continue-on-error`                                            | Keeps processing when an individual file cannot be signed.                   |
| Folder detached + overwrite            | `mjksig sign ./documents --key alice.json --detached --overwrite`                                                    | Replaces existing detached outputs where supported.                          |
| Folder detached + continue + overwrite | `mjksig sign ./documents --key alice.json --detached --continue-on-error --overwrite`                                | Continues through failures and replaces existing sidecars where appropriate. |

### Combining independent metadata options

The following options are independent metadata/output modifiers and can be added to an otherwise valid signing workflow when supported:

```text
--content-type <mime>
--timestamp <iso>
--valid-until <iso>
--json
--overwrite
--seal
```

For example:

```bash
mjksig sign contract.pdf \
  --key alice.json \
  --content-type application/pdf \
  --timestamp 2026-10-01T12:00:00.000Z \
  --valid-until 2027-01-01T00:00:00.000Z \
  --json
```

---

# Invalid `sign` Combinations

The CLI intentionally rejects certain combinations.

| Combination                                      | Result  | Why                                                                             |
| ------------------------------------------------ | ------- | ------------------------------------------------------------------------------- |
| `--map --detached`                               | Invalid | Map mode and detached single-envelope mode are different workflows.             |
| `--map --cosign`                                 | Invalid | Initial map creation and map co-signing are separate operations.                |
| `--detached --cosign`                            | Invalid | Detached signing and MJKSMAP co-signing are separate operations.                |
| `--bundle` without `--map` or `--cosign`         | Invalid | Bundling is tied to map/co-sign workflows.                                      |
| `--tsa-token` without `--detached` or `--cosign` | Invalid | TSA token input is restricted to supported detached/co-sign workflows.          |
| `--allow-key` with `--cosign`                    | Invalid | Co-signing uses the allowlist already established by the existing envelope/map. |

> **Allowlist rule:** the first signer establishes the signing allowlist. A later signer should not try to create a new allowlist after another signer has already signed the file. Use the co-sign workflow for an already-authorized signer.

---

# `verify`

## Syntax

```bash
mjksig verify <input> [options]
```

`verify` supports the following verification targets:

- Embedded signature in the input file
- Detached `.mjksig` envelope supplied with `--detached`
- Folder contents verified against an `.mjksmap` supplied with `--map`

## Options

| Option              | Argument | Description                                                        |
| ------------------- | -------- | ------------------------------------------------------------------ |
| `-k, --key <path>`  | Path     | Optional Majik Key reference for supported verification workflows. |
| `--detached <path>` | Path     | Detached `.mjksig` envelope to verify against the input file.      |
| `--map <path>`      | Path     | `.mjksmap` file used to verify a folder.                           |
| `--order <signers>` | CSV      | Expected signer fingerprints in order, separated by commas.        |
| `--strict`          | None     | Enable strict verification behavior.                               |
| `--json`            | None     | Emit machine-readable JSON.                                        |

---

# `verify` Examples

| Workflow                        | Example                                                                                 | What it does                                            |
| ------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Verify embedded                 | `mjksig verify report.pdf`                                                              | Verifies the signature embedded in `report.pdf`.        |
| Verify embedded + JSON          | `mjksig verify report.pdf --json`                                                       | Returns the embedded verification result as JSON.       |
| Verify embedded + strict        | `mjksig verify report.pdf --strict`                                                     | Performs strict verification.                           |
| Verify with signer order        | `mjksig verify report.pdf --order alice,bob`                                            | Supplies an expected signer sequence.                   |
| Verify + order + strict         | `mjksig verify report.pdf --order alice,bob --strict`                                   | Combines signer-order and strict verification.          |
| Verify detached                 | `mjksig verify report.pdf --detached report.pdf.mjksig`                                 | Verifies the source file against its detached envelope. |
| Verify detached + JSON          | `mjksig verify report.pdf --detached report.pdf.mjksig --json`                          | Detached verification with JSON output.                 |
| Verify detached + order         | `mjksig verify report.pdf --detached report.pdf.mjksig --order alice,bob`               | Detached verification with expected signer ordering.    |
| Verify detached + strict        | `mjksig verify report.pdf --detached report.pdf.mjksig --strict`                        | Strict detached verification.                           |
| Verify MJKSMAP                  | `mjksig verify ./project --map ./project/signatures.mjksmap`                            | Verifies every mapped file against the manifest.        |
| Verify MJKSMAP + JSON           | `mjksig verify ./project --map ./project/signatures.mjksmap --json`                     | Returns map verification as JSON.                       |
| Verify MJKSMAP + order          | `mjksig verify ./project --map ./project/signatures.mjksmap --order alice,bob`          | Verifies the map while checking signer order.           |
| Verify MJKSMAP + strict         | `mjksig verify ./project --map ./project/signatures.mjksmap --strict`                   | Strict map verification.                                |
| Verify MJKSMAP + order + strict | `mjksig verify ./project --map ./project/signatures.mjksmap --order alice,bob --strict` | Strict map verification with signer-order constraints.  |

---

# Verification Outcomes and Exit Codes

The CLI uses exit codes suitable for scripting and CI.

| Exit code | Meaning                                                                                          |
| --------: | ------------------------------------------------------------------------------------------------ |
|       `0` | Operation succeeded.                                                                             |
|       `1` | Operation completed with an unsuccessful result, such as invalid verification or denied signing. |
|       `2` | CLI usage/parsing failure, such as a missing required option or incompatible flags.              |

Typical verification verdicts include:

| Verdict    | Meaning                                                                      |
| ---------- | ---------------------------------------------------------------------------- |
| `valid`    | Signature verification succeeded.                                            |
| `invalid`  | A signature exists but verification failed, such as after content tampering. |
| `unsigned` | No recognized signature was found for the selected verification workflow.    |

For MJKSMAP verification, per-file results can additionally identify conditions such as tampering, missing files, and relocated files.

---

# `seal`

`seal` applies a seal to an existing embedded signature envelope or detached `.mjksig` envelope.

## Syntax

```bash
mjksig seal <input> --key <path>
```

## Options

| Option                | Argument      | Description                                             |
| --------------------- | ------------- | ------------------------------------------------------- |
| `-k, --key <path>`    | Path          | Majik Key JSON backup used to apply the seal. Required. |
| `-o, --output <path>` | Path          | Optional output destination where supported.            |
| `--timestamp <iso>`   | ISO timestamp | Explicit seal timestamp.                                |
| `--overwrite`         | None          | Replace an existing output where supported.             |
| `--json`              | None          | Emit machine-readable JSON.                             |

## Examples

| Workflow                      | Example                                                                            | What it does                                                    |
| ----------------------------- | ---------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| Seal embedded file            | `mjksig seal final.pdf --key alice.json`                                           | Applies a seal to the embedded envelope.                        |
| Seal embedded + timestamp     | `mjksig seal final.pdf --key alice.json --timestamp 2026-10-01T12:00:00.000Z`      | Applies a seal with an explicit timestamp.                      |
| Seal embedded + JSON          | `mjksig seal final.pdf --key alice.json --json`                                    | Applies the seal and emits JSON.                                |
| Seal detached envelope        | `mjksig seal final.pdf.mjksig --key alice.json`                                    | Seals an existing `.mjksig` envelope.                           |
| Seal detached + overwrite     | `mjksig seal final.pdf.mjksig --key alice.json --overwrite`                        | Rewrites the detached envelope after sealing.                   |
| Seal detached + custom output | `mjksig seal final.pdf.mjksig --key alice.json --output ./sealed/final.pdf.mjksig` | Writes the resulting envelope to a custom path where supported. |

A sealed envelope is intended to reject later signing attempts.

---

# `can-sign`

`can-sign` checks whether a specified Majik Key is permitted to sign the target.

## Syntax

```bash
mjksig can-sign <input> --key <path>
```

## Options

| Option             | Argument | Description                              |
| ------------------ | -------- | ---------------------------------------- |
| `-k, --key <path>` | Path     | Majik Key JSON backup to test. Required. |
| `--json`           | None     | Emit machine-readable JSON.              |

## Examples

| Workflow                    | Example                                              | What it does                                                         |
| --------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------- |
| Check unsigned file         | `mjksig can-sign report.pdf --key alice.json`        | Determines whether Alice is allowed to sign.                         |
| Check with JSON             | `mjksig can-sign report.pdf --key alice.json --json` | Same check with machine-readable output.                             |
| Check a sealed file         | `mjksig can-sign final.pdf --key bob.json`           | Reports that the sealed file is not available for another signature. |
| Check an allowlisted signer | `mjksig can-sign contract.pdf --key bob.json`        | Determines whether Bob satisfies the signing policy.                 |
| Check a denied signer       | `mjksig can-sign contract.pdf --key carol.json`      | Reports that Carol is not permitted when the allowlist excludes her. |

---

# `inspect`

`inspect` is read-only. It reports whether a recognized Majik Signature envelope is present and returns envelope metadata without modifying the target.

## Syntax

```bash
mjksig inspect <input>
```

## Options

| Option   | Argument | Description                            |
| -------- | -------- | -------------------------------------- |
| `--json` | None     | Emit machine-readable inspection data. |

## Examples

| Workflow                  | Example                                   | What it does                                        |
| ------------------------- | ----------------------------------------- | --------------------------------------------------- |
| Inspect unsigned file     | `mjksig inspect report.pdf`               | Determines whether a signature envelope is present. |
| Inspect signed file       | `mjksig inspect signed.pdf`               | Displays signature/envelope metadata.               |
| Inspect detached envelope | `mjksig inspect signed.pdf.mjksig`        | Inspects the `.mjksig` envelope directly.           |
| Inspect as JSON           | `mjksig inspect signed.pdf --json`        | Returns machine-readable inspection data.           |
| Inspect detached as JSON  | `mjksig inspect signed.pdf.mjksig --json` | Inspects a detached envelope with JSON output.      |

---

# MJKSMAP Workflows

MJKSMAP is intended for folder-level integrity and multi-file signing workflows.

## Create a map

```bash
mjksig sign ./project --key alice.json --map
```

Typical result:

```text
project/
├── alpha.txt
├── nested/
│   └── beta.txt
└── signatures.mjksmap
```

## Verify the map

```bash
mjksig verify ./project --map ./project/signatures.mjksmap
```

This can detect conditions such as:

- Modified file content
- Missing mapped files
- Relocated files identified by content hash

## Create a map and bundle

```bash
mjksig sign ./project --key alice.json --map --bundle
```

## Establish an allowlist during map creation

```bash
mjksig sign ./project \
  --key alice.json \
  --map \
  --allow-key bob.json
```

Bob can then co-sign the existing map:

```bash
mjksig sign ./project \
  --key bob.json \
  --cosign ./project/signatures.mjksmap \
  --overwrite
```

---

# Multi-Signature and Allowlists

An allowlist controls which additional signers may add signatures after the first signer.

## Establish an allowlist

The first signer establishes the policy:

```bash
mjksig sign contract.pdf \
  --key alice.json \
  --allow-key bob.json
```

For multiple authorized signers:

```bash
mjksig sign contract.pdf \
  --key alice.json \
  --allow-key bob.json \
  --allow-key carol.json
```

## Check permission

```bash
mjksig can-sign contract.pdf --key bob.json
```

## Co-sign an MJKSMAP

```bash
mjksig sign ./project \
  --key bob.json \
  --cosign ./project/signatures.mjksmap \
  --overwrite
```

> **Important:** an allowlist is established by the first signer. A later signer should use the existing allowlist rather than attempting to replace it.

---

# Batch Detached Signing

Detached mode can process folder contents.

## Basic batch signing

```bash
mjksig sign ./documents --key alice.json --detached
```

## Continue after individual failures

```bash
mjksig sign ./documents \
  --key alice.json \
  --detached \
  --continue-on-error
```

This is useful when one output already exists or one file cannot be signed but the remaining files should continue processing.

## Continue and overwrite

```bash
mjksig sign ./documents \
  --key alice.json \
  --detached \
  --continue-on-error \
  --overwrite
```

---

# JSON Output

Use `--json` when `mjksig` is being consumed by another program.

Examples:

```bash
mjksig sign report.pdf --key alice.json --json
```

```bash
mjksig verify report.pdf --json
```

```bash
mjksig can-sign report.pdf --key alice.json --json
```

```bash
mjksig inspect report.pdf --json
```

Typical automation pattern:

```powershell
mjksig verify release.zip --json

if ($LASTEXITCODE -ne 0) {
    throw "Majik Signature verification failed"
}
```

---

# Common End-to-End Recipes

## 1. Sign a document for self-contained verification

```bash
mjksig sign contract.pdf --key alice.json
```

Then verify:

```bash
mjksig verify contract.pdf
```

---

## 2. Create and verify a detached signature

Create:

```bash
mjksig sign contract.pdf --key alice.json --detached
```

Verify:

```bash
mjksig verify contract.pdf --detached contract.pdf.mjksig
```

---

## 3. Sign and expire a document

```bash
mjksig sign contract.pdf \
  --key alice.json \
  --timestamp 2026-10-01T12:00:00.000Z \
  --valid-until 2027-01-01T00:00:00.000Z
```

---

## 4. Sign and seal a final document

```bash
mjksig sign final-contract.pdf --key alice.json --seal
```

Then check whether another signer can add a signature:

```bash
mjksig can-sign final-contract.pdf --key bob.json
```

---

## 5. Sign an entire project folder

```bash
mjksig sign ./project --key alice.json --map
```

Verify later:

```bash
mjksig verify ./project --map ./project/signatures.mjksmap
```

---

## 6. Create a portable map bundle

```bash
mjksig sign ./project --key alice.json --map --bundle
```

---

## 7. Authorize a second signer and co-sign a map

Alice establishes the policy:

```bash
mjksig sign ./project \
  --key alice.json \
  --map \
  --allow-key bob.json
```

Bob co-signs:

```bash
mjksig sign ./project \
  --key bob.json \
  --cosign ./project/signatures.mjksmap \
  --overwrite
```

Verify:

```bash
mjksig verify ./project --map ./project/signatures.mjksmap
```

---

## 8. Run in CI without an interactive terminal

```bash
export MAJIK_KEY_PASSPHRASE="$MAJIK_KEY_SECRET"
```

Then:

```bash
mjksig sign ./release \
  --key ./keys/release.json \
  --map \
  --bundle \
  --json
```

---

# `npx` Usage

The npm package is scoped, so the most explicit `npx` invocation is:

```bash
npx @majikah/majik-signature <command> [options]
```

Examples:

```bash
npx @majikah/majik-signature --help
```

```bash
npx @majikah/majik-signature sign report.pdf --key alice.json
```

```bash
npx @majikah/majik-signature verify report.pdf
```

Pin a version:

```bash
npx @majikah/majik-signature verify report.pdf
```

After a global npm install, the executable is simply:

```bash
mjksig verify report.pdf
```

> If another application also installs an executable named `mjksig`, a direct `mjksig` invocation uses whichever executable appears first on the system `PATH`. Using `npx @majikah/majik-signature ...` explicitly targets the npm package.

---

# Complete Command Cheat Sheet

| Goal                         | Command                                                                            |
| ---------------------------- | ---------------------------------------------------------------------------------- |
| Show help                    | `mjksig --help`                                                                    |
| Show version                 | `mjksig --version`                                                                 |
| Embedded sign                | `mjksig sign FILE --key KEY.json`                                                  |
| Embedded sign with allowlist | `mjksig sign FILE --key ALICE.json --allow-key BOB.json`                           |
| Embedded sign + seal         | `mjksig sign FILE --key KEY.json --seal`                                           |
| Embedded sign + JSON         | `mjksig sign FILE --key KEY.json --json`                                           |
| Detached sign                | `mjksig sign FILE --key KEY.json --detached`                                       |
| Detached sign to custom path | `mjksig sign FILE --key KEY.json --detached --output OUT.mjksig`                   |
| Verify embedded              | `mjksig verify FILE`                                                               |
| Verify detached              | `mjksig verify FILE --detached FILE.mjksig`                                        |
| Verify map                   | `mjksig verify FOLDER --map FOLDER/signatures.mjksmap`                             |
| Create map                   | `mjksig sign FOLDER --key KEY.json --map`                                          |
| Create map + bundle          | `mjksig sign FOLDER --key KEY.json --map --bundle`                                 |
| Co-sign map                  | `mjksig sign FOLDER --key KEY.json --cosign FOLDER/signatures.mjksmap --overwrite` |
| Check signing permission     | `mjksig can-sign FILE --key KEY.json`                                              |
| Seal embedded                | `mjksig seal FILE --key KEY.json`                                                  |
| Seal detached                | `mjksig seal FILE.mjksig --key KEY.json --overwrite`                               |
| Inspect                      | `mjksig inspect FILE`                                                              |
| JSON output                  | Add `--json`                                                                       |
| Non-interactive passphrase   | Set `MAJIK_KEY_PASSPHRASE`                                                         |

---

# Operational Notes

### Use JSON output for automation

Human-readable output is best for interactive use. `--json` is intended for scripts, CI/CD, agents, and other software.

### Use `--overwrite` deliberately

It permits replacement of an existing output. Use it only when replacement is intentional.

### Protect private key backups

Majik Key JSON backups can contain encrypted private-key material. Keep them out of public repositories and use appropriate filesystem/secret-storage protections.

### Prefer pinned versions in reproducible automation

For CI/release systems:

```bash
npx @majikah/majik-signature verify release.zip
```

### Verify before distribution

A useful release workflow is:

```bash
mjksig sign ./release --key ./keys/release.json --map --bundle
mjksig verify ./release --map ./release/signatures.mjksmap
```

---

# Summary

The most common commands are:

```bash
# Embedded signing
mjksig sign report.pdf --key alice.json

# Detached signing
mjksig sign report.pdf --key alice.json --detached

# Verify embedded
mjksig verify report.pdf

# Verify detached
mjksig verify report.pdf --detached report.pdf.mjksig

# Folder map
mjksig sign ./project --key alice.json --map

# Verify map
mjksig verify ./project --map ./project/signatures.mjksmap

# Check signing permission
mjksig can-sign report.pdf --key alice.json

# Seal
mjksig seal report.pdf --key alice.json

# Inspect
mjksig inspect report.pdf

# Machine-readable output
mjksig verify report.pdf --json
```

**Sign. Anchor. Verify. Trust the Chain. Just like Majik.**
