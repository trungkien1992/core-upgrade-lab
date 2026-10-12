# Core Upgrade Lab

A reusable, dependency-free testing tool for Bitcoin Core release transitions.
It turns selected release-guide workflows into local, inspectable evidence for
wallet developers, node operators and release testers.

The first supported transition is **Bitcoin Core 31.1 to 32.0rc3** on Linux
x86_64. The tool was executed on genuine, checksum- and signature-verified Core
binaries. See `evidence/run-06/report.html` for the readable result and
`evidence/run-06/results.json` for the underlying checks. The second fresh v0.1.1 run
is included under `evidence/run-07/`.

## What it contributes

A release can keep transactions valid while changing an API or interchange
default that downstream applications depend on. This project makes selected
changes easy to reproduce and inspect:

- PSBT v2 becomes the candidate default. The baseline rejects the candidate
  default PSBT, while an explicit version 0 PSBT decodes on the baseline.
- Watch-only exports from the candidate restore on the baseline with matching
  public descriptors and transaction counts.
- Documented RPC discovery, balance fields and mempool size fields are checked.
- An existing lab wallet is opened by the candidate, and its balance, transaction
  history, descriptors and chain tip are compared before another local spend.

It records exact binary hashes, observed RPC responses and file checksums.
The application never supplies an existing wallet or production data directory.
Each node runs a new private regtest fixture with peer networking disabled.

## Quick start

Requirements: Python 3.12+, Linux x86_64, GnuPG `gpg` and `gpgv`, internet access
for the two official downloads, about 1 GB of free disk space. The lab itself
has no Python package dependencies and requires no blockchain synchronization.

Review the pinned signing fingerprint and provenance policy before downloading:

```bash
python3 bootstrap.py --directory vendor
python3 core_upgrade_lab.py run \
  --baseline-dir vendor/31.1/bitcoin-31.1/bin \
  --candidate-dir vendor/32.0rc3/bitcoin-32.0rc3/bin \
  --provenance vendor/provenance.json \
  --output output/my-run
python3 core_upgrade_lab.py verify output/my-run
python3 -m unittest discover -s tests -v
```

Choose a new output name for each run. The runner refuses existing output and
runtime directories. It never deletes or resets a user data directory.
Open `output/my-run/report.html` locally after the run.
See [the reproduction guide](docs/REPRODUCING.md) for the observations that
should agree across fresh fixtures and the details that naturally vary.

## Actual validation

The packaged evidence contains two fresh integration runs with **30 checks
passed, 0 failed, 0 errors** in each run. These are checks, not 30 independent
security findings. A pass may confirm an expected incompatibility.

The measurement controls separately demonstrate assertion failure, runtime
error, invalid setup selection, altered evidence and modified signature data.
Read `evidence/measurement-controls.json` and the unit-test log.

| Phase | Scope |
| --- | --- |
| Baseline | Standard descriptor wallets, local payment, PSBT pipeline, public descriptor import and RPC observations |
| Candidate | The same flows plus the documented candidate contracts |
| Cross version | Legacy PSBT decoding, default PSBT compatibility observation and watch-only restore |
| Upgrade | Same-directory wallet and chain preservation, followed by a local confirmed spend |

## Reading the result correctly

A successful lab run establishes the listed observations for these binaries,
fixtures, settings and host. It does not establish general security, consensus
correctness, release readiness, hardware-wallet compatibility or downstream
application coverage. The candidate default PSBT rejection on 31.1 is a
documented compatibility change, not a vulnerability finding.

Hashes detect altered evidence relative to the supplied manifest. Someone able
to replace every file and manifest can forge a package; an independently
repeated run or an external signature is needed to establish stronger provenance.

Runtime wallet files and cookies remain in a sibling directory ending in
`-runtime`. They are excluded from the publication package. The RPC transcript
contains only synthetic regtest data and public descriptors, without
authentication headers or cookie values.

## Existing work and scope

Bitcoin Core already has an extensive functional test suite, release testing
guides and binary verification tooling. Bitcoinperf provides performance
comparison tooling. This lab complements that work with a narrow, portable
upgrade evidence package; it does not claim to replace those projects.

v0.1 is deliberately pinned to one version pair. Updating the contract set for
later releases requires reviewing release notes and the new testing guide.
The tool is not a generic automatic compatibility verdict for arbitrary binaries.

## Project ownership and AI assistance

This independent project was created with substantial AI assistance.
A human maintainer should understand the checks, repeat the run and take
responsibility for any public claim. Bitcoin Core's AI policy expects upstream
comments to be human-written; this package does not post comments or reviews.

Original project code and documentation are MIT licensed. Public key material
and build attestations under `provenance/` retain their upstream provenance.
See `docs/PROVENANCE.md`, `docs/ECOSYSTEM_VALUE.md` and
`docs/MAINTENANCE_PLAN.md`.

## Project layout

- `core_upgrade_lab.py`: isolated node lifecycle, scenarios, reporting and verification
- `bootstrap.py`: official downloads checked against signed, pinned manifests
- `tests/`: measurement and integrity controls
- `evidence/`: genuine executed results and validation logs
- `provenance/`: exact upstream signed metadata and public key
- `docs/`: design rationale, trust limits and maintenance plan
