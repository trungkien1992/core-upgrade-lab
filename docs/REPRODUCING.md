# Reproducing a release transition

The useful external check is a fresh execution of the same runner with the
same verified releases. Copying an existing evidence directory and verifying
its hashes checks integrity; it does not repeat the workflows.

## Fresh run

1. Obtain this repository at a specific commit. Record that commit with
   `git rev-parse HEAD` and review the code and pinned trust policy.
2. On Linux x86_64 with Python 3.12 or later and GnuPG, run the Quick start
   commands in README.md. No Python packages or blockchain synchronization
   are required. Choose an output directory that does not already exist.
3. Run `python3 core_upgrade_lab.py verify output/my-run` and inspect the
   report and RPC transcript. A successful run should contain 30 passing
   checks, with no failed checks or runtime errors.
4. Record the operating system, architecture, Python version, source commit,
   executed binary hashes and observed outcome. The evidence records the
   host type, Python version, runner hash and executable hashes automatically.

The bootstrap can be repeated in the same vendor directory. It verifies the
signed manifests, archive hashes and extracted `bitcoind` bytes again. It
refuses an altered executable and never overwrites an existing installation.
Other files in a cached installation are not reverified or used by the lab.

## What should agree

| Observation | Expected for the pinned pair |
| --- | --- |
| Check counts | 12 baseline, 12 candidate, 3 cross version, 3 upgrade |
| PSBT defaults | Baseline version 0; candidate version 2 |
| Candidate default on baseline | Decoding rejected with RPC error -22 |
| Candidate explicit version 0 on baseline | Decoding succeeds |
| Candidate watch-only export on baseline | Public descriptors and transaction counts match; private keys disabled |
| Upgrade preservation | Balance, transaction count, public descriptors, chain height and tip, and private-key flag match before and after |
| Payment after upgrade | Local transaction signs and confirms |

Wallet seeds, public descriptors, addresses, block hashes, transaction IDs,
some transaction sizes and fees, and elapsed times can vary between runs.
They should not be compared byte for byte across independent fixtures.
The runner checks relationships within each run, such as exact transaction
accounting and unchanged state through the upgrade.

An automated run on another machine is a separate execution environment.
It is not a human review, an endorsement, or evidence that a downstream
application has adopted the tool.

## Report feedback

Use this project's reproduction issue template after inspecting the results.
Attach the six evidence files from your output directory if appropriate.
Inspect them before publication, particularly if you modified the runner.
Keep the sibling `-runtime` directory, wallet files and RPC cookies private.
Describe setup failures separately from failed behavioral checks. If a check
is unhelpful or duplicates another tool, explain the concrete overlap and
the workflow that would make it useful.
