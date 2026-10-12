# Ecosystem value and project choice

The selected project is a reusable release and upgrade compatibility lab.
The choice is based on evidence of demand and what can be delivered and measured
now. It is not a claim that a single project has been proven to provide the
largest possible benefit across the whole Bitcoin ecosystem.

## Evidence of demand

Bitcoin Core's contribution guidance describes in-depth testing and review as
a bottleneck. The current 32.0 release testing guide explicitly asks people to
test regularly used features across versions and says the guide is not exhaustive.

In the April 2026 release-testing discussion, participants reported shell-alias
and scripting friction while following manual instructions. A portable runner
can remove this particular setup burden and capture the observations needed
for another person to repeat the work.

Primary sources:

- https://github.com/bitcoin/bitcoin/blob/master/CONTRIBUTING.md
- https://github.com/bitcoin-core/bitcoin-devwiki/wiki/32.0-Release-Candidate-Testing-Guide
- https://bitcoincore.reviews/v31-rc-testing
- https://github.com/bitcoin/bitcoin/blob/master/doc/AI_POLICY.md

## Why this scope

| Candidate | Existing infrastructure | Marginal value we can establish |
| --- | --- | --- |
| A personal wallet testing report | Core functional tests and manual guides | Useful evidence, but less reusable |
| Another binary verifier | Core already provides signed-binary verification tools | High duplication risk |
| Core Upgrade Lab | Core tests, release guides and Bitcoinperf already exist | A local version-transition package with exact provenance and inspectable downstream API observations |

Core Upgrade Lab was chosen because one maintained tool can serve multiple
wallet projects, node operators and release cycles. The measured example is
PSBT interchange: the new default is rejected by the old version, and the
explicit legacy-format control works. This is an actionable integration issue
for developers who exchange PSBTs across versions.

Existing tools reviewed:

- https://github.com/bitcoin/bitcoin/blob/master/test/README.md
- https://github.com/bitcoin/bitcoin/blob/master/contrib/verify-binaries/README.md
- https://github.com/chaincodelabs/bitcoinperf

The duplicate check is bounded to those tools and the current guide.
Maintainer feedback may identify better integrations or overlapping projects.

## Value that is already demonstrated

The code executes on actual Core binaries, recreates the selected documented
flows, preserves evidence and verifies it. Two separate integration runs passed
the 30 defined checks. The evidence includes a confirmed cross-version PSBT
incompatibility and a working format-selection control.

The tool also checks that wallet state survives a local upgrade and that the
upgraded wallet can complete another transaction. These checks are useful
regression evidence; they do not establish all-wallet migration safety.

## Value that still needs evidence

No maintainer endorsement, independent rerun, downstream adoption or measured
review-time saving has yet been established. The first pilot should seek:

1. One independent rerun with matching outcomes.
2. Feedback from a release tester on whether the package reduces setup or review work.
3. Feedback from one wallet integration developer on the PSBT transition report.

Measure setup time, reproducibility failures, actionable integration changes
and recurring use. Do not count downloads or passing assertions as ecosystem
impact by themselves. Funding should support maintenance and demonstrated
use, with these observations attached to an application.
