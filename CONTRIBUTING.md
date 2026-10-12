# Contributing

Start with an independent rerun or a concrete downstream workflow that the
lab should cover. See docs/REPRODUCING.md. Useful feedback identifies a release,
an expected documented behavior, the actual observation and why a user or
integrator needs the check.

For a new scenario, use ordinary local regtest behavior, include a successful
control, explain the source of its release contract and distinguish an
assertion failure from a setup error. Use exact satoshi accounting. Keep
private keys, cookies and authentication headers out of published evidence.

Original code and documentation are MIT licensed. Contributors are responsible
for understanding and checking their changes, including AI-assisted changes.
Run `python3 -m unittest discover -s tests -v` for runner or verifier changes,
then execute the real pinned transition when node workflows change. Include
the source commit and evidence, with any limitations stated plainly.

This project is independent of Bitcoin Core. Follow Bitcoin Core's contribution
and AI policies when contributing there; write upstream comments yourself.
