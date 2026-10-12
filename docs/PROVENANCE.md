# Binary and evidence provenance

The initial execution used the official Linux x86_64 release archives:

| Release | Archive SHA256 |
| --- | --- |
| 31.1 | b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e |
| 32.0rc3 | 87c92cd7e1bc41e6fcc9d7739a4a314ed1f8dde67e68985892338b1be797bdac |

Archive URLs:

- https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1-x86_64-linux-gnu.tar.gz
- https://bitcoincore.org/bin/bitcoin-core-32.0/test.rc3/bitcoin-32.0rc3-x86_64-linux-gnu.tar.gz

The archives matched noncodesigned manifests carrying valid signatures from
the Ava Chow builder key. The signing fingerprint is:

`152812300785C96444D3334D17565732E08E5E41`

The exact public key, checksum manifests and detached signatures are preserved
in `provenance/`. They were compared byte-for-byte with the upstream files at:

`bitcoin-core/guix.sigs@cdac1b3a0bf6ee3d5e688a6075e6168e275d9a4a`

- `builder-keys/achow101.gpg`
- `31.1/achow101/noncodesigned.SHA256SUMS`
- `31.1/achow101/noncodesigned.SHA256SUMS.asc`
- `32.0rc3/achow101/noncodesigned.SHA256SUMS`
- `32.0rc3/achow101/noncodesigned.SHA256SUMS.asc`

The pinned public key establishes cryptographic consistency with that source,
not independent identity verification. The operator must choose whether to
trust that fingerprint. No out-of-band key authentication, multi-builder
quorum or independent Guix reproduction is claimed.

The official download directory and current testing guide listed 32.0rc3 at
the time of selection on 12 October 2026. Preliminary attestations for 32.0rc4
were visible but were not used as evidence of a published downloadable release.

Each evidence run includes executable SHA256 values and the release provenance
records used for the run. The runner checks that supplied provenance records
identify the actual executable hashes. RPC cookies and private runtime wallets
are excluded from the published bundle.

Evidence manifests verify internal file integrity. They do not authenticate
the person who executed the run. Reported timings are observations on one host.
