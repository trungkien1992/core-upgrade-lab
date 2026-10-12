# Core Upgrade Lab evidence report

Run: 2026-10-12T12:34:25.273723+00:00
Baseline: Bitcoin Core daemon version v31.1.0 bitcoind
Candidate: Bitcoin Core daemon version v32.0.0rc3 bitcoind

Outcome: 30 passed, 0 failed, 0 errors.

The lab ran ordinary workflows on private regtest nodes with peer networking disabled.
Results apply to these binaries, scenarios, host and settings. They are not a general security audit, a consensus assurance claim, or permission to test third-party systems.

Passing a check can confirm an expected incompatibility. The PSBT v2 decoding result must be read alongside the explicit version 0 compatibility control.

| Phase | Check | Result |
| --- | --- | --- |
| baseline | network_isolation | pass |
| baseline | descriptor_wallet_and_mature_funds | pass |
| baseline | documented_invalid_height_control | pass |
| baseline | ordinary_payment_accounting | pass |
| baseline | mempool_rpc_size_contract | pass |
| baseline | payment_confirmation | pass |
| baseline | default_psbt_fund_sign_finalize_confirm | pass |
| baseline | legacy_psbt_format_available | pass |
| baseline | watch_only_and_signing_controls | pass |
| baseline | rpc_discovery_contract | pass |
| baseline | balance_rpc_contract | pass |
| baseline | capture_upgrade_reference_state | pass |
| candidate | network_isolation | pass |
| candidate | descriptor_wallet_and_mature_funds | pass |
| candidate | documented_invalid_height_control | pass |
| candidate | ordinary_payment_accounting | pass |
| candidate | mempool_rpc_size_contract | pass |
| candidate | payment_confirmation | pass |
| candidate | default_psbt_fund_sign_finalize_confirm | pass |
| candidate | legacy_psbt_format_available | pass |
| candidate | watch_only_and_signing_controls | pass |
| candidate | rpc_discovery_contract | pass |
| candidate | balance_rpc_contract | pass |
| candidate | capture_upgrade_reference_state | pass |
| cross_version | candidate_legacy_psbt_decodes_on_baseline | pass |
| cross_version | candidate_default_psbt_baseline_observation | pass |
| cross_version | candidate_watch_only_export_restores_on_baseline | pass |
| upgrade | network_isolation_after_upgrade | pass |
| upgrade | wallet_and_chain_state_preserved | pass |
| upgrade | wallet_spends_after_upgrade | pass |

## Compatibility observations

### baseline default_psbt_fund_sign_finalize_confirm

```json
{
  "default_psbt_version": 0,
  "signed_complete": true,
  "finalized": true,
  "accepted_locally": true,
  "confirmed": true,
  "funding_fee_sats": 282
}
```

### candidate default_psbt_fund_sign_finalize_confirm

```json
{
  "default_psbt_version": 2,
  "signed_complete": true,
  "finalized": true,
  "accepted_locally": true,
  "confirmed": true,
  "funding_fee_sats": 282
}
```

### cross_version candidate_default_psbt_baseline_observation

```json
{
  "baseline_decodes_candidate_default": false,
  "rpc_error": -22,
  "rpc_message": "TX decode failed Unsupported version number: iostream error",
  "candidate_default_psbt_version": 2,
  "interpretation": "Observed compatibility result, not a vulnerability verdict"
}
```

### cross_version candidate_legacy_psbt_decodes_on_baseline

```json
{
  "candidate_explicit_version": 0,
  "baseline_decodes": true
}
```

### cross_version candidate_watch_only_export_restores_on_baseline

```json
{
  "source_transaction_count": 105,
  "restored_transaction_count": 105,
  "restored_private_keys_enabled": false,
  "public_descriptors_equal": true
}
```

### upgrade wallet_and_chain_state_preserved

```json
{
  "unchanged_fields": [
    "balance_sats",
    "txcount",
    "private_keys_enabled",
    "descriptors",
    "chain_height",
    "bestblockhash"
  ],
  "balance_sats": 14849999436,
  "txcount": 105,
  "chain_height": 103
}
```

## Reproduction

Use the pinned bootstrap tool and the run command in README.md. Run the verifier on this directory after copying it. Each binary digest, release archive digest and signing fingerprint is recorded. Authentication cookies, wallet files and runtime directories are excluded from the published evidence.

Report elapsed times are observations for this host, not controlled performance benchmarks.
No reviewer adoption, maintainer endorsement or time-saving estimate is claimed.
