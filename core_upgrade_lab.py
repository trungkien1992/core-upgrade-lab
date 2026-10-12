#!/usr/bin/env python3
"""Core Upgrade Lab: repeatable local Bitcoin Core compatibility evidence."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal
from typing import Any

VERSION = "0.1.1"
SCHEMA = "core-upgrade-lab/evidence-v1"
SATOSHIS = Decimal(100000000)


class CheckFailure(Exception):
    pass


class RPCError(Exception):
    def __init__(self, code: int, message: str):
        self.code, self.message = code, message
        super().__init__(f"RPC {code}: {message}")


def require(condition: bool, message: str):
    if not condition:
        raise CheckFailure(message)


def sats(value: Any) -> int:
    amount = Decimal(str(value))
    if not amount.is_finite() or amount * SATOSHIS != (amount * SATOSHIS).to_integral_value():
        raise ValueError("Amount must be finite with at most eight decimal places")
    return int(amount * SATOSHIS)


def serializable(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): serializable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [serializable(v) for v in value]
    return value


def write_json(path: Path, data: Any):
    path.write_text(json.dumps(serializable(data), sort_keys=True, indent=2, allow_nan=False) + "\n")


def sha256(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def psbt_version(encoded: str) -> int:
    """Read the BIP174 global version in a PSBT created by the local fixture."""
    data = base64.b64decode(encoded, validate=True)
    if len(data) > 8_000_000 or data[:5] != b"psbt\xff":
        raise ValueError("Not a bounded PSBT")
    offset = 5

    def compact():
        nonlocal offset
        if offset >= len(data):
            raise ValueError("Truncated compact size")
        n = data[offset]
        offset += 1
        sizes = {253: 2, 254: 4, 255: 8}
        if n in sizes:
            size = sizes[n]
            if offset + size > len(data):
                raise ValueError("Truncated compact size")
            n = int.from_bytes(data[offset:offset + size], "little")
            offset += size
        return n

    found = None
    while True:
        keylen = compact()
        if not keylen:
            break
        if offset + keylen > len(data):
            raise ValueError("Truncated key")
        key = data[offset:offset + keylen]
        offset += keylen
        vallen = compact()
        if offset + vallen > len(data):
            raise ValueError("Truncated value")
        value = data[offset:offset + vallen]
        offset += vallen
        if key == b"\xfb":
            if len(value) != 4 or found is not None:
                raise ValueError("Invalid global version")
            found = int.from_bytes(value, "little")
    return 0 if found is None else found


class Checks:
    def __init__(self, phase: str):
        self.phase = phase
        self.items: list[dict] = []

    def step(self, name: str, fn):
        start = time.monotonic()
        result = {"name": name, "phase": self.phase}
        try:
            result["observed"] = serializable(fn())
            result["status"] = "pass"
        except CheckFailure as e:
            result.update(status="fail", error=str(e))
        except Exception as e:
            result.update(status="error", error=f"{type(e).__name__}: {e}")
        result["elapsed_seconds"] = round(time.monotonic() - start, 4)
        self.items.append(result)
        print(f"[{self.phase}] {name}: {result['status']}", flush=True)
        return result.get("observed") if result["status"] == "pass" else None


class Node:
    """Always starts a new regtest process in a lab-owned runtime directory."""
    def __init__(self, bindir: Path, datadir: Path, label: str):
        self.bindir, self.datadir, self.label = bindir.resolve(), datadir, label
        self.process = None
        self.transcript: list[dict] = []
        self.log = None
        self.port = None
        self.binary = self.bindir / "bitcoind"
        if not self.binary.is_file():
            raise ValueError(f"Missing bitcoind: {self.binary}")

    def start(self):
        self.datadir.mkdir(parents=True, exist_ok=True)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        args = [
            str(self.binary), f"-datadir={self.datadir}", "-regtest=1",
            "-server=1", "-listen=0", "-listenonion=0", "-discover=0",
            "-dnsseed=0", "-fixedseeds=0", "-connect=0", "-networkactive=0",
            "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            f"-rpcport={self.port}", "-txindex=1", "-fallbackfee=0.00002000",
            "-printtoconsole=0", "-persistmempool=0", "-daemon=0",
        ]
        self.log = (self.datadir / f"{self.label}.stdout.log").open("wb")
        self.process = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.log.close()
                text = (self.datadir / f"{self.label}.stdout.log").read_text(errors="replace")
                raise RuntimeError(f"Node failed to start: {text[-2400:]}")
            try:
                self.rpc("getblockchaininfo")
                return self
            except (RPCError, OSError, urllib.error.URLError):
                time.sleep(0.1)
        self.stop()
        raise TimeoutError("Node did not become ready within 30 seconds")

    def rpc(self, method: str, params=None, wallet: str | None = None):
        cookie = (self.datadir / "regtest" / ".cookie").read_text().strip()
        path = "/" if wallet is None else "/wallet/" + urllib.parse.quote(wallet, safe="")
        request_data = {"jsonrpc": "2.0", "id": len(self.transcript) + 1,
                        "method": method, "params": [] if params is None else params}
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(request_data).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": "Basic " + base64.b64encode(cookie.encode()).decode()},
        )
        # Ignore ambient proxies for the loopback-only RPC connection.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=15) as response:
                raw = response.read(8_000_001)
        except urllib.error.HTTPError as e:
            raw = e.read(8_000_001)
        if len(raw) > 8_000_000:
            raise ValueError("Unexpectedly large RPC response")
        payload = json.loads(raw, parse_float=Decimal)
        result = payload.get("result")
        error = payload.get("error")
        # Authentication is deliberately never included in published evidence.
        self.transcript.append({"method": method, "params": request_data["params"],
                                "wallet": wallet, "result": serializable(result),
                                "error": error})
        if error:
            raise RPCError(error["code"], error["message"])
        if "result" not in payload or payload.get("id") != request_data["id"]:
            raise ValueError("Malformed or mismatched RPC response")
        return result

    def stop(self):
        if self.process is None:
            return
        try:
            if self.process.poll() is None:
                try:
                    self.rpc("stop")
                except Exception:
                    pass
                try:
                    self.process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=5)
        finally:
            if self.log and not self.log.closed:
                self.log.close()
            self.process = None


def isolation(node: Node):
    chain, network = node.rpc("getblockchaininfo"), node.rpc("getnetworkinfo")
    require(chain["chain"] == "regtest", "This must be a regtest chain")
    require(network["connections"] == 0, "Unexpected peer connection")
    require(network["networkactive"] is False, "Peer networking must be disabled")
    return {"chain": chain["chain"], "connections": network["connections"],
            "networkactive": network["networkactive"], "rpc_host": "127.0.0.1"}


def wallet_snapshot(node: Node, wallet="funding"):
    info = node.rpc("getwalletinfo", wallet=wallet)
    return {
        "balance_sats": sats(node.rpc("getbalance", wallet=wallet)),
        "txcount": info["txcount"], "private_keys_enabled": info["private_keys_enabled"],
        "descriptors": sorted(x["desc"] for x in node.rpc("listdescriptors", [False], wallet)["descriptors"]),
        "chain_height": node.rpc("getblockcount"),
        "bestblockhash": node.rpc("getbestblockhash"),
    }


def run_common(node: Node, checks: Checks, role: str):
    state = {}
    checks.step("network_isolation", lambda: isolation(node))

    def setup():
        for name in ["funding", "receiver"]:
            node.rpc("createwallet", {"wallet_name": name, "descriptors": True})
        address = node.rpc("getnewaddress", ["", "bech32"], "funding")
        state["mining_address"] = address
        node.rpc("generatetoaddress", [101, address])
        info = node.rpc("getwalletinfo", wallet="funding")
        balance = sats(node.rpc("getbalance", wallet="funding"))
        require(info["descriptors"] is True and info["private_keys_enabled"] is True,
                "Expected a signing descriptor wallet")
        require(balance > 0, "No mature regtest coins")
        return {"height": node.rpc("getblockcount"), "mature_balance_sats": balance,
                "descriptor_wallet": True}
    checks.step("descriptor_wallet_and_mature_funds", setup)

    def invalid_control():
        try:
            node.rpc("getblockhash", [-1])
        except RPCError as e:
            require(e.code == -8, "Unexpected error code for documented invalid height")
            return {"expected_error": -8, "observed_error": e.code}
        raise CheckFailure("Invalid block height was unexpectedly accepted")
    checks.step("documented_invalid_height_control", invalid_control)

    def payment():
        destination = node.rpc("getnewaddress", ["", "bech32"], "receiver")
        txid = node.rpc("sendtoaddress", {"address": destination, "amount": 1,
                                         "fee_rate": 2}, "funding")
        record = node.rpc("gettransaction", [txid], "funding")
        tx = node.rpc("decoderawtransaction", [record["hex"]])
        inputs = 0
        for vin in tx["vin"]:
            prev = node.rpc("gettransaction", [vin["txid"]], "funding")
            decoded = node.rpc("decoderawtransaction", [prev["hex"]])
            inputs += sats(decoded["vout"][vin["vout"]]["value"])
        outputs = sum(sats(vout["value"]) for vout in tx["vout"])
        fee = -sats(record["fee"])
        require(inputs - outputs == fee and fee > 0, "Transaction accounting does not match")
        receive = node.rpc("gettransaction", [txid], "receiver")
        require(sats(receive["amount"]) == 100_000_000, "Wrong recipient amount")
        require(receive["confirmations"] == 0, "Expected unconfirmed payment")
        state["payment_txid"] = txid
        state["payment_vsize"] = tx["vsize"]
        return {"input_sats": inputs, "output_sats": outputs, "fee_sats": fee,
                "recipient_sats": sats(receive["amount"]), "vsize": tx["vsize"],
                "requested_fee_rate_sat_vb": 2}
    checks.step("ordinary_payment_accounting", payment)

    def mempool():
        txid = state["payment_txid"]
        entry = node.rpc("getmempoolentry", [txid])
        raw = node.rpc("getrawtransaction", [txid, True])
        require(entry["vsize"] > 0, "Missing positive vsize")
        fields = {k: entry[k] for k in ["vsize", "vsize_adjusted", "vsize_bip141"] if k in entry}
        if role == "candidate":
            require("vsize_adjusted" in entry and "vsize_bip141" in entry,
                    "Candidate should expose the documented vsize fields")
            require(raw["vsize_adjusted"] == entry["vsize_adjusted"],
                    "RPC vsize observations disagree")
        return {"mempool_fields": fields,
                "raw_transaction_fields": {k: raw[k] for k in fields if k in raw}}
    checks.step("mempool_rpc_size_contract", mempool)

    def confirm():
        node.rpc("generatetoaddress", [1, state["mining_address"]])
        record = node.rpc("gettransaction", [state["payment_txid"]], "receiver")
        require(record["confirmations"] >= 1, "Payment did not confirm")
        require(sats(node.rpc("getbalance", wallet="receiver")) == 100_000_000,
                "Unexpected recipient confirmed balance")
        return {"confirmations": record["confirmations"], "recipient_balance_sats": 100_000_000}
    checks.step("payment_confirmation", confirm)

    def psbt_flow():
        destination = node.rpc("getnewaddress", ["", "bech32"], "receiver")
        funded = node.rpc("walletcreatefundedpsbt", {
            "inputs": [], "outputs": [{destination: 0.5}], "locktime": 0,
            "options": {"fee_rate": 2},
        }, "funding")
        version = psbt_version(funded["psbt"])
        require(version == (2 if role == "candidate" else 0),
                "PSBT default differs from the pinned release contract")
        signed = node.rpc("walletprocesspsbt", [funded["psbt"]], "funding")
        final = node.rpc("finalizepsbt", [signed["psbt"]])
        require(final["complete"] is True and bool(final.get("hex")), "PSBT did not finalize")
        accepted = node.rpc("testmempoolaccept", [[final["hex"]]])[0]
        require(accepted["allowed"] is True, "Ordinary signed PSBT transaction rejected")
        txid = node.rpc("sendrawtransaction", [final["hex"]])
        node.rpc("generatetoaddress", [1, state["mining_address"]])
        require(node.rpc("gettransaction", [txid], "receiver")["confirmations"] >= 1,
                "PSBT transaction did not confirm")
        state["default_psbt"] = funded["psbt"]
        state["default_psbt_version"] = version
        return {"default_psbt_version": version, "signed_complete": signed["complete"],
                "finalized": True, "accepted_locally": True, "confirmed": True,
                "funding_fee_sats": sats(funded["fee"])}
    checks.step("default_psbt_fund_sign_finalize_confirm", psbt_flow)

    def legacy():
        params = {"inputs": [], "outputs": []}
        if role == "candidate":
            params["psbt_version"] = 0
        encoded = node.rpc("createpsbt", params)
        require(psbt_version(encoded) == 0, "Expected explicit legacy PSBT version 0")
        state["legacy_psbt"] = encoded
        return {"psbt_version": 0, "selection": "explicit" if role == "candidate" else "default"}
    checks.step("legacy_psbt_format_available", legacy)

    def watch_only():
        node.rpc("createwallet", {"wallet_name": "observer", "disable_private_keys": True,
                                 "blank": True, "descriptors": True})
        public = node.rpc("listdescriptors", [False], "funding")["descriptors"]
        imports = []
        for descriptor in public:
            obj = {k: descriptor[k] for k in ["desc", "active", "internal"] if k in descriptor}
            obj["timestamp"] = "now"
            obj["range"] = [0, 99]
            imports.append(obj)
        result = node.rpc("importdescriptors", [imports], "observer")
        require(all(x["success"] for x in result), "Public descriptors did not import")
        require(node.rpc("getwalletinfo", wallet="observer")["private_keys_enabled"] is False,
                "Observer unexpectedly has private keys")
        address = node.rpc("getnewaddress", ["", "bech32"], "receiver")
        funded = node.rpc("walletcreatefundedpsbt", {
            "inputs": [], "outputs": [{address: 0.25}], "locktime": 0,
            "options": {"fee_rate": 2}}, "funding")
        observer = node.rpc("walletprocesspsbt", [funded["psbt"]], "observer")
        signer = node.rpc("walletprocesspsbt", [funded["psbt"]], "funding")
        require(observer["complete"] is False and signer["complete"] is True,
                "Watch-only and signing controls did not distinguish capabilities")
        return {"public_descriptors_imported": len(imports), "private_keys_enabled": False,
                "observer_complete": False, "signing_control_complete": True}
    checks.step("watch_only_and_signing_controls", watch_only)

    def discovery():
        help_text = node.rpc("help")
        present = "getopenrpcinfo" in help_text
        if role == "baseline":
            require(present is False, "Pinned baseline unexpectedly exposes candidate API")
            return {"available": False, "expected_for_pinned_release": False}
        require(present, "Candidate discovery method missing")
        a = node.rpc("getopenrpcinfo")
        b = node.rpc("rpc.discover")
        require(a == b, "OpenRPC discovery methods disagree")
        require(a["openrpc"] == "1.4.1", "Unexpected OpenRPC document version")
        names = {method["name"] for method in a["methods"]}
        require("getblockchaininfo" in names and "exportwatchonlywallet" in names,
                "Expected methods absent in discovery")
        return {"available": True, "openrpc": a["openrpc"], "methods": len(names),
                "discovery_methods_equal": True}
    checks.step("rpc_discovery_contract", discovery)

    def balances():
        obj = node.rpc("getbalances", wallet="funding")["mine"]
        if role == "candidate":
            require("nonmempool" in obj, "Documented balance field missing")
            require(sats(obj["nonmempool"]) <= 0, "Unexpected positive nonmempool balance")
        return {"fields": sorted(obj), "nonmempool_present": "nonmempool" in obj,
                "nonmempool_sats": sats(obj["nonmempool"]) if "nonmempool" in obj else None}
    checks.step("balance_rpc_contract", balances)
    state["snapshot"] = checks.step("capture_upgrade_reference_state", lambda: wallet_snapshot(node))
    return state


def run_cross_checks(baseline: Node, candidate: Node, state: dict, checks: Checks, runtime: Path):
    def legacy_portability():
        encoded = state["legacy_psbt"]
        result = baseline.rpc("decodepsbt", [encoded])
        require(psbt_version(encoded) == 0 and isinstance(result, dict), "Legacy PSBT did not decode")
        return {"candidate_explicit_version": 0, "baseline_decodes": True}
    checks.step("candidate_legacy_psbt_decodes_on_baseline", legacy_portability)

    def default_portability():
        encoded = state["default_psbt"]
        try:
            baseline.rpc("decodepsbt", [encoded])
            outcome = {"baseline_decodes_candidate_default": True}
        except RPCError as e:
            outcome = {"baseline_decodes_candidate_default": False, "rpc_error": e.code,
                       "rpc_message": e.message}
        outcome["candidate_default_psbt_version"] = psbt_version(encoded)
        outcome["interpretation"] = "Observed compatibility result, not a vulnerability verdict"
        return outcome
    checks.step("candidate_default_psbt_baseline_observation", default_portability)

    def watch_export():
        export = runtime / "watch-only-wallet.dat"
        info = candidate.rpc("getwalletinfo", wallet="funding")
        candidate.rpc("exportwatchonlywallet", [str(export)], "funding")
        require(export.is_file(), "Watch-only export file missing")
        baseline.rpc("restorewallet", ["portable_watch", str(export)])
        restored = baseline.rpc("getwalletinfo", wallet="portable_watch")
        require(restored["private_keys_enabled"] is False, "Exported wallet has private keys enabled")
        require(restored["txcount"] == info["txcount"], "Exported wallet transaction count differs")
        require(sorted(x["desc"] for x in baseline.rpc("listdescriptors", [False], "portable_watch")["descriptors"])
                == sorted(x["desc"] for x in candidate.rpc("listdescriptors", [False], "funding")["descriptors"]),
                "Public descriptors differ after export and restore")
        return {"source_transaction_count": info["txcount"],
                "restored_transaction_count": restored["txcount"],
                "restored_private_keys_enabled": False,
                "public_descriptors_equal": True}
    checks.step("candidate_watch_only_export_restores_on_baseline", watch_export)


def run_upgrade(node: Node, reference: dict, checks: Checks):
    checks.step("network_isolation_after_upgrade", lambda: isolation(node))

    def preserve():
        # Wallet loading behavior is not assumed to be identical across releases.
        wallets = node.rpc("listwallets")
        if "funding" not in wallets:
            node.rpc("loadwallet", ["funding"])
        current = wallet_snapshot(node)
        for key in ["balance_sats", "txcount", "descriptors", "chain_height", "bestblockhash",
                    "private_keys_enabled"]:
            require(current[key] == reference[key], f"Upgrade changed {key}")
        return {"unchanged_fields": list(current), "balance_sats": current["balance_sats"],
                "txcount": current["txcount"], "chain_height": current["chain_height"]}
    checks.step("wallet_and_chain_state_preserved", preserve)

    def spend():
        destination = node.rpc("getnewaddress", ["", "bech32"], "funding")
        txid = node.rpc("sendtoaddress", {"address": destination, "amount": 0.1,
                                         "fee_rate": 2}, "funding")
        decoded = node.rpc("gettransaction", [txid], "funding")
        require(decoded["confirmations"] == 0, "Unexpected initial confirmation state")
        node.rpc("generatetoaddress", [1, destination])
        require(node.rpc("gettransaction", [txid], "funding")["confirmations"] >= 1,
                "Upgraded wallet payment did not confirm")
        return {"signs_after_upgrade": True, "local_payment_confirmed": True}
    checks.step("wallet_spends_after_upgrade", spend)


def safe_manifest_paths(root: Path, entries: dict):
    for name, digest in entries.items():
        rel = Path(name)
        if rel.is_absolute() or ".." in rel.parts or not rel.parts or not isinstance(digest, str):
            raise ValueError("Unsafe evidence manifest entry")
        path = root / rel
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError:
            raise ValueError(f"Evidence path escapes the package: {name}") from None
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Missing or symlinked evidence: {name}")
        if sha256(path) != digest:
            raise ValueError(f"Evidence hash mismatch: {name}")


def verify(root: Path):
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("schema") != SCHEMA or not isinstance(manifest.get("files"), dict):
        raise ValueError("Unsupported evidence manifest")
    required = {"results.json", "rpc-transcript.json", "report.md", "source-provenance.json",
                "report.html"}
    if not required.issubset(manifest["files"]):
        raise ValueError("Incomplete evidence manifest")
    safe_manifest_paths(root, manifest["files"])
    results = json.loads((root / "results.json").read_text())
    if results.get("schema") != SCHEMA:
        raise ValueError("Unsupported results schema")
    checks = results["checks"]
    if not checks or any(x.get("status") not in {"pass", "fail", "error"} for x in checks):
        raise ValueError("Invalid or empty check results")
    counts = {status: sum(x["status"] == status for x in checks) for status in ["pass", "fail", "error"]}
    if counts != results["counts"]:
        raise ValueError("Result counts disagree with checks")
    if results["successful"] != (counts["fail"] == counts["error"] == 0):
        raise ValueError("Success flag disagrees with checks")
    return {"files_verified": len(manifest["files"]), "counts": counts,
            "successful": results["successful"],
            "limit": "Hashes check package integrity, not independent execution or signer identity"}


def report_markdown(results: dict):
    lines = [
        "# Core Upgrade Lab evidence report", "",
        f"Run: {results['run_id']}",
        f"Baseline: {results['binaries']['baseline']['version']}",
        f"Candidate: {results['binaries']['candidate']['version']}", "",
        f"Outcome: {results['counts']['pass']} passed, {results['counts']['fail']} failed, "
        f"{results['counts']['error']} errors.", "",
        "The lab ran ordinary workflows on private regtest nodes with peer networking disabled.",
        "Results apply to these binaries, scenarios, host and settings. They are not a general "
        "security audit, a consensus assurance claim, or permission to test third-party systems.", "",
        "Passing a check can confirm an expected incompatibility. The PSBT v2 decoding result "
        "must be read alongside the explicit version 0 compatibility control.", "",
        "| Phase | Check | Result |", "| --- | --- | --- |",
    ]
    for item in results["checks"]:
        lines.append(f"| {item['phase']} | {item['name']} | {item['status']} |")
    lines.extend(["", "## Compatibility observations", ""])
    for name in ["default_psbt_fund_sign_finalize_confirm",
                 "candidate_default_psbt_baseline_observation",
                 "candidate_legacy_psbt_decodes_on_baseline",
                 "candidate_watch_only_export_restores_on_baseline", "wallet_and_chain_state_preserved"]:
        for item in results["checks"]:
            if item["name"] == name:
                lines.extend([f"### {item['phase']} {name}", "",
                              "```json", json.dumps(item.get("observed", item.get("error")), indent=2),
                              "```", ""])
    lines.extend([
        "## Reproduction", "",
        "Use the pinned bootstrap tool and the run command in README.md. Run the verifier on this "
        "directory after copying it. Each binary digest, release archive digest and signing "
        "fingerprint is recorded. Authentication cookies, wallet files and runtime directories "
        "are excluded from the published evidence.",
        "", "Report elapsed times are observations for this host, not controlled performance benchmarks.",
        "No reviewer adoption, maintainer endorsement or time-saving estimate is claimed.", "",
    ])
    return "\n".join(lines)


def report_html(results: dict):
    import html
    esc = html.escape
    counts = results["counts"]
    rows = "".join("<tr><td>" + esc(x["phase"]) + "</td><td>" +
                   esc(x["name"].replace("_", " ")) + "</td><td class='" +
                   x["status"] + "'>" + x["status"].upper() + "</td></tr>" for x in results["checks"])
    details = "".join("<details><summary>" + esc(x["phase"] + " / " + x["name"].replace("_", " ")) +
                      "</summary><pre>" + esc(json.dumps(x.get("observed", x.get("error")), indent=2)) +
                      "</pre></details>" for x in results["checks"])
    return f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Core Upgrade Lab evidence</title><style>
body{{font:16px system-ui,sans-serif;color:#19283a;background:#f4f6fa;margin:0}}
main{{max-width:1100px;margin:40px auto;padding:28px;background:white;border-radius:16px}}
h1{{font-size:38px;margin:12px 0}}.eyebrow{{letter-spacing:.08em;color:#59718b}}
.stats{{display:flex;gap:16px;margin:24px 0;flex-wrap:wrap}}.stats div{{padding:16px;background:#eef3f8;border-radius:10px;min-width:120px}}
.stats strong{{font-size:30px;display:block}}table{{width:100%;border-collapse:collapse;font-size:14px}}
td,th{{text-align:left;padding:11px;border-bottom:1px solid #dfe5ed}}th{{background:#edf2f7}}
.pass{{color:#11664d}}.fail,.error{{color:#a02232}}p{{line-height:1.6;max-width:900px}}
details{{padding:13px;border-bottom:1px solid #dfe5ed}}summary{{cursor:pointer}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6fa;padding:14px}}
small{{color:#52657a}}</style><main>
<div class="eyebrow">BITCOIN CORE RELEASE COMPATIBILITY</div><h1>Core Upgrade Lab</h1>
<p>Real local test evidence for <strong>{esc(results['binaries']['baseline']['version'])}</strong>
to <strong>{esc(results['binaries']['candidate']['version'])}</strong>.</p>
<div class="stats"><div><strong>{counts['pass']}</strong>passed</div>
<div><strong>{counts['fail']}</strong>failed</div><div><strong>{counts['error']}</strong>errors</div>
<div><strong>0</strong>network peers required</div></div>
<p>This report covers ordinary regtest node and wallet workflows, documented RPC changes,
PSBT interchange, watch-only export, and preservation of wallet state through an upgrade.</p>
<p><small>Run {esc(results['run_id'])}. Linux x86_64 validation.
The results do not establish general security, consensus correctness, downstream application
coverage, or maintainer endorsement.</small></p>
<table><thead><tr><th>Phase</th><th>Check</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Inspect the observations</h2>{details}
<p><small>Use the supplied verifier to check file integrity. Full reproduction needs the pinned
binaries and source. Runtime wallet files and RPC cookies are not included.</small></p></main></html>"""


def run(args):
    root = Path(args.output).resolve()
    if root.exists():
        raise ValueError("Output directory must not already exist; the lab never resets user data")
    runtime = root.parent / (root.name + "-runtime")
    if runtime.exists():
        raise ValueError("Runtime directory already exists")
    nodes = []
    all_checks = []
    started = time.monotonic()
    run_id = dt.datetime.now(dt.timezone.utc).isoformat()
    binaries = {}
    for role, directory in [("baseline", args.baseline_dir), ("candidate", args.candidate_dir)]:
        binary = Path(directory).resolve() / "bitcoind"
        version = subprocess.run([str(binary), "--version"], capture_output=True,
                                 text=True, timeout=10, check=True).stdout.splitlines()[0]
        binaries[role] = {"version": version, "sha256": sha256(binary), "name": "bitcoind"}
    if binaries["baseline"]["sha256"] == binaries["candidate"]["sha256"]:
        raise ValueError("Baseline and candidate binaries are identical")
    require("v31.1.0" in binaries["baseline"]["version"], "v0.1 baseline contract is 31.1.0")
    require("v32.0.0rc3" in binaries["candidate"]["version"], "v0.1 candidate contract is 32.0.0rc3")
    provenance = json.loads(Path(args.provenance).read_text()) if args.provenance else {
        "verification": "Executable hashes recorded; release signatures were not provided"}
    if args.provenance:
        require(isinstance(provenance, list), "Expected a list of release provenance records")
        for role, release in [('baseline', '31.1'), ('candidate', '32.0rc3')]:
            record = next((x for x in provenance if x.get('release') == release), None)
            require(record is not None and record.get('binary_sha256') == binaries[role]['sha256'],
                    f"Provenance does not identify the executed {role} binary")
    # Finish input validation before creating either run directory.
    root.mkdir(parents=True, mode=0o700)
    runtime.mkdir(mode=0o700)
    baseline = Node(Path(args.baseline_dir), runtime / "baseline", "baseline")
    candidate = Node(Path(args.candidate_dir), runtime / "candidate", "candidate")
    try:
        nodes.extend([baseline, candidate])
        baseline.start()
        candidate.start()
        baseline_checks, candidate_checks = Checks("baseline"), Checks("candidate")
        base_state = run_common(baseline, baseline_checks, "baseline")
        cand_state = run_common(candidate, candidate_checks, "candidate")
        all_checks.extend(baseline_checks.items + candidate_checks.items)
        cross = Checks("cross_version")
        run_cross_checks(baseline, candidate, cand_state, cross, runtime)
        all_checks.extend(cross.items)
        # Capture after cross-version restore so upgrades check the actual final baseline state.
        reference = wallet_snapshot(baseline)
        baseline.stop()
        upgraded = Node(Path(args.candidate_dir), runtime / "baseline", "upgrade")
        nodes.append(upgraded)
        upgraded.start()
        upgrade_checks = Checks("upgrade")
        run_upgrade(upgraded, reference, upgrade_checks)
        all_checks.extend(upgrade_checks.items)
    except Exception as e:
        all_checks.append({"phase": "setup_or_run", "name": "unhandled_runtime_error",
                           "status": "error", "error": f"{type(e).__name__}: {e}"})
    finally:
        for node in reversed(nodes):
            try:
                node.stop()
            except Exception as e:
                all_checks.append({"phase": "teardown", "name": "process_cleanup",
                                   "status": "error", "error": f"{type(e).__name__}: {e}"})
    transcript = []
    for node in nodes:
        transcript.extend({"phase": node.label, **entry} for entry in node.transcript)
    # Replace run-specific paths, while retaining synthetic addresses and public descriptors.
    transcript = json.loads(json.dumps(serializable(transcript)).replace(str(runtime), "$RUNTIME"))
    counts = {status: sum(x["status"] == status for x in all_checks)
              for status in ["pass", "fail", "error"]}
    results = {
        "schema": SCHEMA, "tool_version": VERSION, "run_id": run_id,
        "runner_sha256": sha256(Path(__file__)),
        "host": {"system": platform.system(), "machine": platform.machine(),
                 "python": platform.python_version()},
        "binaries": binaries, "checks": all_checks, "counts": counts,
        "successful": counts["fail"] == counts["error"] == 0,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "scope": "Owned local regtest fixtures; no peers, public network or real funds",
    }
    write_json(root / "results.json", results)
    write_json(root / "rpc-transcript.json", transcript)
    write_json(root / "source-provenance.json", provenance)
    (root / "report.md").write_text(report_markdown(results))
    (root / "report.html").write_text(report_html(results))
    names = ["results.json", "rpc-transcript.json", "source-provenance.json", "report.md", "report.html"]
    write_json(root / "manifest.json", {"schema": SCHEMA,
               "files": {name: sha256(root / name) for name in names}})
    print(json.dumps(verify(root), indent=2))
    return 0 if results["successful"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    execute = sub.add_parser("run")
    execute.add_argument("--baseline-dir", required=True)
    execute.add_argument("--candidate-dir", required=True)
    execute.add_argument("--output", required=True)
    execute.add_argument("--provenance")
    check = sub.add_parser("verify")
    check.add_argument("directory")
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            return run(args)
        print(json.dumps(verify(Path(args.directory)), indent=2))
        return 0
    except Exception as e:
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
