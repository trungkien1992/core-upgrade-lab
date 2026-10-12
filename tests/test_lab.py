"""Meaningful controls for report integrity, money precision and check classification."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import core_upgrade_lab as lab
import bootstrap


class MoneyControls(unittest.TestCase):
    def test_exact_satoshi_and_whole_amounts(self):
        self.assertEqual(lab.sats("0.00000001"), 1)
        self.assertEqual(lab.sats("50"), 5_000_000_000)
        self.assertEqual(lab.sats("-0.00000123"), -123)

    def test_fractional_satoshis_are_not_rounded(self):
        with self.assertRaises(ValueError):
            lab.sats("0.000000001")

    def test_nonfinite_amounts_rejected(self):
        for value in ["NaN", "Infinity", "-Infinity"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                lab.sats(value)


class MeasurementControls(unittest.TestCase):
    def test_assertion_failure_and_runtime_error_are_distinguished(self):
        checks = lab.Checks("controls")
        def failure():
            lab.require(False, "injected expected disagreement")
        def error():
            raise RuntimeError("injected setup failure")
        with contextlib.redirect_stdout(io.StringIO()):
            checks.step("positive", lambda: {"ok": True})
            checks.step("disagreement", failure)
            checks.step("runtime", error)
        self.assertEqual([c["status"] for c in checks.items], ["pass", "fail", "error"])

    def test_identical_binary_selection_is_not_valid_evidence(self):
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / 'bitcoind'
            binary.write_text('#!' + sys.executable + '\nprint("Bitcoin Core daemon version v31.1.0 bitcoind")\n')
            binary.chmod(0o700)
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                code = lab.main(['run', '--baseline-dir', str(root),
                                 '--candidate-dir', str(root),
                                 '--output', str(root / 'evidence')])
            self.assertEqual(code, 2)
            self.assertIn('binaries are identical', errors.getvalue())
            self.assertFalse((root / 'evidence').exists())
            self.assertFalse((root / 'evidence-runtime').exists())


class InstallationControls(unittest.TestCase):
    def test_cached_executable_is_checked_and_never_overwritten(self):
        import tarfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / 'original'; original.write_bytes(b'verified fixture executable')
            archive = root / 'fixture.tar.gz'
            with tarfile.open(archive, 'w:gz') as output:
                output.add(original, arcname='bitcoin-fixture/bin/bitcoind')
            target = root / 'installed'
            binary = bootstrap.install_archive(archive, target, 'fixture')
            self.assertEqual(bootstrap.install_archive(archive, target, 'fixture'), binary)
            binary.write_bytes(b'local modification')
            with self.assertRaisesRegex(ValueError, 'does not match'):
                bootstrap.install_archive(archive, target, 'fixture')
            self.assertEqual(binary.read_bytes(), b'local modification')


class LifecycleControls(unittest.TestCase):
    def test_malformed_stop_response_does_not_skip_process_reaping(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'bitcoind').write_text('fixture')
            node = lab.Node(root, root / 'runtime', 'control')
            process = Mock(); process.poll.return_value = None
            node.process = process
            with patch.object(node, 'rpc', side_effect=ValueError('malformed control response')):
                node.stop()
            process.wait.assert_called_once_with(timeout=20)
            self.assertIsNone(node.process)

    def test_startup_exception_closes_all_registered_nodes(self):
        import argparse
        import types
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ['baseline', 'candidate']:
                (root / name).mkdir(); (root / name / 'bitcoind').write_text(name)
            versions = [types.SimpleNamespace(stdout='Bitcoin Core daemon version v31.1.0\n'),
                        types.SimpleNamespace(stdout='Bitcoin Core daemon version v32.0.0rc3\n')]
            args = argparse.Namespace(output=str(root / 'run'), baseline_dir=str(root / 'baseline'),
                                      candidate_dir=str(root / 'candidate'), provenance=None)
            stopped = []
            with patch.object(lab.subprocess, 'run', side_effect=versions), \
                 patch.object(lab.Node, 'start', side_effect=RuntimeError('startup control')), \
                 patch.object(lab.Node, 'stop', lambda node: stopped.append(node.label)), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(lab.run(args), 1)
            self.assertEqual(stopped, ['candidate', 'baseline'])
            result = json.loads((root / 'run' / 'results.json').read_text())
            self.assertEqual(result['counts']['error'], 1)


class PSBTControls(unittest.TestCase):
    def test_version_zero_when_global_version_omitted(self):
        self.assertEqual(lab.psbt_version(base64.b64encode(b"psbt\xff\x00").decode()), 0)

    def test_version_two_from_explicit_global_field(self):
        psbt = b"psbt\xff\x01\xfb\x04\x02\x00\x00\x00\x00"
        self.assertEqual(lab.psbt_version(base64.b64encode(psbt).decode()), 2)

    def test_truncation_and_bad_magic_do_not_become_version_zero(self):
        for data in [b"psbt\xff\x01", b"invalid", b"psbt\xff\x01\xfb\x04\x02"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                lab.psbt_version(base64.b64encode(data).decode())


class EvidenceControls(unittest.TestCase):
    def make_evidence(self, root):
        results = {"schema": lab.SCHEMA, "checks": [{"status": "pass"}],
                   "counts": {"pass": 1, "fail": 0, "error": 0}, "successful": True}
        lab.write_json(root / "results.json", results)
        for name in ["report.md", "report.html", "rpc-transcript.json", "source-provenance.json"]:
            (root / name).write_text("fixture")
        entries = {p.name: lab.sha256(p) for p in root.iterdir()}
        lab.write_json(root / "manifest.json", {"schema": lab.SCHEMA, "files": entries})

    def test_clean_package_passes_and_changed_report_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.make_evidence(root)
            self.assertTrue(lab.verify(root)["successful"])
            (root / "report.md").write_text("altered evidence")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                lab.verify(root)

    def test_missing_required_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.make_evidence(root)
            manifest = json.loads((root / "manifest.json").read_text())
            del manifest["files"]["rpc-transcript.json"]
            lab.write_json(root / "manifest.json", manifest)
            with self.assertRaisesRegex(ValueError, "Incomplete"):
                lab.verify(root)

    def test_recomputed_manifest_does_not_hide_inconsistent_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.make_evidence(root)
            result = json.loads((root / "results.json").read_text())
            result["counts"]["pass"] = 2
            lab.write_json(root / "results.json", result)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["files"]["results.json"] = lab.sha256(root / "results.json")
            lab.write_json(root / "manifest.json", manifest)
            with self.assertRaisesRegex(ValueError, "counts disagree"):
                lab.verify(root)

    def test_manifest_cannot_traverse_outside_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                lab.safe_manifest_paths(Path(tmp), {"../private": "0" * 64})

    def test_symlinked_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "target").write_text("evidence")
            (root / "link").symlink_to(root / "target")
            with self.assertRaisesRegex(ValueError, "symlinked"):
                lab.safe_manifest_paths(root, {"link": lab.sha256(root / "target")})

    def test_parent_symlink_cannot_escape_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'evidence'; root.mkdir()
            outside = base / 'outside'; outside.mkdir()
            (outside / 'data').write_text('outside the package')
            (root / 'nested').symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'escapes'):
                lab.safe_manifest_paths(root, {'nested/data': lab.sha256(outside / 'data')})


if __name__ == "__main__":
    unittest.main()
