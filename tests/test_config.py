"""Tests for the configuration loader."""
import os
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import load_config, resolve_modules_for_mode, ScanConfig


class TestConfigLoader(unittest.TestCase):
    def test_defaults_when_no_file(self):
        cfg = load_config("/nonexistent/path.yaml")
        self.assertIsInstance(cfg, ScanConfig)
        self.assertEqual(cfg.mode, "standard")
        self.assertTrue(cfg.authorized_only)
        self.assertFalse(cfg.destructive_tests)

    def test_load_yaml(self):
        yaml_content = """
target:
  url: "https://example.com"
  allowed_hosts: ["example.com"]
scan:
  mode: deep
  threads: 10
  timeout: 5
  rate_limit: 3
safety:
  destructive_tests: false
  brute_force: false
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            path = f.name
        try:
            cfg = load_config(path)
            self.assertEqual(cfg.target_url, "https://example.com")
            self.assertEqual(cfg.mode, "deep")
            self.assertEqual(cfg.threads, 10)
            self.assertEqual(cfg.timeout, 5)
            self.assertFalse(cfg.destructive_tests)
        finally:
            os.unlink(path)

    def test_destructive_options_off_by_default(self):
        cfg = ScanConfig()
        self.assertFalse(cfg.destructive_tests)
        self.assertFalse(cfg.brute_force)
        self.assertFalse(cfg.data_modification)

    def test_resolve_modules_quick(self):
        cfg = ScanConfig(mode="quick")
        modules = resolve_modules_for_mode(cfg)
        self.assertTrue(modules["discovery"])
        self.assertTrue(modules["headers"])
        self.assertFalse(modules["xss"])
        self.assertFalse(modules["infrastructure"])

    def test_resolve_modules_full(self):
        cfg = ScanConfig(mode="full")
        modules = resolve_modules_for_mode(cfg)
        self.assertTrue(modules["discovery"])
        self.assertTrue(modules["infrastructure"])
        self.assertTrue(modules["xss"])

    def test_resolve_modules_config_can_disable(self):
        cfg = ScanConfig(mode="standard")
        cfg.modules = {"xss": False}
        modules = resolve_modules_for_mode(cfg)
        self.assertFalse(modules["xss"])

    def test_resolve_modules_config_cannot_enable_destructive(self):
        cfg = ScanConfig(mode="quick")
        cfg.modules = {"command_injection": True}  # quick disables this
        modules = resolve_modules_for_mode(cfg)
        # command_injection should stay off in quick mode
        self.assertFalse(modules.get("command_injection", False))


if __name__ == "__main__":
    unittest.main()
