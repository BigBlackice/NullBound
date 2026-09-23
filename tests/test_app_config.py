"""Tests for validated Blackwall startup configuration."""

from __future__ import annotations

import unittest

from app_config import AppConfig, DEFAULT_HOST, DEFAULT_PORT


class AppConfigTests(unittest.TestCase):
    def test_defaults_are_loopback_only(self) -> None:
        config = AppConfig.from_args([])

        self.assertEqual(config.host, DEFAULT_HOST)
        self.assertEqual(config.port, DEFAULT_PORT)
        self.assertTrue(config.is_loopback)
        self.assertIsNone(config.remote_access_warning)

    def test_explicit_lan_binding_is_allowed_with_warning(self) -> None:
        config = AppConfig.from_args(["--host", "0.0.0.0", "--port", "9090"])

        self.assertEqual(config.host, "0.0.0.0")
        self.assertEqual(config.port, 9090)
        self.assertFalse(config.is_loopback)
        self.assertIn("host filesystem browser", config.remote_access_warning or "")

    def test_ipv6_and_localhost_are_recognized_as_loopback(self) -> None:
        self.assertTrue(AppConfig(host="::1").is_loopback)
        self.assertTrue(AppConfig(host="localhost").is_loopback)

    def test_invalid_direct_values_are_rejected(self) -> None:
        for config in (
            {"host": ""},
            {"host": "https://localhost"},
            {"port": 0},
            {"port": 65536},
        ):
            with self.subTest(config=config):
                with self.assertRaises(ValueError):
                    AppConfig(**config)


if __name__ == "__main__":
    unittest.main()
