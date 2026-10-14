"""Persistent operator setting regressions."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from operator_settings import OperatorSettings, OperatorSettingsStore


class OperatorSettingsTests(unittest.TestCase):
    def test_proxy_and_separate_wordlist_directories_persist(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            store = OperatorSettingsStore(path)
            store.update(
                proxy_enabled=True, proxy_protocol="socks5", proxy_port=1080,
                web_wordlist_directory="lists/web",
                password_wordlist_directory="lists/passwords",
            )
            loaded = OperatorSettingsStore(path).settings

        self.assertTrue(loaded.proxy_enabled)
        self.assertEqual(loaded.proxy_protocol, "socks5")
        self.assertEqual(loaded.web_wordlist_directory, "lists/web")
        self.assertEqual(loaded.password_wordlist_directory, "lists/passwords")

    def test_wordlist_directories_cannot_escape_a_project(self) -> None:
        with self.assertRaisesRegex(ValueError, "project-relative"):
            OperatorSettings(web_wordlist_directory="../outside")


if __name__ == "__main__":
    unittest.main()
