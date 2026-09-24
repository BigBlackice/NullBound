"""Tests for runtime-editable module definitions."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from recon_modules import ModuleCatalog, ScanProfile


class ModuleCatalogTests(unittest.TestCase):
    def test_create_edit_delete_and_reload(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "definitions.json"
            catalog = ModuleCatalog((), source_path=path)
            profile = ScanProfile.from_mapping({
                "name": "Default", "arguments": ["-u", "{target}"],
                "output_format": "jsonl",
            })
            module = catalog.create_module(
                eyebrow="discovery", description="Custom probe", bin="probe",
                path="probe", profiles=(profile,),
            )
            catalog.replace_module(module.id, description="Edited probe")
            catalog.save()

            loaded = ModuleCatalog.load(path)
            self.assertEqual(loaded.get(module.id).description, "Edited probe")
            self.assertEqual(loaded.get(module.id).profiles[0].arguments, ("-u", "{target}"))

            loaded.remove_module(module.id)
            self.assertEqual(len(loaded), 0)

    def test_mixed_target_placeholder_styles_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "mixes target placeholder styles"):
            ScanProfile.from_mapping({
                "name": "Broken", "arguments": ["-u", "{target}", "{targets}"],
            })

    def test_profile_names_are_unique_without_regard_to_case(self) -> None:
        catalog = ModuleCatalog(())
        profiles = (
            ScanProfile.from_mapping({"name": "Default", "arguments": ["{targets}"]}),
            ScanProfile.from_mapping({"name": "default", "arguments": ["{targets}"]}),
        )

        with self.assertRaisesRegex(ValueError, "scan profile names must be unique"):
            catalog.create_module(
                eyebrow="test", description="Duplicate profiles", bin="probe",
                path="probe", profiles=profiles,
            )


if __name__ == "__main__":
    unittest.main()
