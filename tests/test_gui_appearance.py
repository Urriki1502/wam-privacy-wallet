"""Day/night schedule and mode override, without Core or network."""
import unittest
from datetime import datetime, timedelta, timezone

from wam_privacy_wallet.gui.appearance import (
    appearance_colors, appearance_stylesheet, resolved_appearance,
)


class DayNightAppearanceTests(unittest.TestCase):
    def setUp(self):
        self.zone = timezone(timedelta(hours=7))

    def test_local_time_boundary(self):
        for hour, minute, expected in (
            (0, 0, "dark"), (5, 59, "dark"), (6, 0, "light"),
            (12, 0, "light"), (17, 59, "light"), (18, 0, "dark"),
            (23, 59, "dark"),
        ):
            with self.subTest(hour=hour, minute=minute):
                date = datetime(2026, 10, 14, hour, minute, tzinfo=self.zone)
                self.assertEqual(resolved_appearance("auto", date), expected)

    def test_timezone_shift_recomputes_auto_theme(self):
        utc = datetime(2026, 10, 13, 23, 30, tzinfo=timezone.utc)
        self.assertEqual(resolved_appearance("auto", utc), "dark")
        self.assertEqual(resolved_appearance("auto", utc.astimezone(self.zone)), "light")

    def test_manual_mode_and_denials(self):
        local = datetime(2026, 10, 14, 2, tzinfo=self.zone)
        self.assertEqual(resolved_appearance("light", local), "light")
        self.assertEqual(resolved_appearance("dark", local), "dark")
        for bad in (None, "", True, "system", "sunrise"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                resolved_appearance(bad, local)
        with self.assertRaises(ValueError):
            resolved_appearance("auto", datetime(2026, 10, 14, 12))

    def test_palette_and_styles_are_bounded(self):
        light = appearance_colors("light")
        dark = appearance_colors("dark")
        self.assertNotEqual(light["background"], dark["background"])
        self.assertNotEqual(light["text"], dark["text"])
        self.assertIn("QMainWindow", appearance_stylesheet("dark"))
        with self.assertRaises(ValueError):
            appearance_stylesheet("unknown")


if __name__ == "__main__":
    unittest.main()
