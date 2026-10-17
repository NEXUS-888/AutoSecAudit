"""History page: the per-row select label must be visually hidden and the checkbox themed."""
import os
import re
import unittest

TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui", "templates", "history.html")


def _read():
    with open(TEMPLATE, encoding="utf-8") as fh:
        return fh.read()


class HistoryPolishTests(unittest.TestCase):
    def test_visually_hidden_class_is_defined_where_used(self):
        html = _read()
        self.assertIn('class="visually-hidden"', html)
        self.assertRegex(html, r"\.visually-hidden\s*\{[^}]*clip:\s*rect\(0")

    def test_checkbox_follows_theme(self):
        html = _read()
        self.assertRegex(html, r"\.scan-checkbox\s*\{[^}]*color-scheme:\s*dark")
        self.assertRegex(html, r"\[data-theme=\"light\"\]\s+\.scan-checkbox\s*\{[^}]*color-scheme:\s*light")


if __name__ == "__main__":
    unittest.main()
