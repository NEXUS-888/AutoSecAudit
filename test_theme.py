"""Test dark/light mode toggle feature."""
import sys
sys.path.insert(0, ".")

print("=" * 50)
print("TESTING: Feature 8 - Dark/Light Mode Toggle")
print("=" * 50)

from ui.app import app

# Test 1: Home page has theme toggle
with app.test_client() as client:
    resp = client.get("/")
    html = resp.data.decode("utf-8")
    assert "themeToggle" in html, "Should have theme toggle button"
    assert "toggleTheme" in html, "Should have toggleTheme function"
    assert "themeIcon" in html, "Should have theme icon SVG"
    print("[PASS] Home page has theme toggle button and JS")

# Test 2: Light theme CSS variables exist
    assert 'data-theme="light"' in html, "Should have [data-theme=light] CSS"
    assert ("#f8fafc" in html or "#f5f5f7" in html), "Light theme should have light background"
    assert ("#0f172a" in html or "#1a1a2e" in html), "Light theme should have dark text color"
    print("[PASS] Light theme CSS variables defined")

# Test 3: Theme persists via localStorage
    assert "localStorage" in html, "Should use localStorage for persistence"
    assert "autosec-theme" in html, "Should use 'autosec-theme' key"
    print("[PASS] Theme persists via localStorage")

# Test 4: History page also has theme toggle
    resp = client.get("/history")
    html = resp.data.decode("utf-8")
    assert "themeToggle" in html or "toggleTheme" in html, "History page should have theme toggle"
    assert 'data-theme="light"' in html, "History should have light theme CSS"
    print("[PASS] History page also supports theme toggle")

# Test 5: Icon switches between sun and moon
with app.test_client() as client:
    resp = client.get("/")
    html = resp.data.decode("utf-8")
    assert "M21 12.79A9 9 0 1 1 11.21 3" in html, "Should have moon icon SVG path"
    assert 'r="5"' in html, "Should have sun icon circle"
    print("[PASS] Sun (dark mode) and moon (light mode) icons are present")

print()
print("=" * 50)
print("ALL TESTS PASSED")
print("=" * 50)
