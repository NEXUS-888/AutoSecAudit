#!/usr/bin/env python3
"""Automated UI/UX audit of the AutoSecAudit dashboard, run in headless Chrome.

    python audit/ux_check.py                 # full run: 3 viewports x 2 themes, saves screenshots
    python audit/ux_check.py --quick         # 2 viewports x dark theme (use while iterating)
    python audit/ux_check.py --fail-on-issues --no-screenshots   # what the loop's mechanical check runs

It starts a throwaway dashboard (own data directory, demo mode, registration on), walks the real user
flows, snapshots every page and applies objective rules (names, labels, landmarks, tap targets, overflow,
contrast, ...) plus a few behaviour checks (readable errors, empty states, demo banner). Every issue has a
stable id so it can be accepted with a written reason in audit/baselines/ux_accepted.json.

Exit codes: 0 clean, 1 issues found, 3 the tool itself could not run (no Chrome, server did not start).
"""

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
ACCEPTED_FILE = ROOT / "audit" / "baselines" / "ux_accepted.json"
SHOTS_DIR = ROOT / "data" / "ux_shots"

VIEWPORTS = {"desktop": (1366, 768), "tablet": (768, 1024), "mobile": (375, 812)}
MIN_TARGET_PX = 24            # WCAG 2.2 AA (2.5.8)
MIN_CONTRAST = 4.5            # WCAG AA normal text
MIN_CONTRAST_LARGE = 3.0      # large text: >= 24px, or >= 18.66px bold
RAW_ERROR_RE = re.compile(r"Errno|Traceback|getaddrinfo|Exception|\{\s*\"error\"|<!doctype", re.I)

# ---------------------------------------------------------------------------
# Browser-side collector. Returns plain data; all judgement happens in Python.
# ---------------------------------------------------------------------------
COLLECT_JS = r"""
() => {
  const cv = document.createElement('canvas'); cv.width = cv.height = 1;
  const cx = cv.getContext('2d', {willReadFrequently: true});
  const rgba = (c) => { cx.clearRect(0,0,1,1); cx.fillStyle = '#000'; cx.fillStyle = c; cx.fillRect(0,0,1,1);
                        const d = cx.getImageData(0,0,1,1).data; return [d[0], d[1], d[2], d[3] / 255]; };
  const esc = (s) => (window.CSS && CSS.escape) ? CSS.escape(s) : s;
  const sel = (el) => {
    if (el.id && document.querySelectorAll('#' + esc(el.id)).length === 1) return '#' + el.id;
    const parts = [];
    for (let n = el, d = 0; n && n.nodeType === 1 && n !== document.body && d < 4; n = n.parentElement, d++) {
      let p = n.tagName.toLowerCase();
      if (n.id) { parts.unshift(p + '#' + n.id); break; }
      const cls = (n.getAttribute('class') || '').split(/\s+/).filter(Boolean).slice(0, 2);
      if (cls.length) p += '.' + cls.join('.');
      const sib = n.parentElement ? Array.from(n.parentElement.children).filter(c => c.tagName === n.tagName) : [];
      if (sib.length > 1) p += ':nth-of-type(' + (sib.indexOf(n) + 1) + ')';
      parts.unshift(p);
    }
    return parts.join(' > ');
  };
  const visible = (el) => {
    const r = el.getBoundingClientRect(), s = getComputedStyle(el);
    if (s.display === 'none' || s.visibility === 'hidden' || +s.opacity === 0) return false;
    if (r.width === 0 || r.height === 0) return false;
    for (let n = el.parentElement; n; n = n.parentElement) {
      const ps = getComputedStyle(n);
      if (ps.display === 'none' || ps.visibility === 'hidden' || +ps.opacity === 0) return false;
    }
    return true;
  };
  const textOf = (id) => { const e = document.getElementById(id); return e ? e.textContent.trim() : ''; };
  const nameOf = (el) => {
    const t = el.tagName.toLowerCase();
    let n = (el.getAttribute('aria-label') || '').trim();
    if (n) return n;
    const lb = el.getAttribute('aria-labelledby');
    if (lb) { n = lb.split(/\s+/).map(textOf).join(' ').trim(); if (n) return n; }
    if (el.labels && el.labels.length) { n = Array.from(el.labels).map(l => l.textContent.trim()).join(' ').trim(); if (n) return n; }
    if (t === 'input' && ['submit', 'button', 'reset'].includes(el.type)) { n = (el.value || '').trim(); if (n) return n; }
    if (t === 'img') return (el.getAttribute('alt') || '').trim();
    n = (el.innerText || el.textContent || '').trim();
    if (n) return n;
    const img = el.querySelector('img[alt]'); if (img && img.alt.trim()) return img.alt.trim();
    const svgt = el.querySelector('svg title'); if (svgt && svgt.textContent.trim()) return svgt.textContent.trim();
    return (el.getAttribute('title') || '').trim();
  };
  const out = {controls: [], images: [], dup_ids: [], text: []};
  out.lang = (document.documentElement.getAttribute('lang') || '').trim();
  out.title = (document.title || '').trim();
  out.viewport_meta = !!document.querySelector('meta[name="viewport"]');
  out.h1 = Array.from(document.querySelectorAll('h1')).filter(visible).length;
  out.main = document.querySelectorAll('main, [role="main"]').length;
  out.scroll_width = document.documentElement.scrollWidth;
  out.client_width = document.documentElement.clientWidth;

  const ctl = 'a[href], button, input:not([type="hidden"]), select, textarea, [role="button"], [role="link"], [tabindex]:not([tabindex="-1"])';
  const seen = new Set();
  document.querySelectorAll(ctl).forEach(el => {
    if (seen.has(el) || el.disabled) return; seen.add(el);
    const r = el.getBoundingClientRect(), s = getComputedStyle(el);
    if (el.tagName === 'INPUT' && ['radio', 'checkbox'].includes(el.type) && !visible(el)) {
      // custom-styled radios/checkboxes: judge the label that wraps/targets them instead
      if (el.labels && el.labels.length && visible(el.labels[0])) {
        const lr = el.labels[0].getBoundingClientRect();
        out.controls.push({selector: sel(el), tag: 'input', type: el.type, visible: true, w: lr.width, h: lr.height,
                           inline: false, name: nameOf(el)});
      }
      return;
    }
    const inline = s.display === 'inline' && el.tagName === 'A';
    out.controls.push({selector: sel(el), tag: el.tagName.toLowerCase(), type: el.type || '', visible: visible(el),
                       w: r.width, h: r.height, inline: inline, name: nameOf(el)});
  });
  document.querySelectorAll('img').forEach(el => {
    out.images.push({selector: sel(el), alt: el.hasAttribute('alt') ? el.getAttribute('alt') : null, visible: visible(el),
                     decorative: el.getAttribute('role') === 'presentation' || el.getAttribute('aria-hidden') === 'true'});
  });
  const ids = {};
  document.querySelectorAll('[id]').forEach(e => { ids[e.id] = (ids[e.id] || 0) + 1; });
  out.dup_ids = Object.keys(ids).filter(k => ids[k] > 1);

  // contrast: only where the background resolves to solid colours (gradients/images are never guessed)
  const bgOf = (el) => {
    const layers = [];
    for (let n = el; n; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (s.backgroundImage && s.backgroundImage !== 'none') return null;
      const c = rgba(s.backgroundColor);
      if (c[3] > 0) { layers.push(c); if (c[3] >= 1) break; }
    }
    let base = [255, 255, 255];
    if (!layers.length || layers[layers.length - 1][3] < 1) {
      const cs = getComputedStyle(document.documentElement).colorScheme || '';
      if (cs.indexOf('dark') >= 0 && cs.indexOf('light') < 0) base = [0, 0, 0];
    } else { base = layers.pop().slice(0, 3); }
    for (let i = layers.length - 1; i >= 0; i--) {
      const [r, g, b, a] = layers[i];
      base = [r * a + base[0] * (1 - a), g * a + base[1] * (1 - a), b * a + base[2] * (1 - a)];
    }
    return base.map(Math.round);
  };
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const done = new Set(); let count = 0;
  while (walker.nextNode() && count < 500) {
    const tn = walker.currentNode; const txt = tn.nodeValue.trim();
    if (!txt) continue;
    const el = tn.parentElement;
    if (!el || done.has(el) || ['SCRIPT', 'STYLE', 'NOSCRIPT', 'CANVAS', 'SVG'].includes(el.tagName.toUpperCase())) continue;
    if (!visible(el) || el.closest('[disabled], [aria-hidden="true"]')) continue;
    done.add(el);
    const s = getComputedStyle(el);
    const fg = rgba(s.color);
    let op = 1; for (let n = el; n; n = n.parentElement) op *= +getComputedStyle(n).opacity;
    const bg = bgOf(el);
    count++;
    out.text.push({selector: sel(el), fg: fg.slice(0, 3).map(Math.round), fg_alpha: fg[3], bg: bg, size: parseFloat(s.fontSize),
                   weight: parseInt(s.fontWeight, 10) || 400, sample: txt.slice(0, 40), opacity: op});
  }
  return out;
}
"""


# ---------------------------------------------------------------------------
# Pure analysis (unit-tested without a browser)
# ---------------------------------------------------------------------------
def _lum(c: Sequence[float]) -> float:
    def ch(v: float) -> float:
        v = v / 255.0
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(x) for x in c[:3])
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg: Sequence[float], bg: Sequence[float]) -> float:
    a, b = _lum(fg), _lum(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def issue_id(rule: str, page: str, selector: str) -> str:
    stable = re.sub(r":nth-of-type\(\d+\)", "", selector)  # list position varies with scan result order
    return "UX-" + hashlib.sha1(f"{rule}|{page}|{stable}".encode()).hexdigest()[:8]


def _issue(rule: str, page: str, viewport: str, theme: str, selector: str, detail: str) -> Dict[str, Any]:
    return {"id": issue_id(rule, page, selector), "rule": rule, "page": page, "selector": selector,
            "detail": detail, "context": f"{viewport}/{theme}"}


def analyse_snapshot(s: Dict[str, Any], page: str, viewport: str, theme: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    def add(rule: str, selector: str, detail: str) -> None:
        out.append(_issue(rule, page, viewport, theme, selector, detail))

    if not (s.get("lang") or "").strip():
        add("doc-lang", "html", "<html> has no lang attribute")
    if not (s.get("title") or "").strip():
        add("doc-title", "title", "page has no <title>")
    if not s.get("viewport_meta"):
        add("doc-viewport", "head", "missing <meta name=viewport>; mobile browsers will zoom out")
    if s.get("main", 0) != 1:
        add("landmark-main", "body", f"expected exactly one <main> landmark, found {s.get('main', 0)}")
    if s.get("h1", 0) != 1:
        add("page-h1", "body", f"expected exactly one visible <h1>, found {s.get('h1', 0)}")
    if s.get("scroll_width", 0) > s.get("client_width", 0) + 1:
        add("layout-overflow", "html",
            f"page scrolls sideways: content {s['scroll_width']}px wide in a {s['client_width']}px viewport")
    for c in s.get("controls", []):
        if not c.get("visible"):
            continue
        label = f"<{c.get('tag')}{(' type=' + c['type']) if c.get('type') else ''}>"
        if not (c.get("name") or "").strip():
            add("control-name", c["selector"], f"{label} has no accessible name")
        if not c.get("inline") and min(c.get("w", 0), c.get("h", 0)) < MIN_TARGET_PX:
            add("target-size", c["selector"],
                f"{label} is {c.get('w', 0):.0f}x{c.get('h', 0):.0f}px; minimum is {MIN_TARGET_PX}x{MIN_TARGET_PX}px")
    for im in s.get("images", []):
        if im.get("visible") and im.get("alt") is None and not im.get("decorative"):
            add("image-alt", im["selector"], "image has no alt attribute (use alt=\"\" if decorative)")
    for d in s.get("dup_ids", []):
        add("dup-id", f"#{d}", f"id \"{d}\" is used more than once")
    for t in s.get("text", []):
        bg, fg = t.get("bg"), list(t.get("fg") or [])
        if bg is None or len(fg) < 3:
            continue
        a = t.get("fg_alpha", 1) * t.get("opacity", 1)
        if a < 1:
            fg = [fg[i] * a + bg[i] * (1 - a) for i in range(3)]
        ratio = contrast_ratio(fg, bg)
        size, weight = t.get("size", 16), t.get("weight", 400)
        need = MIN_CONTRAST_LARGE if (size >= 24 or (size >= 18.66 and weight >= 700)) else MIN_CONTRAST
        if ratio < need:
            add("text-contrast", t["selector"], f"contrast {ratio:.2f}:1 (needs {need}:1) for \"{t.get('sample', '')}\"")
    return out


def merge_issues(issues: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for i in issues:
        cur = merged.get(i["id"])
        if cur is None:
            cur = dict(i)
            cur["contexts"] = []
            cur.pop("context", None)
            merged[i["id"]] = cur
        ctx = i.get("context")
        if ctx and ctx not in cur["contexts"]:
            cur["contexts"].append(ctx)
    return sorted(merged.values(), key=lambda x: (x["page"], x["rule"], x["selector"]))


def load_accepted(path: Path = ACCEPTED_FILE) -> Dict[str, str]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {e["id"]: e.get("reason", "") for e in data.get("accepted", [])}


def filter_accepted(issues: List[Dict[str, Any]], accepted: Dict[str, str]) -> List[Dict[str, Any]]:
    for ident, reason in accepted.items():
        if not (reason or "").strip():
            raise ValueError(f"accepted UX issue {ident} has no reason")
    return [i for i in issues if i["id"] not in accepted]


# ---------------------------------------------------------------------------
# Browser + app harness
# ---------------------------------------------------------------------------
FINISH_ANIMATIONS_JS = """() => document.getAnimations().forEach(a => { try { a.finish(); } catch (e) { a.cancel(); } })"""


def settle(page, max_seconds: float = 5.0) -> None:
    """Let entrance animations and count-up numbers finish so snapshots are stable from run to run."""
    deadline = time.time() + max_seconds
    page.evaluate(FINISH_ANIMATIONS_JS)
    previous = None
    while time.time() < deadline:
        current = page.evaluate("() => document.body.innerText")
        if current == previous:
            break
        previous = current
        page.wait_for_timeout(300)
    page.evaluate(FINISH_ANIMATIONS_JS)


def collect_snapshot(page) -> Dict[str, Any]:
    return page.evaluate(COLLECT_JS)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class DashboardServer:
    """A throwaway dashboard in demo mode with its own data directory."""

    PASSWORD = "UxCheck#2026-Admin"

    def __init__(self) -> None:
        self.port = _free_port()
        self.tmp = tempfile.TemporaryDirectory(prefix="ux_check_")
        self.proc: Optional[subprocess.Popen] = None
        self.base = f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "DashboardServer":
        env = dict(os.environ, AUTOSEC_DATA_DIR=self.tmp.name, AUTOSEC_ADMIN_PASSWORD=self.PASSWORD,
                   AUTOSEC_ALLOW_REGISTRATION="true", AUTOSEC_MOCK_MODE="true", PYTHONIOENCODING="utf-8")
        code = (f"import sys; sys.path.insert(0, {str(ROOT)!r}); from ui.app import app; "
                f"app.run(host='127.0.0.1', port={self.port}, debug=False, threaded=True)")
        self.proc = subprocess.Popen([sys.executable, "-c", code], cwd=ROOT, env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 45
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("dashboard process exited during start-up")
            try:
                urllib.request.urlopen(self.base + "/login", timeout=5).read()
                return self
            except Exception:
                time.sleep(0.4)
        raise RuntimeError("dashboard did not start within 45 s")

    def __exit__(self, *exc) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        try:
            self.tmp.cleanup()
        except Exception:
            pass


TRANSIENT_RE = re.compile(r"net::ERR_|ECONNRESET|ECONNREFUSED|ETIMEDOUT|Target page, context or browser has been closed")


def retry_transient(fn, tries: int = 3, pause: float = 1.0):
    """Run fn(); retry only browser/network hiccups (Chrome <-> the Flask dev server on Windows drops the odd
    connection). Real failures, such as a missing selector, are raised at once."""
    for attempt in range(1, tries + 1):
        try:
            return fn()
        except Exception as exc:
            if attempt >= tries or not TRANSIENT_RE.search(str(exc)):
                raise
            time.sleep(pause)


def is_real_console_error(message: str) -> bool:
    """Console errors worth reporting; a dropped local connection is test-infrastructure noise, a 404 or a script error is not."""
    return not TRANSIENT_RE.search(message)


def _goto(page, url: str, **kw):
    return retry_transient(lambda: page.goto(url, **kw))


def _login(page, base: str) -> None:
    retry_transient(lambda: _login_once(page, base))


def _login_once(page, base: str) -> None:
    page.goto(base + "/login")
    page.fill("input[name=identifier]", "admin")
    page.fill("input[name=password]", DashboardServer.PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(re.compile(r".*/(scanner|dashboard).*"), timeout=15000)


def _make_demo_report(page, base: str) -> str:
    token = page.evaluate("() => (document.querySelector('input[name=csrf_token]')||{}).value || ''")
    if not token:
        token = page.evaluate("() => (document.querySelector('meta[name=csrf-token]')||{}).content || ''")
    resp = page.request.post(base + "/scan/async", form={"target": "http://127.0.0.1:8099", "mode": "demo",
                                                         "profile": "recon"}, headers={"X-CSRFToken": token})
    if not resp.ok:
        raise RuntimeError(f"could not start the demo scan: HTTP {resp.status} {resp.text()[:120]}")
    sid = resp.json()["scan_id"]
    for _ in range(120):
        st = page.request.get(f"{base}/scan/status/{sid}").json()
        if st.get("status") == "done" and st.get("report_name"):
            return st["report_name"]
        if st.get("status") in ("error", "cancelled"):
            raise RuntimeError(f"demo scan failed: {st}")
        time.sleep(1)
    raise RuntimeError("demo scan did not finish within 120 s")


def _shot(page, name: str, shots: Optional[Path]) -> None:
    if shots is not None:
        shots.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(shots / f"{name}.png"), full_page=True)


def _flow_issue(rule: str, page_name: str, selector: str, detail: str) -> Dict[str, Any]:
    return {"id": issue_id(rule, page_name, selector), "rule": rule, "page": page_name, "selector": selector,
            "detail": detail, "context": "flow"}


def run_flows(browser, base: str, shots: Optional[Path], features: bool = False) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Behavioural checks. Returns (issues, demo_report_id)."""
    issues: List[Dict[str, Any]] = []
    ctx = browser.new_context(viewport={"width": 1366, "height": 768})
    page = ctx.new_page()
    dialogs: List[str] = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

    # wrong password -> visible, readable message
    _goto(page, base + "/login")
    page.fill("input[name=identifier]", "admin")
    page.fill("input[name=password]", "definitely-wrong")
    page.click("button[type=submit]")
    page.wait_for_load_state("load")
    msg = page.locator(".alert-error, [role=alert]")
    if msg.count() == 0 or not msg.first.is_visible():
        issues.append(_flow_issue("flow-login-error", "login", "form", "a failed sign-in shows no visible error message"))
    elif RAW_ERROR_RE.search(msg.first.inner_text()):
        issues.append(_flow_issue("flow-login-error", "login", ".alert-error", "error message exposes technical details"))

    _login(page, base)

    # history before any scan -> empty state, not a blank table
    _goto(page, base + "/history")
    body = page.inner_text("body")
    if not re.search(r"no (scans|reports)|nothing (here )?yet|no scan history|run (a|your) (first )?scan|get started", body, re.I):
        issues.append(_flow_issue("flow-empty-history", "history", "body",
                                  "history with no scans shows no empty-state message telling the user what to do"))

    # scanner: bad input must produce an in-page, readable message (never alert(), never raw exceptions)
    _goto(page, base + "/scanner")
    for label, target, rule in (("not a url", "not a url", "flow-bad-target"),
                                ("unreachable", "http://127.0.0.1:1", "flow-unreachable-target")):
        _goto(page, base + "/scanner")
        page.check("#radioReal")
        page.fill("#target", target)
        page.click(".btn-launch-scan")
        text = ""
        for _ in range(40):
            page.wait_for_timeout(250)
            text = page.evaluate("() => { const e = document.getElementById('scanConsoleText'); "
                                 "const v = e && e.offsetParent !== null ? e.innerText : ''; return v; }")
            if text and not text.startswith("Initializing"):
                break
        if dialogs:
            issues.append(_flow_issue(rule, "scanner", "#scanForm", f"uses a browser alert() to report the error: {dialogs[0][:80]}"))
            dialogs.clear()
        elif not text or text.startswith("Initializing"):
            issues.append(_flow_issue(rule, "scanner", "#scanConsoleText", f"no visible error after submitting '{label}'"))
        elif RAW_ERROR_RE.search(text):
            issues.append(_flow_issue(rule, "scanner", "#scanConsoleText", f"error shows technical details: {text[:100]!r}"))
        _shot(page, f"flow-{rule}", shots)

    # demo scan -> report must say it is simulated
    _goto(page, base + "/scanner")
    rid = None
    try:
        rid = _make_demo_report(page, base)
        _goto(page, f"{base}/report/{rid}")
        if page.locator("[data-testid=demo-banner]").count() == 0:
            issues.append(_flow_issue("flow-demo-banner", "report", "body", "a demo-mode report does not say it is simulated"))
        if features:
            _feature_flows(page, base, rid, issues)
    except Exception as exc:
        issues.append(_flow_issue("flow-demo-scan", "scanner", "body", f"could not complete a demo scan: {exc}"))
    ctx.close()
    return issues, rid


def _feature_flows(page, base: str, rid: str, issues: List[Dict[str, Any]]) -> None:
    """Controls introduced by batch B31 (finding triage, scan comparison, scan cancel); enabled with --features."""
    if page.locator("[data-testid=finding-triage]").count() == 0:
        issues.append(_flow_issue("flow-triage", "report", "[data-testid=finding-triage]",
                                  "findings cannot be marked as false positive / accepted risk (no finding-triage control)"))
    _goto(page, base + "/scanner")
    rid2 = _make_demo_report(page, base)
    _goto(page, base + "/history")
    if page.locator("[data-testid=compare-scans]").count() == 0:
        issues.append(_flow_issue("flow-compare", "history", "[data-testid=compare-scans]",
                                  "history offers no way to compare two scans (no compare-scans control)"))
    resp = page.request.get(f"{base}/compare/{rid}/{rid2}")
    body_text = resp.text() if resp.ok else ""
    if not resp.ok or not all(w in body_text for w in ("New", "Fixed", "Unchanged")):
        issues.append(_flow_issue("flow-compare", "compare", f"/compare/{rid}/{rid2}",
                                  f"/compare/<older>/<newer> must return 200 listing New, Fixed and Unchanged findings (got HTTP {resp.status})"))
    # a running scan can be cancelled from the progress screen
    _goto(page, base + "/scanner")
    page.check("#radioDemo")
    page.fill("#target", "http://127.0.0.1:8099")
    page.click(".btn-launch-scan")
    found = False
    for _ in range(40):
        cancel = page.locator("[data-testid=cancel-scan]")
        if cancel.count() and cancel.first.is_visible():
            found = True
            break
        page.wait_for_timeout(100)
    if not found:
        issues.append(_flow_issue("flow-cancel", "scanner", "[data-testid=cancel-scan]",
                                  "no visible Cancel control appears while a scan is running"))


def run(quick: bool, shots: Optional[Path], themes: Optional[List[str]] = None, features: bool = False) -> List[Dict[str, Any]]:
    from playwright.sync_api import sync_playwright

    viewports = ["desktop", "mobile"] if quick else list(VIEWPORTS)
    themes = themes or (["dark"] if quick else ["dark", "light"])
    raw: List[Dict[str, Any]] = []
    with DashboardServer() as srv, sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=True)
        try:
            flow_issues, rid = run_flows(browser, srv.base, shots, features)
            raw.extend(flow_issues)
            pages = [("landing", "/", False), ("login", "/login", False), ("register", "/register", False),
                     ("scanner", "/scanner", True), ("history", "/history", True)]
            if rid:
                pages.append(("report", f"/report/{rid}", True))
            for theme in themes:
                for vp in viewports:
                    w, h = VIEWPORTS[vp]
                    ctx = browser.new_context(viewport={"width": w, "height": h})
                    ctx.add_init_script(f"try{{localStorage.setItem('autosec-theme','{theme}')}}catch(e){{}}")
                    pg = ctx.new_page()
                    console_errors: List[str] = []
                    pg.on("pageerror", lambda e: console_errors.append(str(e)))
                    pg.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
                    pg.on("response", lambda r: console_errors.append(f"HTTP {r.status} {r.url}") if r.status >= 400 and r.request.resource_type != "document" else None)
                    logged_in = False
                    for name, path, needs_login in pages:
                        if needs_login and not logged_in:
                            _login(pg, srv.base)
                            logged_in = True
                        console_errors.clear()
                        _goto(pg, srv.base + path, wait_until="load")
                        settle(pg)
                        raw.extend(analyse_snapshot(collect_snapshot(pg), name, vp, theme))
                        for err in [e for e in console_errors if is_real_console_error(e)][:3]:
                            raw.append(_issue("console-error", name, vp, theme, "console", err[:160]))
                        _shot(pg, f"{name}-{vp}-{theme}", shots)
                    ctx.close()
        finally:
            browser.close()
    return merge_issues(raw)


def render(issues: List[Dict[str, Any]], accepted_count: int) -> str:
    if not issues:
        return f"UX check: 0 issues ({accepted_count} accepted with reasons)."
    lines = [f"UX check: {len(issues)} issue(s) ({accepted_count} accepted with reasons)", ""]
    for i in issues:
        ctxs = ", ".join(i.get("contexts") or ["flow"])
        lines.append(f"[{i['id']}] {i['rule']} on {i['page']} :: {i['selector']}\n    {i['detail']}\n    seen at: {ctxs}")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Automated UI/UX audit of the dashboard (headless Chrome).")
    ap.add_argument("--quick", action="store_true", help="2 viewports x dark theme only (for iterating)")
    ap.add_argument("--fail-on-issues", action="store_true", help="exit 1 when any unaccepted issue remains")
    ap.add_argument("--features", action="store_true", help="also require the B31 controls (finding triage, compare, cancel)")
    ap.add_argument("--no-screenshots", action="store_true", help="do not write screenshots")
    ap.add_argument("--shots-dir", default=str(SHOTS_DIR), help="where screenshots go (default data/ux_shots)")
    ap.add_argument("--json", metavar="FILE", help="also write the issues as JSON")
    args = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    try:
        accepted = load_accepted()
        raw = run(args.quick, None if args.no_screenshots else Path(args.shots_dir), features=args.features)
        issues = filter_accepted(raw, accepted)
    except ValueError as exc:
        print(f"ux_check: bad baseline: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # no Chrome, server failed, playwright missing, ...
        print(f"ux_check: could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    print(render(issues, len(raw) - len(issues)))
    if args.json:
        Path(args.json).write_text(json.dumps(issues, indent=2), encoding="utf-8")
    return 1 if (issues and args.fail_on_issues) else 0


if __name__ == "__main__":
    sys.exit(main())
