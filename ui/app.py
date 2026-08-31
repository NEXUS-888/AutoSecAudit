import os
import re
import logging
import threading
import uuid
import queue
import time
from flask import Flask, render_template_string, render_template, request, redirect, url_for, send_file, abort, Response, jsonify, session
from pathlib import Path
from werkzeug.utils import secure_filename
import json

import config
import core.auth as auth
from core.engine import Engine
from core.models import Report
from core.utils import load_json, is_target_allowed
from reports.generator import ReportGenerator
from intelligence.correlator import Correlator
from intelligence.enricher import Enricher
from intelligence.compliance import ComplianceMapper

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder=str(Path(__file__).parent / "static"), static_url_path="/static")
app.secret_key = config.SECRET_KEY
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

# ---------------------------------------------------------------------------
# SSE Scan Progress: in-memory job store
# ---------------------------------------------------------------------------
scan_jobs = {}  # {scan_id: {"status", "target", "progress_queue", "report_name", "error"}}

SCAN_JOB_TTL_SECONDS = 3600  # 1 hour

def _cleanup_stale_jobs():
    """Remove scan jobs older than TTL to prevent memory leaks."""
    now = time.time()
    stale = [sid for sid, job in scan_jobs.items()
             if job.get("created_at", 0) < now - SCAN_JOB_TTL_SECONDS
             and job.get("status") in ("done", "error")]
    for sid in stale:
        del scan_jobs[sid]
    if stale:
        logger.info(f"Cleaned up {len(stale)} stale scan job(s)")


# ---------------------------------------------------------------------------
# Security: Validate report IDs to prevent path traversal
# ---------------------------------------------------------------------------
REPORT_ID_PATTERN = re.compile(r"^[\w-]+$")


def _validate_report_id(report_id: str) -> str:
    """Validate report_id contains only safe characters (alphanumeric, dash, underscore)."""
    if not REPORT_ID_PATTERN.match(report_id):
        abort(400, description="Invalid report ID.")
    return report_id


# ---------------------------------------------------------------------------
# Security: Add security headers to all responses
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# ---------------------------------------------------------------------------
# HTML_FORM — Home / Scan Page
# ---------------------------------------------------------------------------
HTML_FORM = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoSecAudit — Intelligent Security Auditing</title>
    <link rel="icon" type="image/png" href="/static/favicon.png">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

        /* ── Design Tokens ─────────────────────────────────────────── */
        :root {
            --bg-deep:          #020203;
            --bg-base:          #050506;
            --bg-elevated:      #0a0a0c;
            --surface:          rgba(255,255,255,0.05);
            --surface-hover:    rgba(255,255,255,0.08);
            --fg:               #EDEDEF;
            --fg-muted:         #8A8F98;
            --accent:           #5E6AD2;
            --accent-bright:    #6872D9;
            --accent-glow:      rgba(94,106,210,0.30);
            --border:           rgba(255,255,255,0.06);
            --border-hover:     rgba(255,255,255,0.10);
            --radius-sm:        8px;
            --radius-md:        12px;
            --radius-lg:        16px;
            --ease-expo:        cubic-bezier(0.16,1,0.3,1);
        }

        /* ── Reset ─────────────────────────────────────────────────── */
        *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }

        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: var(--bg-deep);
            color: var(--fg);
            min-height: 100vh;
            overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        /* ── Background System ─────────────────────────────────────── */
        .bg-system {
            position: fixed; inset: 0;
            z-index: 0;
            pointer-events: none;
            overflow: hidden;
            background: radial-gradient(ellipse 120% 80% at 50% 0%, #0a0a0f 0%, #050506 45%, #020203 100%);
        }

        /* Animated gradient blobs */
        .blob {
            position: absolute;
            border-radius: 50%;
            filter: blur(150px);
            will-change: transform;
        }
        .blob--primary {
            width: 900px; height: 1400px;
            top: -30%; left: 50%;
            transform: translateX(-50%);
            background: radial-gradient(circle, rgba(94,106,210,0.25) 0%, transparent 70%);
            animation: blob-float-1 18s ease-in-out infinite alternate;
        }
        .blob--secondary {
            width: 600px; height: 800px;
            top: 20%; left: -8%;
            filter: blur(120px);
            background: radial-gradient(circle, rgba(139,92,246,0.15) 0%, transparent 70%);
            animation: blob-float-2 22s ease-in-out infinite alternate;
        }
        .blob--tertiary {
            width: 500px; height: 700px;
            top: 40%; right: -6%;
            filter: blur(100px);
            background: radial-gradient(circle, rgba(79,70,229,0.12) 0%, transparent 70%);
            animation: blob-float-3 20s ease-in-out infinite alternate;
        }

        @keyframes blob-float-1 {
            0%   { transform: translateX(-50%) translateY(0)   scale(1);    }
            100% { transform: translateX(-50%) translateY(40px) scale(1.05); }
        }
        @keyframes blob-float-2 {
            0%   { transform: translateY(0)    scale(1);    }
            100% { transform: translateY(60px) scale(1.08); }
        }
        @keyframes blob-float-3 {
            0%   { transform: translateY(0)     scale(1);    }
            100% { transform: translateY(-50px) scale(1.06); }
        }

        /* Grid overlay */
        .bg-grid {
            position: absolute; inset: 0;
            background-image:
                linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
            background-size: 64px 64px;
        }

        /* Noise texture (inline SVG) */
        .bg-noise {
            position: absolute; inset: 0;
            opacity: 0.015;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
            background-repeat: repeat;
            background-size: 256px 256px;
        }

        /* ── Layout ────────────────────────────────────────────────── */
        .container {
            position: relative;
            z-index: 1;
            max-width: 620px;
            margin: 0 auto;
            padding: 60px 24px 80px;
        }

        /* ── Hero ──────────────────────────────────────────────────── */
        .hero {
            text-align: center;
            margin-bottom: 48px;
        }

        .hero-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 80px; height: 80px;
            margin-bottom: 28px;
            border-radius: 20px;
            overflow: hidden;
            box-shadow:
                0 0 0 1px rgba(94,106,210,0.20),
                0 0 40px rgba(94,106,210,0.18),
                0 8px 32px rgba(0,0,0,0.4);
        }
        .hero-icon img {
            width: 100%; height: 100%;
            object-fit: cover;
        }

        .hero-title {
            font-size: 42px;
            font-weight: 700;
            letter-spacing: -1.2px;
            line-height: 1.1;
            background: linear-gradient(180deg, #ffffff 0%, rgba(255,255,255,0.70) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .hero-sub {
            margin-top: 12px;
            font-size: 16px;
            font-weight: 400;
            color: var(--fg-muted);
            letter-spacing: -0.1px;
        }

        .version-badge {
            display: inline-block;
            margin-top: 18px;
            padding: 4px 14px;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.4px;
            color: var(--accent-bright);
            border: 1px solid rgba(94,106,210,0.35);
            border-radius: 100px;
            background: rgba(94,106,210,0.08);
        }

        /* ── Glass Card ────────────────────────────────────────────── */
        .card {
            position: relative;
            z-index: 10;
            background: linear-gradient(160deg, rgba(20, 24, 36, 0.85) 0%, rgba(10, 12, 18, 0.92) 100%);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 36px 32px 32px;
            box-shadow:
                0 1px 0 0 rgba(255,255,255,0.04) inset,
                0 4px 24px rgba(0,0,0,0.35),
                0 12px 48px rgba(0,0,0,0.30);
            overflow: hidden;
        }

        /* Inner glow line at top */
        .card::before {
            content: '';
            position: absolute;
            top: 0; left: 24px; right: 24px;
            height: 1px;
            background: linear-gradient(90deg, transparent 0%, rgba(94,106,210,0.40) 50%, transparent 100%);
        }

        /* ── Tactical Console Elements ─────────────────────────────── */
        .card-status-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-bottom: 18px;
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border);
        }
        .status-indicator-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 4px 12px;
            background: rgba(16, 185, 129, 0.10);
            border: 1px solid rgba(16, 185, 129, 0.28);
            border-radius: 100px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.6px;
            color: #34d399;
        }
        .status-pulse-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 8px #10b981;
            animation: statusDotPulse 1.8s ease-in-out infinite alternate;
        }
        @keyframes statusDotPulse {
            0% { transform: scale(0.85); opacity: 0.6; }
            100% { transform: scale(1.15); opacity: 1; box-shadow: 0 0 12px #34d399; }
        }
        .card-meta-chips {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .meta-chip {
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.3px;
            padding: 3px 10px;
            border-radius: 6px;
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--fg-muted);
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
        }
        .meta-chip-mode {
            color: var(--accent-bright);
            border-color: rgba(94, 106, 210, 0.3);
            background: rgba(94, 106, 210, 0.08);
        }

        /* ── Form ──────────────────────────────────────────────────── */
        .form-group { margin-bottom: 22px; }

        .label-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 8px;
        }
        .form-label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: var(--fg);
            letter-spacing: 0.1px;
        }
        .label-hint {
            font-size: 11px;
            color: var(--fg-muted);
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
        }

        .input-with-icon {
            position: relative;
            display: flex;
            align-items: center;
        }
        .input-icon-glyph {
            position: absolute;
            left: 14px;
            color: var(--fg-muted);
            font-size: 14px;
            pointer-events: none;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: color 200ms ease;
        }
        .custom-url-input {
            width: 100%;
            padding: 12px 16px 12px 42px !important;
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace !important;
            font-size: 14px !important;
            color: var(--fg);
            background: #0b0e17;
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            outline: none;
            transition: border-color 250ms var(--ease-expo), box-shadow 250ms var(--ease-expo);
        }
        .custom-url-input::placeholder { color: rgba(138,143,152,0.45); }
        .custom-url-input:focus {
            border-color: rgba(94,106,210,0.65);
            box-shadow: 0 0 0 3px rgba(94,106,210,0.18), 0 0 24px rgba(94,106,210,0.12);
        }
        .input-with-icon:focus-within .input-icon-glyph {
            color: var(--accent-bright);
        }

        .quick-presets-row {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }
        .presets-label {
            font-size: 11px;
            font-weight: 600;
            color: var(--fg-muted);
            letter-spacing: 0.2px;
        }
        .preset-pill {
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--fg);
            font-size: 11px;
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
            font-weight: 500;
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 180ms ease;
        }
        .preset-pill:hover {
            background: rgba(94, 106, 210, 0.15);
            border-color: var(--accent);
            color: var(--accent-bright);
            transform: translateY(-1px);
        }
        .preset-pill:active {
            transform: translateY(0);
        }
        .input-highlight-pulse {
            animation: inputGlowPulse 0.6s ease;
        }
        @keyframes inputGlowPulse {
            0% { box-shadow: 0 0 0 0 rgba(94, 106, 210, 0.5); }
            50% { box-shadow: 0 0 0 4px rgba(94, 106, 210, 0.3), 0 0 20px rgba(94, 106, 210, 0.4); }
            100% { box-shadow: 0 0 0 0 rgba(94, 106, 210, 0); }
        }

        /* ── Dropzones Grid ─────────────────────────────────────────── */
        .dropzones-section {
            margin-bottom: 24px;
        }
        .dropzones-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-top: 8px;
        }
        .dropzone-box {
            position: relative;
            border: 1px dashed var(--border-hover);
            border-radius: var(--radius-sm);
            padding: 16px 14px;
            background: var(--surface);
            cursor: pointer;
            text-align: center;
            transition: all 220ms var(--ease-expo);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 88px;
        }
        .dropzone-box:hover, .dropzone-box.drag-over {
            border-color: var(--accent-bright);
            background: rgba(94, 106, 210, 0.08);
            transform: translateY(-1px);
        }
        .dropzone-box.has-file {
            border-style: solid;
            border-color: rgba(16, 185, 129, 0.45);
            background: rgba(16, 185, 129, 0.05);
        }
        .dropzone-icon {
            font-size: 20px;
            margin-bottom: 4px;
        }
        .dropzone-title {
            font-size: 12px;
            font-weight: 600;
            color: var(--fg);
            letter-spacing: -0.1px;
        }
        .dropzone-desc {
            font-size: 11px;
            color: var(--fg-muted);
            margin-top: 2px;
        }
        .file-hidden-input {
            display: none !important;
        }
        .file-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.35);
            border-radius: 6px;
            max-width: 100%;
        }
        .file-badge-name {
            font-size: 11px;
            font-weight: 600;
            color: #34d399;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
        }
        .file-badge-remove {
            background: none;
            border: none;
            color: var(--fg-muted);
            font-size: 12px;
            cursor: pointer;
            padding: 0 4px;
            line-height: 1;
            transition: color 150ms;
        }
        .file-badge-remove:hover {
            color: #f87171;
        }

        /* ── CTA Button ────────────────────────────────────────────── */
        .btn-primary {
            position: relative;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            width: 100%;
            padding: 15px 28px;
            font-family: 'Inter', system-ui, sans-serif;
            font-size: 15px;
            font-weight: 600;
            letter-spacing: -0.1px;
            color: #fff;
            background: var(--accent);
            border: none;
            border-radius: var(--radius-sm);
            cursor: pointer;
            overflow: hidden;
            box-shadow:
                0 0 0 1px rgba(94,106,210,0.50),
                0 2px 12px rgba(94,106,210,0.30),
                0 6px 28px rgba(94,106,210,0.18);
            transition: background 250ms var(--ease-expo), box-shadow 250ms var(--ease-expo), transform 200ms var(--ease-expo);
        }
        .btn-primary:hover {
            background: var(--accent-bright);
            box-shadow:
                0 0 0 1px rgba(104,114,217,0.60),
                0 4px 20px rgba(94,106,210,0.40),
                0 8px 36px rgba(94,106,210,0.25);
            transform: translateY(-1px);
        }
        .btn-primary:active { transform: translateY(0) scale(0.99); }

        /* Shine sweep on hover */
        .btn-primary::after {
            content: '';
            position: absolute;
            top: 0; left: -100%;
            width: 60%; height: 100%;
            background: linear-gradient(105deg, transparent 30%, rgba(255,255,255,0.12) 50%, transparent 70%);
            transition: left 500ms var(--ease-expo);
        }
        .btn-primary:hover::after { left: 120%; }

        .btn-primary svg { width: 18px; height: 18px; flex-shrink: 0; }

        /* ── Authorized Policy Accordion ────────────────────────────── */
        .authorized-policy-badge {
            margin-top: 22px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            overflow: hidden;
            transition: border-color 200ms ease;
        }
        .authorized-policy-badge:hover {
            border-color: var(--border-hover);
        }
        .policy-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 14px;
            cursor: pointer;
            user-select: none;
        }
        .policy-left {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: var(--fg-muted);
        }
        .shield-badge-icon {
            font-size: 14px;
        }
        .policy-summary strong {
            color: var(--fg);
            font-weight: 600;
        }
        .policy-toggle-btn {
            background: none;
            border: none;
            font-size: 11px;
            font-weight: 600;
            color: var(--accent-bright);
            cursor: pointer;
            padding: 2px 6px;
        }
        .policy-details {
            display: none;
            padding: 0 14px 14px;
            border-top: 1px solid var(--border);
        }
        .policy-details.expanded {
            display: block;
            animation: fadeIn 0.25s ease forwards;
        }
        .policy-details .target-list {
            margin: 10px 0 8px;
            list-style: none;
        }
        .target-list li {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 5px 0;
            font-size: 12px;
            color: var(--fg-muted);
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
        }
        .target-list li svg { width: 14px; height: 14px; color: #34D399; flex-shrink: 0; }
        .policy-warning {
            font-size: 11px;
            color: #f87171;
            line-height: 1.4;
            padding-top: 8px;
            margin-top: 6px;
            border-top: 1px solid rgba(255, 255, 255, 0.04);
        }

        /* ── Recent Reports ────────────────────────────────────────── */
        .section-header {
            display: flex;
            align-items: center;
            gap: 16px;
            margin: 52px 0 20px;
        }
        .section-title {
            font-size: 14px;
            font-weight: 600;
            color: var(--fg);
            white-space: nowrap;
        }
        .section-line {
            flex: 1;
            height: 1px;
            background: linear-gradient(90deg, var(--border) 0%, transparent 100%);
        }

        .report-list { display: flex; flex-direction: column; gap: 8px; }

        .report-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 18px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            text-decoration: none;
            color: var(--fg);
            font-size: 14px;
            transition: border-color 250ms var(--ease-expo), background 250ms var(--ease-expo), transform 200ms var(--ease-expo), box-shadow 250ms var(--ease-expo);
        }
        .report-item:hover {
            background: var(--surface-hover);
            border-color: var(--border-hover);
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.20);
        }
        .report-item svg { width: 16px; height: 16px; color: var(--fg-muted); flex-shrink: 0; }
        .report-item-id { flex: 1; font-weight: 500; }
        .report-item-arrow {
            color: var(--fg-muted);
            transition: transform 200ms var(--ease-expo), color 200ms var(--ease-expo);
        }
        .report-item:hover .report-item-arrow { transform: translateX(3px); color: var(--accent-bright); }

        .empty-state {
            text-align: center;
            padding: 28px 16px;
            color: var(--fg-muted);
            font-size: 14px;
        }

        /* ── Scanning / Waiting State ──────────────────────────────── */
        .scanning-container {
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding: 20px 0;
            animation: fadeIn 0.4s var(--ease-expo) forwards;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .radar-box {
            position: relative;
            width: 100px;
            height: 100px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .radar-circle {
            position: absolute;
            inset: 0;
            border-radius: 50%;
            border: 1px solid rgba(94, 106, 210, 0.15);
            background: radial-gradient(circle, rgba(94,106,210,0.05) 0%, transparent 70%);
        }

        .radar-pulse {
            position: absolute;
            inset: -10px;
            border-radius: 50%;
            border: 2px solid var(--accent);
            opacity: 0;
            animation: radarPulse 2s cubic-bezier(0.21, 0.6, 0.35, 1) infinite;
        }

        .radar-pulse--delayed {
            animation-delay: 1s;
        }

        @keyframes radarPulse {
            0% {
                transform: scale(0.6);
                opacity: 0.8;
            }
            100% {
                transform: scale(1.2);
                opacity: 0;
            }
        }

        .radar-glow {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            overflow: hidden;
            background: var(--accent);
            box-shadow: 0 0 30px var(--accent-glow), 0 0 60px var(--accent-glow);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 2;
        }

        .radar-glow img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            animation: pulse-icon 1.5s ease-in-out infinite alternate;
        }

        @keyframes pulse-icon {
            0% { transform: scale(0.9); }
            100% { transform: scale(1.1); }
        }

        .scan-status-title {
            font-size: 18px;
            font-weight: 600;
            color: var(--fg);
            margin-bottom: 6px;
            letter-spacing: -0.2px;
        }

        .scan-status-target {
            font-size: 14px;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            color: var(--accent-bright);
            margin-bottom: 24px;
            word-break: break-all;
        }

        .scan-progress-bar {
            width: 100%;
            height: 4px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 100px;
            overflow: hidden;
            margin-bottom: 24px;
            border: 1px solid var(--border);
        }

        .scan-progress-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, var(--accent) 0%, var(--accent-bright) 100%);
            box-shadow: 0 0 10px var(--accent-glow);
            border-radius: 100px;
            transition: width 0.3s ease;
        }

        .scan-console {
            width: 100%;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            padding: 14px 16px;
            text-align: left;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 12px;
            color: var(--fg-muted);
            min-height: 52px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .scan-console-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #34D399;
            box-shadow: 0 0 8px #34D399;
            animation: pulse-green 1s ease-in-out infinite alternate;
        }

        @keyframes pulse-green {
            0% { opacity: 0.4; }
            100% { opacity: 1; }
        }

        .scan-console-text {
            flex: 1;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        /* ── Footer ────────────────────────────────────────────────── */
        .footer {
            margin-top: 64px;
            text-align: center;
        }
        .footer-line {
            width: 60px;
            height: 1px;
            margin: 0 auto 16px;
            background: linear-gradient(90deg, transparent 0%, var(--border) 50%, transparent 100%);
        }
        .footer-text {
            font-size: 12px;
            color: var(--fg-muted);
            opacity: 0.6;
        }

        /* ── Reduced Motion ────────────────────────────────────────── */
        @media (prefers-reduced-motion: reduce) {
            .blob { animation: none !important; }
            .btn-primary::after { transition: none !important; }
            *, *::before, *::after { transition-duration: 0.01ms !important; animation-duration: 0.01ms !important; }
        }

        /* ── Responsive ────────────────────────────────────────────── */
        @media (max-width: 640px) {
            .container { padding: 40px 16px 60px; }
            .hero-title { font-size: 32px; }
            .card { padding: 28px 20px 24px; }
            .info-box { padding: 16px 18px; }
            .blob--primary  { width: 500px; height: 800px; }
            .blob--secondary { width: 350px; height: 500px; }
            .blob--tertiary  { width: 300px; height: 400px; }
        }
        /* ══════════════════════════════════════════════════════════════
           HIGH-SPECIFICITY LIGHT THEME OVERRIDES (AT BOTTOM OF CASCADE)
           ══════════════════════════════════════════════════════════════ */
        [data-theme="light"] {
            --bg-deep:          #f8fafc;
            --bg-base:          #f1f5f9;
            --bg-elevated:      #ffffff;
            --surface:          rgba(0,0,0,0.03);
            --surface-hover:    rgba(0,0,0,0.06);
            --fg:               #0f172a;
            --fg-muted:         #64748b;
            --accent:           #4f46e5;
            --accent-bright:    #6366f1;
            --accent-glow:      rgba(79,70,229,0.18);
            --border:           #e2e8f0;
            --border-hover:     #cbd5e1;
        }
        [data-theme="light"] body {
            background: #f8fafc !important;
            color: #0f172a !important;
        }
        [data-theme="light"] .bg-system {
            background: radial-gradient(ellipse 120% 80% at 50% 0%, #e2e8f0 0%, #f1f5f9 45%, #f8fafc 100%) !important;
        }
        [data-theme="light"] .blob--primary { background: radial-gradient(circle, rgba(79,70,229,0.10) 0%, transparent 70%) !important; }
        [data-theme="light"] .blob--secondary { background: radial-gradient(circle, rgba(139,92,246,0.06) 0%, transparent 70%) !important; }
        [data-theme="light"] .blob--tertiary { background: radial-gradient(circle, rgba(59,130,246,0.05) 0%, transparent 70%) !important; }
        [data-theme="light"] .bg-grid {
            background-image: linear-gradient(rgba(0,0,0,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(0,0,0,0.04) 1px, transparent 1px) !important;
        }
        [data-theme="light"] .bg-noise { opacity: 0.02 !important; }
        [data-theme="light"] .hero-title {
            background: linear-gradient(180deg, #0f172a 0%, #334155 100%) !important;
            -webkit-background-clip: text !important;
            -webkit-text-fill-color: transparent !important;
            color: #0f172a !important;
        }
        [data-theme="light"] .hero-sub { color: #64748b !important; }
        [data-theme="light"] .hero-icon {
            box-shadow: 0 0 0 1px rgba(79,70,229,0.18), 0 8px 24px rgba(79,70,229,0.10) !important;
        }
        [data-theme="light"] .version-badge {
            background: #eef2ff !important;
            border-color: #c7d2fe !important;
            color: #4f46e5 !important;
        }

        /* Card & Status Header */
        [data-theme="light"] .card {
            background: #ffffff !important;
            border: 1px solid #e2e8f0 !important;
            box-shadow: 0 10px 30px -5px rgba(0,0,0,0.06), 0 4px 6px -2px rgba(0,0,0,0.03) !important;
        }
        [data-theme="light"] .card::before {
            background: linear-gradient(90deg, transparent 0%, rgba(79,70,229,0.30) 50%, transparent 100%) !important;
        }
        [data-theme="light"] .card-status-bar {
            border-bottom-color: #e2e8f0 !important;
        }
        [data-theme="light"] .status-indicator-pill {
            background: #ecfdf5 !important;
            border-color: #a7f3d0 !important;
            color: #047857 !important;
        }
        [data-theme="light"] .meta-chip {
            background: #f1f5f9 !important;
            border-color: #e2e8f0 !important;
            color: #475569 !important;
        }
        [data-theme="light"] .meta-chip-mode {
            background: #eef2ff !important;
            border-color: #c7d2fe !important;
            color: #4f46e5 !important;
        }

        /* Form Labels & Target URL Input */
        [data-theme="light"] .form-label { color: #0f172a !important; }
        [data-theme="light"] .label-hint { color: #64748b !important; }
        [data-theme="light"] .input-icon-glyph { color: #64748b !important; }
        [data-theme="light"] .input-with-icon:focus-within .input-icon-glyph { color: #4f46e5 !important; }
        [data-theme="light"] .custom-url-input {
            background: #ffffff !important;
            color: #0f172a !important;
            border: 1px solid #cbd5e1 !important;
            box-shadow: 0 1px 2px rgba(0,0,0,0.04) inset !important;
        }
        [data-theme="light"] .custom-url-input::placeholder { color: #94a3b8 !important; }
        [data-theme="light"] .custom-url-input:focus {
            background: #ffffff !important;
            border-color: #6366f1 !important;
            box-shadow: 0 0 0 3px rgba(99,102,241,0.18) !important;
        }

        /* Presets */
        [data-theme="light"] .presets-label { color: #64748b !important; }
        [data-theme="light"] .preset-pill {
            background: #f8fafc !important;
            border: 1px solid #e2e8f0 !important;
            color: #334155 !important;
        }
        [data-theme="light"] .preset-pill:hover {
            background: #eef2ff !important;
            border-color: #6366f1 !important;
            color: #4338ca !important;
        }

        /* Dropzones */
        [data-theme="light"] .dropzone-box {
            background: #f8fafc !important;
            border: 1px dashed #cbd5e1 !important;
        }
        [data-theme="light"] .dropzone-box:hover,
        [data-theme="light"] .dropzone-box.drag-over {
            background: #f1f5f9 !important;
            border-color: #6366f1 !important;
        }
        [data-theme="light"] .dropzone-box.has-file {
            background: #ecfdf5 !important;
            border-style: solid !important;
            border-color: #10b981 !important;
        }
        [data-theme="light"] .dropzone-title { color: #0f172a !important; }
        [data-theme="light"] .dropzone-desc { color: #64748b !important; }
        [data-theme="light"] .file-badge {
            background: #ecfdf5 !important;
            border: 1px solid #a7f3d0 !important;
        }
        [data-theme="light"] .file-badge-name { color: #047857 !important; }
        [data-theme="light"] .file-badge-remove { color: #64748b !important; }
        [data-theme="light"] .file-badge-remove:hover { color: #dc2626 !important; }

        /* Authorized Scope Badge */
        [data-theme="light"] .authorized-policy-badge {
            background: #f8fafc !important;
            border: 1px solid #e2e8f0 !important;
        }
        [data-theme="light"] .policy-summary strong { color: #0f172a !important; }
        [data-theme="light"] .policy-left { color: #475569 !important; }
        [data-theme="light"] .policy-toggle-btn { color: #4f46e5 !important; }
        [data-theme="light"] .policy-details { border-top-color: #e2e8f0 !important; }
        [data-theme="light"] .policy-details .target-list li { color: #475569 !important; }
        [data-theme="light"] .policy-warning {
            color: #b91c1c !important;
            border-top-color: #e2e8f0 !important;
        }

        /* Recent Reports & History link */
        [data-theme="light"] .section-title { color: #64748b !important; }
        [data-theme="light"] .section-line { background: #e2e8f0 !important; }
        [data-theme="light"] .report-item {
            background: #ffffff !important;
            border: 1px solid #e2e8f0 !important;
            color: #1e293b !important;
        }
        [data-theme="light"] .report-item:hover {
            background: #f8fafc !important;
            border-color: #6366f1 !important;
            box-shadow: 0 4px 12px rgba(0,0,0,0.06) !important;
        }
        [data-theme="light"] .report-item-id { color: #0f172a !important; }
        [data-theme="light"] .scan-status-title { color: #0f172a !important; }
        [data-theme="light"] .scan-status-target { color: #4f46e5 !important; }
        [data-theme="light"] .scan-progress-bar { background: #e2e8f0 !important; border-color: #cbd5e1 !important; }
        [data-theme="light"] .scan-console { background: #f1f5f9 !important; border: 1px solid #e2e8f0 !important; color: #1e293b !important; }
        [data-theme="light"] .scan-console-text { color: #334155 !important; }
        [data-theme="light"] .footer-line { background: linear-gradient(90deg, transparent 0%, #e2e8f0 50%, transparent 100%) !important; }
        [data-theme="light"] .footer-text { color: #64748b !important; }
    </style>
</head>
<body>

    <!-- Background System -->
    <div class="bg-system">
        <div class="blob blob--primary"></div>
        <div class="blob blob--secondary"></div>
        <div class="blob blob--tertiary"></div>
        <canvas id="cyberMatrixCanvas" style="position: absolute; inset: 0; width: 100%; height: 100%; pointer-events: none; z-index: 1;"></canvas>
        <div class="bg-grid"></div>
        <div class="bg-noise"></div>
    </div>

    <div class="container">

        <!-- Hero -->
        <header class="hero">
            <div class="hero-icon">
                <img src="{{ url_for('static', filename='logo.jpg') }}" alt="AutoSecAudit Logo">
            </div>
            <h1 class="hero-title">AutoSecAudit</h1>
            <p class="hero-sub">Intelligent Security Auditing Framework</p>
            <span class="version-badge">v2.0</span>
        </header>

        <!-- Theme Toggle -->
        <button id="themeToggle" onclick="toggleTheme()" style="position: fixed; top: 20px; right: 20px; z-index: 1000; background: var(--surface); border: 1px solid var(--border); border-radius: 50%; width: 40px; height: 40px; cursor: pointer; display: flex; align-items: center; justify-content: center; color: var(--fg-muted); transition: all 0.3s var(--ease-expo); backdrop-filter: blur(10px);" onmouseover="this.style.borderColor='var(--accent)';this.style.color='var(--accent)'" onmouseout="this.style.borderColor='var(--border)';this.style.color='var(--fg-muted)'" title="Toggle light/dark mode">
            <svg id="themeIcon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
            </svg>
        </button>

        <!-- Scan Form Card -->
        <main class="card">
            <!-- Header Status Bar -->
            <div class="card-status-bar">
                <div class="status-indicator-pill">
                    <span class="status-pulse-dot"></span>
                    <span class="status-pill-text">ENGINE READY</span>
                </div>
                <div class="card-meta-chips">
                    <span class="meta-chip">14 PLUGINS</span>
                    <span class="meta-chip meta-chip-mode">MOCK DEMO</span>
                </div>
            </div>

            <form id="scanForm" action="/scan" method="POST" enctype="multipart/form-data">
                <!-- Target URL & Quick Presets -->
                <div class="form-group">
                    <div class="label-row">
                        <label for="target" class="form-label">Target URL</label>
                        <span class="label-hint">IPv4, Domain, or Port</span>
                    </div>
                    <div class="input-with-icon">
                        <span class="input-icon-glyph">🌐</span>
                        <input
                            type="text"
                            id="target"
                            name="target"
                            class="custom-url-input"
                            placeholder="http://localhost:3000"
                            autocomplete="off"
                            required
                        />
                    </div>
                    <div class="quick-presets-row">
                        <span class="presets-label">⚡ Quick Fill:</span>
                        <button type="button" class="preset-pill" onclick="applyPreset('http://localhost:3000')">localhost:3000</button>
                        <button type="button" class="preset-pill" onclick="applyPreset('http://127.0.0.1:8000')">127.0.0.1:8000</button>
                        <button type="button" class="preset-pill" onclick="applyPreset('http://demo-target.local:5000')">demo-target.local</button>
                    </div>
                </div>

                <!-- Side-by-Side Modern Drag-and-Drop Dropzones -->
                <div class="dropzones-section">
                    <div class="label-row">
                        <span class="form-label">Audit Attachments <span style="font-size: 11px; font-weight: normal; color: var(--fg-muted);">(Optional)</span></span>
                    </div>
                    <div class="dropzones-grid">
                        <!-- OpenAPI Spec Dropzone -->
                        <div class="dropzone-box" id="openapiDropzone" onclick="document.getElementById('openapi_spec').click()">
                            <input
                                type="file"
                                id="openapi_spec"
                                name="openapi_spec"
                                class="file-hidden-input"
                                accept=".json"
                                onchange="handleFileSelected(this, 'openapiBadge', 'openapiDropzone', 'openapiDropContent', 'openapiFileName')"
                            />
                            <div class="dropzone-content" id="openapiDropContent">
                                <div class="dropzone-icon">📄</div>
                                <div class="dropzone-title">OpenAPI / Swagger</div>
                                <div class="dropzone-desc">Click or drop .json</div>
                            </div>
                            <div class="file-badge" id="openapiBadge" style="display: none;">
                                <span class="file-badge-name" id="openapiFileName">spec.json</span>
                                <button type="button" class="file-badge-remove" title="Remove file" onclick="event.stopPropagation(); clearFile('openapi_spec', 'openapiBadge', 'openapiDropzone', 'openapiDropContent')">✕</button>
                            </div>
                        </div>

                        <!-- Previous Report Delta Dropzone -->
                        <div class="dropzone-box" id="deltaDropzone" onclick="document.getElementById('previous_report').click()">
                            <input
                                type="file"
                                id="previous_report"
                                name="previous_report"
                                class="file-hidden-input"
                                accept=".json"
                                onchange="handleFileSelected(this, 'deltaBadge', 'deltaDropzone', 'deltaDropContent', 'deltaFileName')"
                            />
                            <div class="dropzone-content" id="deltaDropContent">
                                <div class="dropzone-icon">📊</div>
                                <div class="dropzone-title">Previous Report</div>
                                <div class="dropzone-desc">Delta analysis .json</div>
                            </div>
                            <div class="file-badge" id="deltaBadge" style="display: none;">
                                <span class="file-badge-name" id="deltaFileName">report.json</span>
                                <button type="button" class="file-badge-remove" title="Remove file" onclick="event.stopPropagation(); clearFile('previous_report', 'deltaBadge', 'deltaDropzone', 'deltaDropContent')">✕</button>
                            </div>
                        </div>
                    </div>
                </div>

                <button type="submit" class="btn-primary btn-launch-scan">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">
                        <polygon points="5 3 19 12 5 21 5 3"/>
                    </svg>
                    <span>Launch Security Audit</span>
                </button>
            </form>

            <!-- Scanning container (initially hidden) -->
            <div id="scanningContainer" class="scanning-container">
                <div class="radar-box">
                    <div class="radar-circle"></div>
                    <div class="radar-pulse"></div>
                    <div class="radar-pulse radar-pulse--delayed"></div>
                    <div class="radar-glow">
                        <img src="{{ url_for('static', filename='logo.jpg') }}" alt="AutoSecAudit">
                    </div>
                </div>
                <h3 class="scan-status-title">Performing Security Audit</h3>
                <p id="scanStatusTarget" class="scan-status-target">Target URL</p>
                
                <div class="scan-progress-bar">
                    <div id="scanProgressFill" class="scan-progress-fill"></div>
                </div>

                <div class="scan-console">
                    <span class="scan-console-dot"></span>
                    <span id="scanConsoleText" class="scan-console-text">Initializing security scanners...</span>
                </div>
            </div>

            <!-- Authorized Targets Policy Badge (Collapsible) -->
            <div id="infoBox" class="authorized-policy-badge">
                <div class="policy-header" onclick="togglePolicyDetails()">
                    <div class="policy-left">
                        <span class="shield-badge-icon">🛡️</span>
                        <span class="policy-summary"><strong>Authorized Scope:</strong> Localhost, 127.0.0.1, RFC-1918 subnets</span>
                    </div>
                    <button type="button" class="policy-toggle-btn" id="policyToggleBtn">Rules ▾</button>
                </div>
                <div class="policy-details" id="policyDetails">
                    <ul class="target-list">
                        <li>
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                            localhost / 127.0.0.1
                        </li>
                        <li>
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                            *.local domains & container subnets
                        </li>
                        <li>
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                            10.x.x.x / 172.16-31.x.x / 192.168.x.x
                        </li>
                        <li>
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                            Explicitly authorized test hosts
                        </li>
                    </ul>
                    <p class="policy-warning">
                        ⚠️ Only scan systems you own or have explicit written authorization to test.
                    </p>
                </div>
            </div>
        </main>

        <!-- Recent Reports -->
        <div class="section-header">
            <span class="section-title">Recent Reports</span>
            <div class="section-line"></div>
        </div>

        {% if recent_reports %}
        <div class="report-list">
            {% for report in recent_reports %}
            <a href="/report/{{ report }}" class="report-item">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                    <line x1="16" y1="13" x2="8" y2="13"/>
                    <line x1="16" y1="17" x2="8" y2="17"/>
                    <polyline points="10 9 9 9 8 9"/>
                </svg>
                <span class="report-item-id">{{ report }}</span>
                <svg class="report-item-arrow" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="9 18 15 12 9 6"/>
                </svg>
            </a>
            {% endfor %}
        </div>
        {% else %}
        <div class="empty-state">No reports yet. Run your first scan above.</div>
        {% endif %}

        <div style="text-align: center; margin-top: 16px;">
            <a href="/history" style="color: var(--accent-bright); text-decoration: none; font-size: 14px; font-weight: 500; padding: 8px 20px; border: 1px solid rgba(94,106,210,0.3); border-radius: 8px; display: inline-flex; align-items: center; gap: 6px; transition: all 0.2s;"
               onmouseover="this.style.background='rgba(94,106,210,0.1)'"
               onmouseout="this.style.background='transparent'">
                📊 View All History →
            </a>
        </div>

        <!-- Footer -->
        <footer class="footer">
            <div class="footer-line"></div>
            <p class="footer-text">Built for ethical security testing</p>
        </footer>
    </div>

    <script>
        /* ── Theme Toggle ──────────────────────────── */
        function toggleTheme() {
            var html = document.documentElement;
            var current = html.getAttribute('data-theme');
            var next = current === 'light' ? 'dark' : 'light';
            html.setAttribute('data-theme', next);
            localStorage.setItem('autosec-theme', next);
            updateThemeIcon(next);
        }
        function updateThemeIcon(theme) {
            var icon = document.getElementById('themeIcon');
            if (!icon) return;
            if (theme === 'light') {
                icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
            } else {
                icon.innerHTML = '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>';
            }
        }
        (function() {
            var saved = localStorage.getItem('autosec-theme');
            if (saved) {
                document.documentElement.setAttribute('data-theme', saved);
                updateThemeIcon(saved);
            }
        })();
    </script>
    <script>
        document.getElementById('scanForm').addEventListener('submit', function (e) {
            e.preventDefault();
            var targetInput = document.getElementById('target');
            if (!targetInput || !targetInput.value.trim()) return;

            var targetUrl = targetInput.value.trim();
            document.getElementById('scanStatusTarget').textContent = targetUrl;

            document.getElementById('scanForm').style.display = 'none';
            document.getElementById('infoBox').style.display = 'none';

            var container = document.getElementById('scanningContainer');
            container.style.display = 'flex';

            var progressFill = document.getElementById('scanProgressFill');
            var consoleText = document.getElementById('scanConsoleText');
            progressFill.style.width = '5%';
            consoleText.textContent = 'Submitting target for automated analysis...';

            var formData = new FormData(this);

            fetch('/scan/async', {
                method: 'POST',
                body: formData
            })
            .then(function (res) {
                if (!res.ok) {
                    return res.json().then(function (err) { throw new Error(err.error || 'Scan request blocked or failed'); });
                }
                return res.json();
            })
            .then(function (data) {
                var scanId = data.scan_id;
                var evtSource = new EventSource('/scan/progress/' + scanId);

                evtSource.onmessage = function (event) {
                    try {
                        var payload = JSON.parse(event.data);
                        if (payload.percent !== undefined) {
                            progressFill.style.width = Math.max(5, payload.percent) + '%';
                        }
                        if (payload.message) {
                            consoleText.textContent = payload.message;
                        }
                        if (payload.stage === 'done') {
                            evtSource.close();
                            progressFill.style.width = '100%';
                            consoleText.textContent = 'Audit complete! Opening interactive dashboard...';
                            var repName = payload.report_name || payload.detail;
                            if (repName && repName !== 'undefined' && repName !== 'null') {
                                setTimeout(function () {
                                    window.location.href = '/report/' + encodeURIComponent(repName);
                                }, 600);
                            } else {
                                fetch('/scan/status/' + scanId)
                                .then(function (r) { return r.json(); })
                                .then(function (statusData) {
                                    if (statusData.report_name) {
                                        window.location.href = '/report/' + encodeURIComponent(statusData.report_name);
                                    } else {
                                        window.location.href = '/history';
                                    }
                                })
                                .catch(function () {
                                    window.location.href = '/history';
                                });
                            }
                        } else if (payload.stage === 'error') {
                            evtSource.close();
                            consoleText.style.color = '#ef4444';
                            consoleText.textContent = 'Error: ' + payload.message;
                            showRetryButton();
                        }
                    } catch (err) {
                        console.error('SSE parse error:', err);
                    }
                };

                evtSource.onerror = function () {
                    evtSource.close();
                    var pollInterval = setInterval(function () {
                        fetch('/scan/status/' + scanId)
                        .then(function (r) { return r.json(); })
                        .then(function (statusData) {
                            if (statusData.status === 'done') {
                                clearInterval(pollInterval);
                                var rep = statusData.report_name;
                                if (rep && rep !== 'undefined') {
                                    window.location.href = '/report/' + encodeURIComponent(rep);
                                } else {
                                    window.location.href = '/history';
                                }
                            } else if (statusData.status === 'error') {
                                clearInterval(pollInterval);
                                consoleText.style.color = '#ef4444';
                                consoleText.textContent = 'Error: ' + (statusData.error || 'Scan failed');
                                showRetryButton();
                            }
                        })
                        .catch(function () {});
                    }, 1200);
                };
            })
            .catch(function (err) {
                consoleText.style.color = '#ef4444';
                consoleText.textContent = 'Error: ' + err.message;
                showRetryButton();
            });

            function showRetryButton() {
                var retryBtn = document.createElement('button');
                retryBtn.textContent = '← Return & Try Again';
                retryBtn.className = 'btn-primary';
                retryBtn.style.marginTop = '20px';
                retryBtn.onclick = function () { window.location.reload(); };
                container.appendChild(retryBtn);
            }
        });

        /* ── Tactical Console UI Handlers ──────────── */
        function applyPreset(url) {
            var input = document.getElementById('target');
            if (!input) return;
            input.value = url;
            input.focus();
            input.classList.add('input-highlight-pulse');
            setTimeout(function () { input.classList.remove('input-highlight-pulse'); }, 600);
        }

        function handleFileSelected(input, badgeId, dropzoneId, contentId, nameId) {
            if (!input.files || !input.files[0]) return;
            var file = input.files[0];
            var dropzone = document.getElementById(dropzoneId);
            var content = document.getElementById(contentId);
            var badge = document.getElementById(badgeId);
            var fileNameEl = document.getElementById(nameId);

            if (fileNameEl) fileNameEl.textContent = file.name;
            if (content) content.style.display = 'none';
            if (badge) badge.style.display = 'flex';
            if (dropzone) dropzone.classList.add('has-file');
        }

        function clearFile(inputId, badgeId, dropzoneId, contentId) {
            var input = document.getElementById(inputId);
            var dropzone = document.getElementById(dropzoneId);
            var content = document.getElementById(contentId);
            var badge = document.getElementById(badgeId);

            if (input) input.value = '';
            if (content) content.style.display = 'flex';
            if (badge) badge.style.display = 'none';
            if (dropzone) dropzone.classList.remove('has-file');
        }

        function togglePolicyDetails() {
            var details = document.getElementById('policyDetails');
            var btn = document.getElementById('policyToggleBtn');
            if (!details) return;
            var isExpanded = details.classList.toggle('expanded');
            if (btn) btn.textContent = isExpanded ? 'Hide ▴' : 'Rules ▾';
        }

        // Drag and drop support for dropzones
        ['openapiDropzone', 'deltaDropzone'].forEach(function (dzId) {
            var el = document.getElementById(dzId);
            if (!el) return;
            var inputId = dzId === 'openapiDropzone' ? 'openapi_spec' : 'previous_report';
            var badgeId = dzId === 'openapiDropzone' ? 'openapiBadge' : 'deltaBadge';
            var contentId = dzId === 'openapiDropzone' ? 'openapiDropContent' : 'deltaDropContent';
            var nameId = dzId === 'openapiDropzone' ? 'openapiFileName' : 'deltaFileName';

            ['dragenter', 'dragover'].forEach(function (eventName) {
                el.addEventListener(eventName, function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                    el.classList.add('drag-over');
                }, false);
            });

            ['dragleave', 'drop'].forEach(function (eventName) {
                el.addEventListener(eventName, function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                    el.classList.remove('drag-over');
                }, false);
            });

            el.addEventListener('drop', function (e) {
                var dt = e.dataTransfer;
                var files = dt.files;
                if (files && files.length) {
                    var fileInput = document.getElementById(inputId);
                    if (fileInput) {
                        fileInput.files = files;
                        handleFileSelected(fileInput, badgeId, dzId, contentId, nameId);
                    }
                }
            }, false);
        });
    </script>

    <!-- ── Interactive Cyber Matrix Spotlight Reveal ────────────── -->
    <script>
    (function () {
        const canvas = document.getElementById('cyberMatrixCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        let width = 0, height = 0;
        let dpr = window.devicePixelRatio || 1;
        let columns = [];
        const fontSize = 13;
        const columnSpacing = 28;

        // Security payloads & bytecode tokens
        const symbols = [
            '0x7F', '0x2A', '41', '55', '54', '4F', '73', '65', '63',
            'GET', 'POST', '200', '403', 'JWT', 'SQLi', 'DAST', 'CORS',
            'CSP', 'AUTH', 'PORT:443', 'TLS1.3', 'SHA256', 'CVE', 'NVD',
            '01', 'FF', '10', '00', 'XSS', 'ROOT', 'PASS', 'NODE', 'λ', '§', 'Δ',
            '0x00', '0xFF', 'TOKEN', 'BEARER', 'COOKIE', 'REST', 'API', 'STATUS:OK'
        ];

        // Smooth mouse spotlight coordinates
        let mouseX = -1000, mouseY = -1000;
        let targetMouseX = -1000, targetMouseY = -1000;
        let isHovered = false;
        let lastTime = 0;

        function resize() {
            width = window.innerWidth;
            height = window.innerHeight;
            canvas.width = width * dpr;
            canvas.height = height * dpr;
            ctx.scale(dpr, dpr);

            const numCols = Math.floor(width / columnSpacing);
            columns = [];
            for (let i = 0; i < numCols; i++) {
                columns.push({
                    x: i * columnSpacing + columnSpacing / 2,
                    y: Math.random() * height,
                    speed: 0.65 + Math.random() * 0.9,
                    tokens: Array.from({ length: 26 }, () => ({
                        char: symbols[Math.floor(Math.random() * symbols.length)],
                        mutationTimer: Math.floor(Math.random() * 60)
                    }))
                });
            }
        }

        window.addEventListener('resize', resize);
        resize();

        window.addEventListener('mousemove', (e) => {
            targetMouseX = e.clientX;
            targetMouseY = e.clientY;
            isHovered = true;
        });

        window.addEventListener('mouseleave', () => {
            isHovered = false;
        });

        function render(timestamp) {
            if (!lastTime) lastTime = timestamp;
            const delta = Math.min((timestamp - lastTime) / 1000, 0.1);
            lastTime = timestamp;

            // Smooth mouse motion
            if (isHovered) {
                mouseX += (targetMouseX - mouseX) * 0.14;
                mouseY += (targetMouseY - mouseY) * 0.14;
            } else {
                mouseX += (-1000 - mouseX) * 0.06;
                mouseY += (-1000 - mouseY) * 0.06;
            }

            ctx.clearRect(0, 0, width, height);

            const isLight = document.documentElement.getAttribute('data-theme') === 'light';
            const spotlightRadius = 260;

            ctx.font = '10px "JetBrains Mono", "SF Mono", Consolas, monospace';
            ctx.textAlign = 'center';

            for (let i = 0; i < columns.length; i++) {
                const col = columns[i];
                col.y += col.speed * 50 * delta;
                if (col.y > height + 350) {
                    col.y = -180;
                }

                for (let j = 0; j < col.tokens.length; j++) {
                    const token = col.tokens[j];
                    const charY = (col.y - j * (fontSize + 7));
                    if (charY < -30 || charY > height + 30) continue;

                    // Periodic mutation
                    token.mutationTimer--;
                    if (token.mutationTimer <= 0) {
                        token.char = symbols[Math.floor(Math.random() * symbols.length)];
                        token.mutationTimer = 40 + Math.floor(Math.random() * 90);
                    }

                    const dist = Math.hypot(col.x - mouseX, charY - mouseY);

                    if (dist < spotlightRadius) {
                        // Spotlight active zone: luminous, crisp cyber glow
                        const factor = Math.pow(1 - dist / spotlightRadius, 1.8);
                        const alpha = 0.08 + factor * 0.85;

                        if (isLight) {
                            ctx.fillStyle = factor > 0.55 ? `rgba(79, 70, 229, ${alpha})` : `rgba(2, 132, 199, ${alpha * 0.9})`;
                        } else {
                            ctx.fillStyle = factor > 0.55 ? `rgba(6, 182, 212, ${alpha})` : `rgba(16, 185, 129, ${alpha * 0.85})`;
                        }

                        if (factor > 0.5) {
                            ctx.shadowColor = isLight ? 'rgba(99, 102, 241, 0.45)' : 'rgba(6, 182, 212, 0.6)';
                            ctx.shadowBlur = 8;
                        } else {
                            ctx.shadowBlur = 0;
                        }

                        ctx.fillText(token.char, col.x, charY);
                        ctx.shadowBlur = 0;
                    } else {
                        // Ambient resting state: ultra-clean & subtle (never overwhelming)
                        const baseAlpha = isLight ? 0.022 : 0.032;
                        ctx.fillStyle = isLight ? `rgba(100, 116, 139, ${baseAlpha})` : `rgba(148, 163, 184, ${baseAlpha})`;
                        ctx.fillText(token.char, col.x, charY);
                    }
                }
            }

            requestAnimationFrame(render);
        }

        requestAnimationFrame(render);
    })();
    </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTML_BLOCKED — Blocked Target Page
# ---------------------------------------------------------------------------
HTML_BLOCKED = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Blocked — AutoSecAudit</title>
    <link rel="icon" type="image/png" href="/static/favicon.png">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

        :root {
            --bg-deep:          #020203;
            --bg-base:          #050506;
            --bg-elevated:      #0a0a0c;
            --surface:          rgba(255,255,255,0.05);
            --surface-hover:    rgba(255,255,255,0.08);
            --fg:               #EDEDEF;
            --fg-muted:         #8A8F98;
            --accent:           #5E6AD2;
            --accent-bright:    #6872D9;
            --accent-glow:      rgba(94,106,210,0.30);
            --danger:           #EF4444;
            --danger-muted:     rgba(239,68,68,0.15);
            --danger-border:    rgba(239,68,68,0.30);
            --border:           rgba(255,255,255,0.06);
            --border-hover:     rgba(255,255,255,0.10);
            --radius-sm:        8px;
            --radius-md:        12px;
            --radius-lg:        16px;
            --ease-expo:        cubic-bezier(0.16,1,0.3,1);
        }

        *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }

        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: var(--bg-deep);
            color: var(--fg);
            min-height: 100vh;
            overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        /* ── Background System ─────────────────────────────────────── */
        .bg-system {
            position: fixed; inset: 0;
            z-index: 0;
            pointer-events: none;
            overflow: hidden;
            background: radial-gradient(ellipse 120% 80% at 50% 0%, #0a0a0f 0%, #050506 45%, #020203 100%);
        }

        .blob {
            position: absolute;
            border-radius: 50%;
            filter: blur(150px);
            will-change: transform;
        }
        .blob--primary {
            width: 900px; height: 1400px;
            top: -30%; left: 50%;
            transform: translateX(-50%);
            background: radial-gradient(circle, rgba(239,68,68,0.18) 0%, transparent 70%);
            animation: blob-float-1 18s ease-in-out infinite alternate;
        }
        .blob--secondary {
            width: 600px; height: 800px;
            top: 20%; left: -8%;
            filter: blur(120px);
            background: radial-gradient(circle, rgba(139,92,246,0.12) 0%, transparent 70%);
            animation: blob-float-2 22s ease-in-out infinite alternate;
        }
        .blob--tertiary {
            width: 500px; height: 700px;
            top: 40%; right: -6%;
            filter: blur(100px);
            background: radial-gradient(circle, rgba(79,70,229,0.10) 0%, transparent 70%);
            animation: blob-float-3 20s ease-in-out infinite alternate;
        }

        @keyframes blob-float-1 {
            0%   { transform: translateX(-50%) translateY(0)   scale(1);    }
            100% { transform: translateX(-50%) translateY(40px) scale(1.05); }
        }
        @keyframes blob-float-2 {
            0%   { transform: translateY(0)    scale(1);    }
            100% { transform: translateY(60px) scale(1.08); }
        }
        @keyframes blob-float-3 {
            0%   { transform: translateY(0)     scale(1);    }
            100% { transform: translateY(-50px) scale(1.06); }
        }

        .bg-grid {
            position: absolute; inset: 0;
            background-image:
                linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
            background-size: 64px 64px;
        }

        .bg-noise {
            position: absolute; inset: 0;
            opacity: 0.015;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
            background-repeat: repeat;
            background-size: 256px 256px;
        }

        /* ── Layout ────────────────────────────────────────────────── */
        .container {
            position: relative;
            z-index: 1;
            max-width: 560px;
            margin: 0 auto;
            padding: 100px 24px 80px;
            text-align: center;
        }

        /* ── Blocked Icon ──────────────────────────────────────────── */
        .blocked-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 88px; height: 88px;
            margin-bottom: 32px;
            border-radius: 24px;
            background: linear-gradient(135deg, rgba(239,68,68,0.16) 0%, rgba(239,68,68,0.04) 100%);
            box-shadow:
                0 0 0 1px var(--danger-border),
                0 0 48px rgba(239,68,68,0.16),
                0 8px 32px rgba(0,0,0,0.4);
            animation: icon-pulse 3s ease-in-out infinite;
        }
        .blocked-icon svg { width: 42px; height: 42px; color: var(--danger); }

        @keyframes icon-pulse {
            0%, 100% { box-shadow: 0 0 0 1px var(--danger-border), 0 0 48px rgba(239,68,68,0.16), 0 8px 32px rgba(0,0,0,0.4); }
            50%      { box-shadow: 0 0 0 1px var(--danger-border), 0 0 64px rgba(239,68,68,0.22), 0 8px 32px rgba(0,0,0,0.4); }
        }

        .blocked-title {
            font-size: 36px;
            font-weight: 700;
            letter-spacing: -1px;
            line-height: 1.15;
            background: linear-gradient(180deg, #F87171 0%, rgba(239,68,68,0.65) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .blocked-sub {
            margin-top: 10px;
            font-size: 15px;
            color: var(--fg-muted);
        }

        /* ── Reason Card ───────────────────────────────────────────── */
        .reason-card {
            margin-top: 36px;
            padding: 22px 24px;
            text-align: left;
            background: linear-gradient(160deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%);
            border: 1px solid var(--border);
            border-left: 3px solid var(--danger);
            border-radius: var(--radius-md);
            box-shadow: 0 4px 24px rgba(0,0,0,0.20);
        }
        .reason-label {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--danger);
            margin-bottom: 8px;
        }
        .reason-text {
            font-size: 14px;
            line-height: 1.6;
            color: var(--fg);
        }

        /* ── Allowed Targets ───────────────────────────────────────── */
        .allowed-section {
            margin-top: 36px;
            text-align: left;
        }
        .allowed-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--fg-muted);
            margin-bottom: 14px;
        }
        .allowed-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .allowed-list li {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 16px;
            font-size: 13px;
            color: var(--fg-muted);
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
        }
        .allowed-list li svg { width: 14px; height: 14px; color: #34D399; flex-shrink: 0; }

        /* ── Go Back Button ────────────────────────────────────────── */
        .btn-back {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            margin-top: 40px;
            padding: 12px 28px;
            font-family: 'Inter', system-ui, sans-serif;
            font-size: 14px;
            font-weight: 600;
            color: #fff;
            background: var(--accent);
            border: none;
            border-radius: var(--radius-sm);
            text-decoration: none;
            cursor: pointer;
            box-shadow:
                0 0 0 1px rgba(94,106,210,0.50),
                0 2px 12px rgba(94,106,210,0.30),
                0 6px 28px rgba(94,106,210,0.18);
            transition: background 250ms var(--ease-expo), box-shadow 250ms var(--ease-expo), transform 200ms var(--ease-expo);
        }
        .btn-back:hover {
            background: var(--accent-bright);
            box-shadow:
                0 0 0 1px rgba(104,114,217,0.60),
                0 4px 20px rgba(94,106,210,0.40),
                0 8px 36px rgba(94,106,210,0.25);
            transform: translateY(-1px);
        }
        .btn-back:active { transform: translateY(0) scale(0.99); }
        .btn-back svg { width: 16px; height: 16px; }

        /* ── Reduced Motion ────────────────────────────────────────── */
        @media (prefers-reduced-motion: reduce) {
            .blob { animation: none !important; }
            .blocked-icon { animation: none !important; }
            *, *::before, *::after { transition-duration: 0.01ms !important; animation-duration: 0.01ms !important; }
        }

        /* ── Responsive ────────────────────────────────────────────── */
        @media (max-width: 640px) {
            .container { padding: 60px 16px 60px; }
            .blocked-title { font-size: 28px; }
            .blocked-icon { width: 72px; height: 72px; border-radius: 20px; }
            .blocked-icon svg { width: 34px; height: 34px; }
            .blob--primary  { width: 500px; height: 800px; }
            .blob--secondary { width: 350px; height: 500px; }
            .blob--tertiary  { width: 300px; height: 400px; }
        }
    </style>
</head>
<body>

    <!-- Background System -->
    <div class="bg-system">
        <div class="blob blob--primary"></div>
        <div class="blob blob--secondary"></div>
        <div class="blob blob--tertiary"></div>
        <div class="bg-grid"></div>
        <div class="bg-noise"></div>
    </div>

    <div class="container">

        <!-- Blocked Icon -->
        <div class="blocked-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 2L3 7v6c0 5.25 3.75 10.15 9 11.25C17.25 23.15 21 18.25 21 13V7l-9-5z"/>
                <line x1="8" y1="8" x2="16" y2="16"/>
                <line x1="16" y1="8" x2="8" y2="16"/>
            </svg>
        </div>

        <h1 class="blocked-title">Scan Blocked</h1>
        <p class="blocked-sub">This target is not authorized for scanning.</p>

        <!-- Reason Card -->
        <div class="reason-card">
            <div class="reason-label">Reason</div>
            <p class="reason-text">{{ reason }}</p>
        </div>

        <!-- Allowed Targets -->
        <div class="allowed-section">
            <p class="allowed-title">You can scan these targets instead:</p>
            <ul class="allowed-list">
                <li>
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                    localhost / 127.0.0.1
                </li>
                <li>
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                    *.local domains
                </li>
                <li>
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                    Private IP ranges (10.x, 172.16-31.x, 192.168.x)
                </li>
                <li>
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                    Explicitly allowed hosts in config
                </li>
            </ul>
        </div>

        <!-- Go Back Button -->
        <a href="/" class="btn-back">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="19" y1="12" x2="5" y2="12"/>
                <polyline points="12 19 5 12 12 5"/>
            </svg>
            Go Back
        </a>
    </div>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# Authentication Helper & Flask Routes
# ---------------------------------------------------------------------------

def get_current_user():
    """Retrieve logged-in user from session, if any."""
    user_id = session.get("user_id")
    if user_id:
        return auth.get_user_by_id(user_id)
    return None


@app.route("/")
@app.route("/landing")
def index():
    """Creative animated landing page explaining AutoSecAudit's orchestration and value proposition."""
    current_user = get_current_user()
    return render_template("landing.html", user=current_user)


@app.route("/dashboard")
@app.route("/scanner")
def dashboard():
    """Active security scanning console and target configuration."""
    current_user = get_current_user()
    if not current_user:
        next_target = request.args.get("target")
        next_url = f"/dashboard?target={next_target}" if next_target else "/dashboard"
        return redirect(url_for("login", next=next_url))

    reports_dir = Path(config.REPORTS_DIR)
    if reports_dir.exists():
        reports = [f.stem.replace("scan_", "") for f in reports_dir.glob("scan_*.json")]
        reports.sort(reverse=True)
        reports = reports[:5]
    else:
        reports = []
    return render_template_string(HTML_FORM, recent_reports=reports, user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login endpoint supporting HTML form and AJAX JSON requests."""
    next_url = request.args.get("next") or request.form.get("next") or url_for("dashboard")
    if request.method == "POST":
        if request.is_json:
            data = request.get_json() or {}
            identifier = data.get("identifier", "")
            password = data.get("password", "")
            next_url = data.get("next") or next_url
        else:
            identifier = request.form.get("identifier", "")
            password = request.form.get("password", "")

        ok, msg, user = auth.verify_user(identifier, password)
        if ok and user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            if request.is_json:
                return jsonify({"success": True, "message": "Login successful", "user": user, "redirect": next_url})
            return redirect(next_url)
        else:
            if request.is_json:
                return jsonify({"success": False, "message": msg}), 401
            return render_template("auth.html", mode="login", error=msg, form_data={"identifier": identifier}, next=next_url)

    # GET request
    if get_current_user():
        return redirect(next_url)
    return render_template("auth.html", mode="login", next=next_url)


@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration endpoint supporting HTML form and AJAX JSON requests."""
    next_url = request.args.get("next") or request.form.get("next") or url_for("dashboard")
    if request.method == "POST":
        if request.is_json:
            data = request.get_json() or {}
            username = data.get("username", "")
            email = data.get("email", "")
            password = data.get("password", "")
            full_name = data.get("full_name", "")
            next_url = data.get("next") or next_url
        else:
            username = request.form.get("username", "")
            email = request.form.get("email", "")
            password = request.form.get("password", "")
            full_name = request.form.get("full_name", "")

        ok, msg, user = auth.create_user(username, email, password, full_name=full_name)
        if ok and user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            if request.is_json:
                return jsonify({"success": True, "message": "Account created successfully", "user": user, "redirect": next_url})
            return redirect(next_url)
        else:
            if request.is_json:
                return jsonify({"success": False, "message": msg}), 400
            return render_template("auth.html", mode="register", error=msg, form_data={"username": username, "email": email, "full_name": full_name}, next=next_url)

    # GET request
    if get_current_user():
        return redirect(next_url)
    return render_template("auth.html", mode="register", next=next_url)


@app.route("/logout")
def logout():
    """Log out user and clear session."""
    session.clear()
    return redirect(url_for("index"))


@app.route("/api/auth/status")
def auth_status():
    """Return JSON authentication status of current session."""
    user = get_current_user()
    if user:
        return jsonify({"authenticated": True, "user": user})
    return jsonify({"authenticated": False, "user": None})


@app.route("/history")
def history():
    """Scan history dashboard with charts and trends."""
    from jinja2 import Environment, FileSystemLoader
    reports_dir = Path(config.REPORTS_DIR)
    scans = []

    if reports_dir.exists():
        for json_file in sorted(reports_dir.glob("scan_*.json")):
            try:
                data = load_json(str(json_file))
                if not data:
                    continue
                summary = data.get("summary", {})
                timestamp = data.get("timestamp", "")
                # Extract short date for chart labels
                date_short = timestamp[:10] if len(timestamp) >= 10 else timestamp
                scans.append({
                    "report_id": json_file.stem.replace("scan_", ""),
                    "timestamp": timestamp,
                    "date_short": date_short[5:] if len(date_short) >= 5 else date_short,
                    "target": data.get("target", "unknown"),
                    "total": summary.get("total", 0),
                    "critical": summary.get("critical", 0),
                    "high": summary.get("high", 0),
                    "medium": summary.get("medium", 0),
                    "low": summary.get("low", 0),
                    "info": summary.get("info", 0),
                })
            except Exception as e:
                logger.debug(f"Skipping corrupt report {json_file}: {e}")

    total_findings = sum(s["total"] for s in scans)
    total_critical = sum(s["critical"] for s in scans)
    total_high = sum(s["high"] for s in scans)
    total_medium = sum(s["medium"] for s in scans)
    total_low = sum(s["low"] for s in scans)
    total_info = sum(s["info"] for s in scans)

    # Use Jinja2 FileSystemLoader to load from ui/templates/
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("history.html")

    return template.render(
        scans=scans,
        total_findings=total_findings,
        total_critical=total_critical,
        total_high=total_high,
        total_medium=total_medium,
        total_low=total_low,
        total_info=total_info,
    )


# ---------------------------------------------------------------------------
# SSE: Async scan with real-time progress streaming
# ---------------------------------------------------------------------------
def _run_scan_background(scan_id: str, target: str, previous_path: str = None, openapi_path: str = None):
    """Run a scan in a background thread, pushing progress events to the queue."""
    job = scan_jobs[scan_id]
    q = job["progress_queue"]

    def emit(stage, message, progress=0, detail=""):
        rep_name = detail if stage == "done" else (job.get("report_name") if job else None)
        q.put({
            "stage": stage,
            "message": message,
            "progress": progress,
            "percent": progress,
            "detail": detail,
            "report_name": rep_name
        })

    try:
        job["status"] = "running"

        # 1. Initialize
        emit("init", "Initializing scan engine...", 5)
        engine = Engine()
        engine.load_plugins()

        if not engine.set_target(target):
            raise ValueError("Invalid target URL")
        emit("init", f"Target: {target} — {len(engine.plugins)} plugins loaded", 10)

        if openapi_path:
            from core.openapi import OpenAPIImporter
            importer = OpenAPIImporter(openapi_path)
            if importer.load_spec():
                imported_eps = importer.get_endpoints()
                engine.crawler_data["injectable_endpoints"] = imported_eps
                emit("init", f"Imported {len(imported_eps)} endpoints from OpenAPI spec", 13)

        if previous_path:
            engine.set_previous_report(previous_path)
            emit("init", "Previous report loaded for delta comparison", 12)

        # 2. Crawling (happens inside run_plugins, but we show progress)
        emit("crawling", "Crawling target for endpoints...", 15)

        # 3. Run plugins
        emit("scanning", "Starting plugin execution...", 20)
        engine.run_plugins()

        # Report crawler results
        if engine.crawl_result:
            cr = engine.crawl_result
            emit("crawling", f"Discovered {len(cr.endpoints)} endpoints, {len(cr.forms)} forms", 30,
                 f"Visited {cr.pages_visited} pages")

        # Report plugin results  
        total_findings = sum(len(sr.findings) for sr in engine.scan_results)
        emit("scanning", f"All {len(engine.scan_results)} plugins complete — {total_findings} raw findings", 55)

        # 4. Generate report
        emit("processing", "Generating report...", 60)
        report = engine.generate_report()

        # 5. Delta analysis
        if previous_path and engine.previous_report:
            emit("processing", "Running delta analysis...", 65)
            from intelligence.delta import DeltaAnalyzer
            previous_data = load_json(previous_path)
            if previous_data:
                from core.models import Finding
                import dataclasses
                _valid_fields = {fld.name for fld in dataclasses.fields(Finding)}
                prev_findings = [Finding(**{k: v for k, v in f.items() if k in _valid_fields}) for f in previous_data.get("all_findings", [])]
                prev_report = Report(
                    target=previous_data.get("target", ""),
                    timestamp=previous_data.get("timestamp", ""),
                    all_findings=prev_findings
                )
                delta = DeltaAnalyzer().compare(report, prev_report)
                report.delta = delta

        # 6. Intelligence pipeline
        emit("enriching", "Correlating findings...", 70)
        correlator = Correlator()
        report.all_findings = correlator.link_related(report.all_findings)

        emit("enriching", "Enriching with CVE data...", 75)
        enricher_obj = Enricher()
        report.all_findings = enricher_obj.enrich(report.all_findings)

        emit("enriching", "Mapping compliance standards...", 80)
        mapper = ComplianceMapper()
        report.all_findings = mapper.map_findings(report.all_findings)

        emit("enriching", "Adding remediation suggestions...", 85)
        from intelligence.remediation import enrich_with_remediation
        report.all_findings = enrich_with_remediation(report.all_findings)

        report.summary = engine._generate_summary(report.all_findings)

        # 7. Save
        emit("saving", "Saving report...", 90)
        json_path = engine.save_report(report)

        emit("saving", "Generating HTML report...", 95)
        generator = ReportGenerator()
        generator.generate_report(report)

        report_name = Path(json_path).stem.replace("scan_", "")
        job["report_name"] = report_name
        job["status"] = "done"
        emit("done", f"Scan complete — {len(report.all_findings)} findings", 100, report_name)

    except Exception as e:
        logger.error(f"Async scan failed: {e}")
        job["status"] = "error"
        job["error"] = str(e)
        emit("error", f"Scan failed: {str(e)}", 0)
    finally:
        for tmp_path in [previous_path, openapi_path]:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass


@app.route("/scan/async", methods=["POST"])
def scan_async():
    """Start a scan in the background, return a scan_id for SSE streaming."""
    _cleanup_stale_jobs()
    target = request.form.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400

    allowed, reason = is_target_allowed(target)
    if not allowed:
        return jsonify({"error": reason}), 403

    previous_path = None
    openapi_path = None

    try:
        previous_file = request.files.get("previous_report")
        if previous_file and previous_file.filename:
            import tempfile
            filename = secure_filename(previous_file.filename)
            with tempfile.NamedTemporaryFile(delete=False, dir=config.DATA_DIR, prefix=f"temp_prev_{filename}_", suffix=".json") as tmp:
                previous_file.save(tmp.name)
                previous_path = tmp.name

        openapi_file = request.files.get("openapi_spec")
        if openapi_file and openapi_file.filename:
            import tempfile
            filename = secure_filename(openapi_file.filename)
            with tempfile.NamedTemporaryFile(delete=False, dir=config.DATA_DIR, prefix=f"temp_openapi_{filename}_", suffix=".json") as tmp:
                openapi_file.save(tmp.name)
                openapi_path = tmp.name

        scan_id = str(uuid.uuid4())[:8]
        scan_jobs[scan_id] = {
            "status": "starting",
            "target": target,
            "progress_queue": queue.Queue(),
            "report_name": None,
            "error": None,
            "created_at": time.time(),
        }

        thread = threading.Thread(
            target=_run_scan_background,
            args=(scan_id, target, previous_path, openapi_path),
            daemon=True,
        )
        thread.start()

        return jsonify({"scan_id": scan_id})

    except Exception as e:
        logger.error(f"Failed to initialize async scan: {e}", exc_info=True)
        for tmp in [previous_path, openapi_path]:
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        return jsonify({"error": f"Failed to initialize scan: {str(e)}"}), 500


@app.route("/scan/progress/<scan_id>")
def scan_progress(scan_id):
    """SSE endpoint — streams scan progress events."""
    if scan_id not in scan_jobs:
        return "Scan not found", 404

    def event_stream():
        job = scan_jobs[scan_id]
        q = job["progress_queue"]
        while True:
            try:
                event = q.get(timeout=30)
                data = json.dumps(event)
                yield f"data: {data}\n\n"
                if event.get("stage") in ("done", "error"):
                    break
            except queue.Empty:
                # Send keepalive
                yield f": keepalive\n\n"
                if job["status"] in ("done", "error"):
                    break

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/scan/status/<scan_id>")
def scan_status(scan_id):
    """JSON status endpoint — polling fallback."""
    if scan_id not in scan_jobs:
        return jsonify({"error": "Scan not found"}), 404
    job = scan_jobs[scan_id]
    return jsonify({
        "status": job["status"],
        "target": job["target"],
        "report_name": job["report_name"],
        "error": job["error"],
    })


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    if not target:
        return "Target is required", 400
    
    allowed, reason = is_target_allowed(target)
    if not allowed:
        logger.warning(f"Blocked scan attempt on: {target}")
        return render_template_string(HTML_BLOCKED, reason=reason), 403
    
    import tempfile

    openapi_file = request.files.get("openapi_spec")
    openapi_path = None
    if openapi_file and openapi_file.filename:
        filename = secure_filename(openapi_file.filename)
        with tempfile.NamedTemporaryFile(delete=False, dir=config.DATA_DIR, prefix=f"temp_openapi_{filename}_", suffix=".json") as tmp:
            openapi_file.save(tmp.name)
            openapi_path = tmp.name

    previous_file = request.files.get("previous_report")
    previous_path = None
    if previous_file and previous_file.filename:
        filename = secure_filename(previous_file.filename)
        with tempfile.NamedTemporaryFile(delete=False, dir=config.DATA_DIR, prefix=f"temp_prev_{filename}_", suffix=".json") as tmp:
            previous_file.save(tmp.name)
            previous_path = tmp.name
    
    try:
        engine = Engine()
        engine.load_plugins()
        
        if not engine.set_target(target):
            return "Invalid target", 400
        
        if openapi_path:
            from core.openapi import OpenAPIImporter
            importer = OpenAPIImporter(openapi_path)
            if importer.load_spec():
                engine.crawler_data["injectable_endpoints"] = importer.get_endpoints()

        if previous_path:
            engine.set_previous_report(previous_path)
        
        engine.run_plugins()
        report = engine.generate_report()
        
        if previous_path and engine.previous_report:
            from intelligence.delta import DeltaAnalyzer
            previous_data = load_json(previous_path)
            if previous_data:
                from core.models import Finding
                import dataclasses
                _valid_fields = {fld.name for fld in dataclasses.fields(Finding)}
                prev_findings = [Finding(**{k: v for k, v in f.items() if k in _valid_fields}) for f in previous_data.get("all_findings", [])]
                prev_report = Report(
                    target=previous_data.get("target", ""),
                    timestamp=previous_data.get("timestamp", ""),
                    all_findings=prev_findings
                )
                delta = DeltaAnalyzer().compare(report, prev_report)
                report.delta = delta
        
        correlator = Correlator()
        report.all_findings = correlator.link_related(report.all_findings)
        
        enricher = Enricher()
        report.all_findings = enricher.enrich(report.all_findings)
        
        mapper = ComplianceMapper()
        report.all_findings = mapper.map_findings(report.all_findings)
        
        # Remediation advice
        from intelligence.remediation import enrich_with_remediation
        report.all_findings = enrich_with_remediation(report.all_findings)
        
        report.summary = engine._generate_summary(report.all_findings)
        
        json_path = engine.save_report(report)
        
        generator = ReportGenerator()
        html_path = generator.generate_report(report)
        
        report_name = Path(json_path).stem.replace("scan_", "")
        
        return redirect(url_for("view_report", report_id=report_name))
    finally:
        # Clean up temporary uploaded files
        for tmp in [previous_path, openapi_path]:
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                    logger.debug(f"Cleaned up temp file: {tmp}")
                except OSError:
                    logger.warning(f"Failed to clean up temp file: {tmp}")



HTML_REPORT_NOT_FOUND = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Not Found — AutoSecAudit</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        :root {
            --bg: #050506;
            --card-bg: #0a0a0c;
            --fg: #ededef;
            --fg-muted: #8a8f98;
            --accent: #5e6ad2;
            --border: rgba(255,255,255,0.08);
        }
        [data-theme="light"] {
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --fg: #0f172a;
            --fg-muted: #64748b;
            --accent: #4f46e5;
            --border: #e2e8f0;
        }
        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: var(--bg);
            color: var(--fg);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 24px;
        }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 40px 32px;
            max-width: 480px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        h2 { font-size: 22px; margin: 16px 0 8px; font-weight: 700; color: var(--fg); }
        p { color: var(--fg-muted); font-size: 14px; margin-bottom: 24px; line-height: 1.5; }
        code { background: rgba(94,106,210,0.15); color: var(--accent); padding: 2px 6px; border-radius: 4px; font-size: 13px; }
        .btn-group { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
        .btn {
            background: var(--accent);
            color: #fff;
            padding: 10px 20px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.2s;
        }
        .btn:hover { filter: brightness(1.1); }
        .btn-secondary {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--fg);
        }
        .btn-secondary:hover { background: rgba(255,255,255,0.05); }
    </style>
</head>
<body>
    <div class="card">
        <div style="font-size: 44px;">🔍</div>
        <h2>Report Not Found</h2>
        <p>Could not locate scan report <code>{{ report_id }}</code>. The audit may still be generating or the report file was removed.</p>
        <div class="btn-group">
            <a href="/" class="btn">← Return to Home</a>
            <a href="/history" class="btn btn-secondary">View Scan History</a>
        </div>
    </div>
    <script>
        (function() {
            var theme = localStorage.getItem('autosec-theme');
            if (theme) document.documentElement.setAttribute('data-theme', theme);
        })();
    </script>
</body>
</html>
"""


def _resolve_report_data(report_id: str):
    """Resolve report JSON data and normalized clean ID across multiple naming schemes and timestamp matching."""
    if not report_id or report_id in ("undefined", "null"):
        return None, None
    _validate_report_id(report_id)
    clean_id = report_id.replace("scan_", "").replace("report_", "").replace(".json", "").replace(".html", "").replace(".pdf", "")
    
    candidate_paths = [
        f"{config.REPORTS_DIR}/scan_{clean_id}.json",
        f"{config.REPORTS_DIR}/{report_id}.json",
        f"{config.REPORTS_DIR}/report_{clean_id}.json",
        f"{config.REPORTS_DIR}/{clean_id}.json",
    ]
    for cp in candidate_paths:
        if os.path.exists(cp):
            data = load_json(cp)
            if data:
                return data, clean_id

    # Fallback: scan all JSON files in REPORTS_DIR matching normalized timestamps or IDs
    import glob
    for fpath in sorted(glob.glob(f"{config.REPORTS_DIR}/*.json"), reverse=True):
        try:
            data = load_json(fpath)
            if not data:
                continue
            ts = str(data.get("timestamp", ""))
            norm_ts = ts.replace(" ", "_").replace(":", "").replace("-", "").replace("T", "_")
            file_stem = Path(fpath).stem.replace("scan_", "").replace("report_", "")
            if clean_id in norm_ts or norm_ts in clean_id or clean_id == file_stem:
                return data, file_stem
        except Exception as e:
            logger.debug(f"Skipping unreadable candidate report {fpath}: {e}")
            continue

    return None, clean_id


@app.route("/report/<report_id>")
def view_report(report_id):
    if not report_id or report_id in ("undefined", "null", "latest"):
        import glob
        reports = sorted(glob.glob(f"{config.REPORTS_DIR}/scan_*.json"), reverse=True)
        if reports:
            latest_id = Path(reports[0]).stem.replace("scan_", "")
            return redirect(url_for("view_report", report_id=latest_id))
        return render_template_string(HTML_REPORT_NOT_FOUND, report_id="Unknown"), 404
        
    _validate_report_id(report_id)
    clean_id = report_id.replace("scan_", "").replace("report_", "").replace(".json", "").replace(".html", "")
    
    report_data, resolved_id = _resolve_report_data(report_id)
    
    if not report_data:
        # Check if pre-rendered HTML file exists
        html_candidates = [
            f"{config.REPORTS_DIR}/report_{clean_id}.html",
            f"{config.REPORTS_DIR}/{report_id}.html",
            f"{config.REPORTS_DIR}/{clean_id}.html",
        ]
        for hp in html_candidates:
            if os.path.exists(hp):
                with open(hp, "r", encoding="utf-8") as f:
                    return f.read()
        return render_template_string(HTML_REPORT_NOT_FOUND, report_id=report_id), 404
    
    template_path = Path(__file__).parent.parent / "reports" / "templates" / "report.html"
    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()
    
    from jinja2 import Environment, select_autoescape
    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    template = env.from_string(template_content)
    html = template.render(report=report_data, report_id=resolved_id or clean_id)
    
    return html


@app.route("/download/<report_id>")
def download_report(report_id):
    if not report_id or report_id in ("undefined", "null"):
        abort(404, description="Invalid report ID.")
    
    report_data, resolved_id = _resolve_report_data(report_id)
    if not report_data:
        abort(404, description="Report not found.")
        
    clean_id = resolved_id or report_id.replace("scan_", "").replace("report_", "").replace(".json", "").replace(".html", "")
    json_path = f"{config.REPORTS_DIR}/scan_{clean_id}.json"
    if not os.path.exists(json_path):
        json_path = f"{config.REPORTS_DIR}/report_{clean_id}.json"
    if not os.path.exists(json_path):
        json_path = f"{config.REPORTS_DIR}/{report_id}.json"
    if not os.path.exists(json_path):
        save_json(report_data, json_path)

    response = send_file(
        json_path,
        as_attachment=True,
        mimetype="application/json",
        download_name=f"report_{clean_id}.json"
    )
    response.headers["Content-Type"] = "application/json"
    response.headers["Content-Disposition"] = f'attachment; filename="report_{clean_id}.json"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/download_pdf/<report_id>")
def download_pdf_report(report_id):
    if not report_id or report_id in ("undefined", "null"):
        abort(404, description="Invalid report ID.")
        
    report_data, resolved_id = _resolve_report_data(report_id)
    if not report_data:
        abort(404, description="Report not found.")
    
    clean_id = resolved_id or report_id.replace("scan_", "").replace("report_", "").replace(".json", "").replace(".html", "").replace(".pdf", "")
    pdf_path = f"{config.REPORTS_DIR}/report_{clean_id}.pdf"
    
    try:
        generator = ReportGenerator()
        generator.generate_pdf(report_data, pdf_path)
    except Exception as e:
        logger.error(f"PDF generation failed: {e}", exc_info=True)
        abort(500, description=f"Failed to generate PDF report: {str(e)}")
    
    response = send_file(
        pdf_path,
        as_attachment=True,
        mimetype="application/pdf",
        download_name=f"report_{clean_id}.pdf"
    )
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f'attachment; filename="report_{clean_id}.pdf"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


if __name__ == "__main__":
    app.run(debug=config.DEBUG, host="0.0.0.0", port=5000)
