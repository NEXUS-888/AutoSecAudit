import os
import re
import logging
import threading
import uuid
import queue
import time
from flask import Flask, render_template_string, request, redirect, url_for, send_file, abort, Response, jsonify
from pathlib import Path
from werkzeug.utils import secure_filename
import json

import config
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

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ---------------------------------------------------------------------------
# SSE Scan Progress: in-memory job store
# ---------------------------------------------------------------------------
scan_jobs = {}  # {scan_id: {"status", "target", "progress_queue", "report_name", "error"}}


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

        /* ── Light Theme ──────────────────────────────────────────── */
        [data-theme="light"] {
            --bg-deep:          #f5f5f7;
            --bg-base:          #eeeef0;
            --bg-elevated:      #ffffff;
            --surface:          rgba(0,0,0,0.04);
            --surface-hover:    rgba(0,0,0,0.07);
            --fg:               #1a1a2e;
            --fg-muted:         #6b7280;
            --accent:           #4f46e5;
            --accent-bright:    #6366f1;
            --accent-glow:      rgba(79,70,229,0.20);
            --border:           rgba(0,0,0,0.08);
            --border-hover:     rgba(0,0,0,0.15);
        }
        [data-theme="light"] .bg-system { background: radial-gradient(ellipse 120% 80% at 50% 0%, #e8e8f0 0%, #f0f0f4 45%, #f5f5f7 100%); }
        [data-theme="light"] .blob--primary { background: radial-gradient(circle, rgba(79,70,229,0.15) 0%, transparent 70%); }
        [data-theme="light"] .blob--secondary { background: radial-gradient(circle, rgba(139,92,246,0.10) 0%, transparent 70%); }
        [data-theme="light"] .blob--tertiary { background: radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%); }
        [data-theme="light"] .bg-grid { background-image: linear-gradient(rgba(0,0,0,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,0,0,0.03) 1px, transparent 1px); }
        [data-theme="light"] .bg-noise { opacity: 0.02; }

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
            width: 72px; height: 72px;
            margin-bottom: 28px;
            border-radius: 20px;
            background: linear-gradient(135deg, rgba(94,106,210,0.18) 0%, rgba(94,106,210,0.06) 100%);
            box-shadow:
                0 0 0 1px rgba(94,106,210,0.20),
                0 0 40px rgba(94,106,210,0.18),
                0 8px 32px rgba(0,0,0,0.4);
        }
        .hero-icon svg {
            width: 36px; height: 36px;
            color: var(--accent-bright);
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
            background: linear-gradient(160deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.02) 100%);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 36px 32px 32px;
            box-shadow:
                0 1px 0 0 rgba(255,255,255,0.04) inset,
                0 4px 24px rgba(0,0,0,0.25),
                0 12px 48px rgba(0,0,0,0.20);
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

        /* ── Form ──────────────────────────────────────────────────── */
        .form-group { margin-bottom: 22px; }

        .form-label {
            display: block;
            font-size: 13px;
            font-weight: 500;
            color: var(--fg-muted);
            margin-bottom: 8px;
            letter-spacing: 0.1px;
        }

        .form-input {
            width: 100%;
            padding: 12px 16px;
            font-family: 'Inter', system-ui, sans-serif;
            font-size: 14px;
            color: var(--fg);
            background: #0F0F12;
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            outline: none;
            transition: border-color 250ms var(--ease-expo), box-shadow 250ms var(--ease-expo);
        }
        .form-input::placeholder { color: rgba(138,143,152,0.50); }
        .form-input:focus {
            border-color: rgba(94,106,210,0.55);
            box-shadow: 0 0 0 3px rgba(94,106,210,0.15), 0 0 20px rgba(94,106,210,0.08);
        }

        .form-input[type="file"] {
            padding: 10px 16px;
            cursor: pointer;
        }
        .form-input[type="file"]::file-selector-button {
            font-family: 'Inter', system-ui, sans-serif;
            font-size: 13px;
            font-weight: 500;
            color: var(--fg);
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 6px 14px;
            margin-right: 12px;
            cursor: pointer;
            transition: background 200ms var(--ease-expo);
        }
        .form-input[type="file"]::file-selector-button:hover {
            background: var(--surface-hover);
        }

        /* ── CTA Button ────────────────────────────────────────────── */
        .btn-primary {
            position: relative;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            width: 100%;
            padding: 14px 28px;
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

        /* ── Info Box ──────────────────────────────────────────────── */
        .info-box {
            margin-top: 28px;
            padding: 20px 22px;
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border);
            border-left: 3px solid var(--accent);
            border-radius: var(--radius-md);
        }

        .info-box-header {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 14px;
        }
        .info-box-header svg { width: 16px; height: 16px; color: var(--accent-bright); flex-shrink: 0; }
        .info-box-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--fg);
        }

        .target-list {
            list-style: none;
            margin-bottom: 14px;
        }
        .target-list li {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 5px 0;
            font-size: 13px;
            color: var(--fg-muted);
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
        }
        .target-list li svg { width: 14px; height: 14px; color: #34D399; flex-shrink: 0; }

        .info-warning {
            font-size: 12px;
            color: #F87171;
            line-height: 1.5;
            padding-top: 10px;
            border-top: 1px solid rgba(255,255,255,0.04);
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
            background: var(--accent);
            box-shadow: 0 0 30px var(--accent-glow), 0 0 60px var(--accent-glow);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 2;
        }

        .radar-glow svg {
            width: 24px;
            height: 24px;
            color: #fff;
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

        <!-- Hero -->
        <header class="hero">
            <div class="hero-icon">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 2L3 7v6c0 5.25 3.75 10.15 9 11.25C17.25 23.15 21 18.25 21 13V7l-9-5z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>
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
            <form id="scanForm" action="/scan" method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="target" class="form-label">Target URL</label>
                    <input
                        type="text"
                        id="target"
                        name="target"
                        class="form-input"
                        placeholder="http://localhost:3000"
                        autocomplete="off"
                        required
                    />
                </div>

                <div class="form-group">
                    <label for="previous_report" class="form-label">Previous Report (optional, for delta analysis)</label>
                    <input
                        type="file"
                        id="previous_report"
                        name="previous_report"
                        class="form-input"
                        accept=".json"
                    />
                </div>

                <button type="submit" class="btn-primary">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                    Start Security Scan
                </button>
            </form>

            <!-- Scanning container (initially hidden) -->
            <div id="scanningContainer" class="scanning-container">
                <div class="radar-box">
                    <div class="radar-circle"></div>
                    <div class="radar-pulse"></div>
                    <div class="radar-pulse radar-pulse--delayed"></div>
                    <div class="radar-glow">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
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

            <!-- Authorized Targets Info Box -->
            <div id="infoBox" class="info-box">
                <div class="info-box-header">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0110 0v4"/>
                    </svg>
                    <span class="info-box-title">Authorized Targets Only</span>
                </div>
                <ul class="target-list">
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
                        10.x.x.x / 172.16-31.x.x / 192.168.x.x
                    </li>
                    <li>
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                        Explicitly allowed hosts
                    </li>
                </ul>
                <p class="info-warning">
                    Scanning targets without explicit authorization is illegal and unethical. Only scan systems you own or have written permission to test.
                </p>
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
            var targetInput = document.getElementById('target');
            if (!targetInput || !targetInput.value.trim()) return;

            var targetUrl = targetInput.value.trim();
            document.getElementById('scanStatusTarget').textContent = targetUrl;

            document.getElementById('scanForm').style.display = 'none';
            document.getElementById('infoBox').style.display = 'none';

            var container = document.getElementById('scanningContainer');
            container.style.display = 'flex';

            var progressFill = document.getElementById('scanProgressFill');
            var progress = 0;
            var progressInterval = setInterval(function () {
                if (progress < 90) {
                    var increment = (95 - progress) * 0.04;
                    progress += increment;
                    progressFill.style.width = progress + '%';
                }
            }, 400);

            var statusMessages = [
                "Initializing security audit engine...",
                "Validating host and verifying authorization...",
                "Running configuration check on environment...",
                "Loading security plugins (SQLi, XSS, Information Disclosure)...",
                "Analyzing network response headers...",
                "Scanning endpoints for SQL Injection vulnerabilities...",
                "Testing authentication controllers and inputs...",
                "Analyzing security headers (X-Frame-Options, CSP, HSTS)...",
                "Cross-checking discovered endpoints for potential threats...",
                "Mapping findings to compliance standards...",
                "Running delta analyzer against historical scans...",
                "Compiling final report data and artifacts...",
                "Generating HTML interactive dashboard..."
            ];
            
            var consoleText = document.getElementById('scanConsoleText');
            var messageIndex = 0;
            var messageInterval = setInterval(function () {
                messageIndex = (messageIndex + 1) % statusMessages.length;
                consoleText.textContent = statusMessages[messageIndex];
            }, 1800);
        });
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
# Flask Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    reports_dir = Path(config.REPORTS_DIR)
    if reports_dir.exists():
        reports = [f.stem.replace("scan_", "") for f in reports_dir.glob("scan_*.json")]
        reports.sort(reverse=True)
        reports = reports[:5]
    else:
        reports = []
    return render_template_string(HTML_FORM, recent_reports=reports)


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
def _run_scan_background(scan_id: str, target: str, previous_path: str = None):
    """Run a scan in a background thread, pushing progress events to the queue."""
    job = scan_jobs[scan_id]
    q = job["progress_queue"]

    def emit(stage, message, progress=0, detail=""):
        q.put({"stage": stage, "message": message, "progress": progress, "detail": detail})

    try:
        job["status"] = "running"

        # 1. Initialize
        emit("init", "Initializing scan engine...", 5)
        engine = Engine()
        engine.load_plugins()

        if not engine.set_target(target):
            raise ValueError("Invalid target URL")
        emit("init", f"Target: {target} — {len(engine.plugins)} plugins loaded", 10)

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
                prev_findings = [Finding(**f) for f in previous_data.get("all_findings", [])]
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
        if previous_path and os.path.exists(previous_path):
            try:
                os.remove(previous_path)
            except OSError:
                pass


@app.route("/scan/async", methods=["POST"])
def scan_async():
    """Start a scan in the background, return a scan_id for SSE streaming."""
    target = request.form.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400

    allowed, reason = is_target_allowed(target)
    if not allowed:
        return jsonify({"error": reason}), 403

    previous_file = request.files.get("previous_report")
    previous_path = None
    if previous_file and previous_file.filename:
        filename = secure_filename(previous_file.filename)
        previous_path = f"{config.DATA_DIR}/temp_{filename}"
        previous_file.save(previous_path)

    scan_id = str(uuid.uuid4())[:8]
    scan_jobs[scan_id] = {
        "status": "starting",
        "target": target,
        "progress_queue": queue.Queue(),
        "report_name": None,
        "error": None,
    }

    thread = threading.Thread(
        target=_run_scan_background,
        args=(scan_id, target, previous_path),
        daemon=True,
    )
    thread.start()

    return jsonify({"scan_id": scan_id})


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
    
    previous_file = request.files.get("previous_report")
    previous_path = None
    if previous_file and previous_file.filename:
        filename = secure_filename(previous_file.filename)
        previous_path = f"{config.DATA_DIR}/temp_{filename}"
        previous_file.save(previous_path)
    
    try:
        engine = Engine()
        engine.load_plugins()
        
        if not engine.set_target(target):
            return "Invalid target", 400
        
        if previous_path:
            engine.set_previous_report(previous_path)
        
        engine.run_plugins()
        report = engine.generate_report()
        
        if previous_path and engine.previous_report:
            from intelligence.delta import DeltaAnalyzer
            previous_data = load_json(previous_path)
            if previous_data:
                from core.models import Finding
                prev_findings = [Finding(**f) for f in previous_data.get("all_findings", [])]
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
        if previous_path and os.path.exists(previous_path):
            try:
                os.remove(previous_path)
                logger.debug(f"Cleaned up temp file: {previous_path}")
            except OSError:
                logger.warning(f"Failed to clean up temp file: {previous_path}")


@app.route("/report/<report_id>")
def view_report(report_id):
    _validate_report_id(report_id)
    json_path = f"{config.REPORTS_DIR}/scan_{report_id}.json"
    report_data = load_json(json_path)
    
    if not report_data:
        return "Report not found", 404
    
    template_path = Path(__file__).parent.parent / "reports" / "templates" / "report.html"
    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()
    
    from jinja2 import Environment, select_autoescape
    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    template = env.from_string(template_content)
    html = template.render(report=report_data)
    
    return html


@app.route("/download/<report_id>")
def download_report(report_id):
    _validate_report_id(report_id)
    json_path = f"{config.REPORTS_DIR}/scan_{report_id}.json"
    if not os.path.exists(json_path):
        abort(404, description="Report not found.")
    return send_file(json_path, as_attachment=True, download_name=f"report_{report_id}.json")


if __name__ == "__main__":
    app.run(debug=config.DEBUG, host="0.0.0.0", port=5000)
