# AutoSecAudit UI/UX: Design, Animation & Layout Specification

This document details the exact CSS structures, layout designs, and custom animations that form the premium user interface of AutoSecAudit.

---

## 1. Design System & Theme Variables

The UI operates on a design token system mapping variables to dark and light palettes. Light mode values inherit or override base variables through the `[data-theme="light"]` attribute.

```css
/* ── Design Tokens ─────────────────────────────────────────── */
:root {
    --bg-deep:          #020203;
    --bg-base:          #050506;
    --bg-elevated:      #0a0a0c;
    --surface:          rgba(255,255,255,0.05);
    --surface-hover:    rgba(255,255,255,0.08);
    --fg:               #EDEDEF;
    --fg-muted:         #8A8F98;
    --fg-faint:         #555960;
    --accent:           #5E6AD2;
    --accent-bright:    #6872D9;
    --accent-glow:      rgba(94,106,210,0.30);
    --border:           rgba(255,255,255,0.06);
    --border-hover:     rgba(255,255,255,0.10);
    --radius-sm:        8px;
    --radius-md:        12px;
    --radius-lg:        16px;
    --ease-expo:        cubic-bezier(0.16,1,0.3,1);
    --ease-out:         cubic-bezier(0.16, 1, 0.3, 1);
    
    /* Severity Colors */
    --severity-critical: #ef4444;
    --severity-high:     #f97316;
    --severity-medium:   #eab308;
    --severity-low:      #22c55e;
    --severity-info:     #3b82f6;
}

/* ── Light Theme Overrides ─────────────────────────────────── */
[data-theme="light"] {
    --bg-deep:          #f5f5f7;
    --bg-base:          #eeeef0;
    --bg-elevated:      #ffffff;
    --surface:          rgba(0,0,0,0.04);
    --surface-hover:    rgba(0,0,0,0.07);
    --fg:               #1a1a2e;
    --fg-muted:         #6b7280;
    --fg-faint:         #9ca3af;
    --accent:           #4f46e5;
    --accent-bright:    #6366f1;
    --accent-glow:      rgba(79,70,229,0.20);
    --border:           rgba(0,0,0,0.08);
    --border-hover:     rgba(0,0,0,0.15);
}
```

---

## 2. Background System (Glows, Grid & Noise)

The background utilizes overlapping blur filters, floating ambient glows, and SVG textures to establish depth.

```css
/* Ambient Background System */
.bg-system {
    position: fixed; inset: 0;
    z-index: 0;
    pointer-events: none;
    overflow: hidden;
    background: radial-gradient(ellipse 120% 80% at 50% 0%, #0a0a0f 0%, #050506 45%, #020203 100%);
}
[data-theme="light"] .bg-system {
    background: radial-gradient(ellipse 120% 80% at 50% 0%, #e8e8f0 0%, #f0f0f4 45%, #f5f5f7 100%);
}

/* Vector Grid Overlay */
.bg-grid {
    position: absolute; inset: 0;
    background-image:
        linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
    background-size: 64px 64px;
}
[data-theme="light"] .bg-grid {
    background-image: 
        linear-gradient(rgba(0,0,0,0.03) 1px, transparent 1px), 
        linear-gradient(90deg, rgba(0,0,0,0.03) 1px, transparent 1px);
}

/* Procedural Noise Texture */
.bg-noise {
    position: absolute; inset: 0;
    opacity: 0.015;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
    background-repeat: repeat;
    background-size: 256px 256px;
}
[data-theme="light"] .bg-noise {
    opacity: 0.02;
}
```

### Ambient Float Keyframes
Three asynchronous float-animations run concurrently on blur-filtered color blobs behind the content canvas.

```css
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
    background: radial-gradient(circle, rgba(139,92,246,0.15) 0%, transparent 70%);
    animation: blob-float-2 22s ease-in-out infinite alternate;
}
.blob--tertiary {
    width: 500px; height: 700px;
    top: 40%; right: -6%;
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
```

---

## 3. UI Element Interaction & Card Design

Interactive container interfaces implement micro-shadows, glow transitions, and responsive hover transformations.

```css
/* Card Layout */
.card {
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: 
        0 4px 24px rgba(0,0,0,0.30),
        0 1px 2px rgba(0,0,0,0.20),
        inset 0 1px 0 rgba(255,255,255,0.03);
    transition: border-color 0.3s var(--ease-expo), box-shadow 0.3s var(--ease-expo);
}
.card:hover {
    border-color: var(--border-hover);
    box-shadow: 
        0 12px 40px rgba(0,0,0,0.40),
        0 0 0 1px rgba(94,106,210,0.05);
}

/* Glassmorphism Cards */
.glass-card {
    background: rgba(255,255,255,0.02);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    transition: all 0.3s var(--ease-out);
}
.glass-card--lift:hover {
    transform: translateY(-2px);
    background: rgba(255,255,255,0.04);
    border-color: var(--border-hover);
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
}
```

---

## 4. SSE Progress Transitions

The loading bar fills smoothly during live background events, avoiding stuttering steps using CSS transforms and transition properties.

```css
/* Progress Track & Fill */
.progress-track {
    width: 100%;
    height: 6px;
    background: rgba(255, 255, 255, 0.03);
    border-radius: 100px;
    overflow: hidden;
    position: relative;
    border: 1px solid var(--border);
}
.progress-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent) 0%, var(--accent-bright) 100%);
    box-shadow: 0 0 12px var(--accent-glow);
    border-radius: 100px;
    width: 0%;
    transition: width 0.4s cubic-bezier(0.25, 1, 0.5, 1);
}
```

---

## 5. View Transition Animations (Fade/Reveal)

Elements appear dynamically on load or when entering the viewport using standard intersections.

```css
/* Page Reveal Transitions */
.reveal {
    opacity: 0;
    transform: translateY(16px);
    transition: opacity 0.6s var(--ease-out), transform 0.6s var(--ease-out);
}
.reveal.is-visible {
    opacity: 1;
    transform: translateY(0);
}

/* Dashboard Fade Animations */
.animate-in {
    animation: fadeIn 0.5s var(--ease-out) both;
}
.delay-1 { animation-delay: 0.1s; }
.delay-2 { animation-delay: 0.2s; }
.delay-3 { animation-delay: 0.3s; }

@keyframes fadeIn {
    from { 
        opacity: 0; 
        transform: translateY(10px); 
    }
    to { 
        opacity: 1; 
        transform: translateY(0); 
    }
}
```

---

## 6. Detail Modal Overlay Animations

Clicking a vulnerability triggers a modal backdrop fade-in accompanied by a drop-slide viewport centering.

```css
/* Modal Container */
#findingModal {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 9999;
    background: rgba(0, 0, 0, 0.75);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    overflow-y: auto;
    animation: modalFadeIn 0.25s ease;
}

/* Modal Content Card */
#modalContent {
    max-width: 720px;
    margin: 40px auto;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    position: relative;
    animation: modalSlideIn 0.3s var(--ease-out);
}

/* Modal Animation Keyframes */
@keyframes modalFadeIn {
    from { opacity: 0; }
    to   { opacity: 1; }
}

@keyframes modalSlideIn {
    from { 
        opacity: 0; 
        transform: translateY(20px) scale(0.98); 
    }
    to { 
        opacity: 1; 
        transform: translateY(0) scale(1); 
    }
}
```
