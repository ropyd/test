"""Appearance: light/dark/auto, an accent colour and a background (solid colour or gradient).

A theme is a small set of validated values, never raw CSS; the stylesheet served at /theme.css is generated from
them, so a theme can't inject styles or scripts and the strict Content-Security-Policy stays as it is."""
import json
import re
import threading
from pathlib import Path

from .store import ValidationError
from .util import atomic_write, read_json

HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
MODES = ("auto", "light", "dark")
BG_TYPES = ("none", "solid", "linear", "radial")

PRESETS = {
    "default": {"mode": "auto", "accent": "", "background": {"type": "none", "colors": [], "angle": 160}},
    "midnight": {"mode": "dark", "accent": "#7c98ff", "background": {"type": "linear", "colors": ["#0b1020", "#1b2a4a"], "angle": 160}},
    "aurora": {"mode": "dark", "accent": "#5eead4", "background": {"type": "linear", "colors": ["#0f2027", "#203a43", "#2c5364"], "angle": 135}},
    "sunset": {"mode": "dark", "accent": "#fb923c", "background": {"type": "linear", "colors": ["#2d1b3d", "#7b2d4f", "#c2603a"], "angle": 120}},
    "forest": {"mode": "dark", "accent": "#4ade80", "background": {"type": "linear", "colors": ["#0d1f17", "#1c3b2b"], "angle": 160}},
    "ocean-light": {"mode": "light", "accent": "#1d6fd1", "background": {"type": "linear", "colors": ["#eef4fb", "#cfe0f5"], "angle": 160}},
    "paper": {"mode": "light", "accent": "#b45309", "background": {"type": "solid", "colors": ["#f6f1e7"], "angle": 0}},
}


def clean_theme(d):
    """Validate a theme (or a preset name) and return the normalised dict. Raises ValidationError."""
    if isinstance(d, str):
        if d not in PRESETS:
            raise ValidationError("unknown preset")
        d = PRESETS[d]
    if not isinstance(d, dict):
        raise ValidationError("a theme must be an object")
    mode = d.get("mode", "auto")
    if mode not in MODES:
        raise ValidationError("mode must be auto, light or dark")
    accent = d.get("accent") or ""
    if accent and not (isinstance(accent, str) and HEX.match(accent)):
        raise ValidationError("accent must be a colour like #2f5bea")
    bg = d.get("background") or {}
    if not isinstance(bg, dict):
        raise ValidationError("background must be an object")
    kind = bg.get("type", "none")
    if kind not in BG_TYPES:
        raise ValidationError("background type must be none, solid, linear or radial")
    colors = bg.get("colors") or []
    if not isinstance(colors, list) or not all(isinstance(c, str) and HEX.match(c) for c in colors):
        raise ValidationError("background colours must look like #0b1020")
    angle = bg.get("angle", 160)
    if isinstance(angle, bool) or not isinstance(angle, int) or not 0 <= angle <= 360:
        raise ValidationError("angle must be a whole number from 0 to 360")
    want = {"none": (0, 0), "solid": (1, 1), "linear": (2, 3), "radial": (2, 3)}[kind]
    if not want[0] <= len(colors) <= want[1]:
        raise ValidationError("a gradient needs 2 or 3 colours, a solid background exactly 1")
    return {"mode": mode, "accent": accent.lower(), "background": {"type": kind, "colors": [c.lower() for c in colors], "angle": angle}}


def _luminance(hex_):
    def chan(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hex_[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)


def contrast(a, b):
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def text_on(accent):
    """Black or white, whichever reads better on the accent colour."""
    return "#0b0f17" if contrast(accent, "#0b0f17") >= contrast(accent, "#ffffff") else "#ffffff"


def background_css(bg):
    kind, cols = bg["type"], bg["colors"]
    if kind == "solid":
        return None, cols[0]
    if kind == "linear":
        return f"linear-gradient({bg['angle']}deg, {', '.join(cols)})", None
    if kind == "radial":
        return f"radial-gradient(circle at {50 + (bg['angle'] % 90)}% 0%, {', '.join(cols)})", None
    return None, None


def theme_css(theme):
    """The stylesheet for a validated theme. Only validated hex colours and integers are ever written."""
    t = clean_theme(theme)
    image, colour = background_css(t["background"])
    rules = [f"--page-bg-image: {image or 'none'};"]
    if colour:
        rules.append(f"--page-bg-color: {colour};")
    if t["accent"]:
        rules += [f"--accent: {t['accent']};", f"--accent-text: {text_on(t['accent'])};", f"--focus: {t['accent']};"]
    return "/* generated from the saved theme; contains only validated values */\n:root:root:root {\n  " + "\n  ".join(rules) + "\n}\n"


class ThemeStore:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        try:
            self.theme = clean_theme(read_json(self.path, None) or "default")
        except ValidationError:
            self.theme = clean_theme("default")

    def set(self, theme):
        t = clean_theme(theme)
        with self.lock:
            self.theme = t
            atomic_write(self.path, json.dumps(t), 0o600)
        return t

    def reset(self):
        return self.set("default")
