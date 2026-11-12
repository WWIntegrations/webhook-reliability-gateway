"""Build docs/how-it-works-{light,dark}.svg from a real demo run.

One dot = one HTTP request or one delivery attempt, in the same scale in every column.
"""
from __future__ import annotations

import sys
from html import escape
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webhook_gateway.demo import run  # noqa: E402

THEMES = {
    "light": dict(bg="#fdfff5", ink="#050507", muted="#55555a", line="#c9cbbf",
                  ok="#1b6e3c", retry="#a86b00", bad="#a3261d", dup="#322db8"),
    "dark": dict(bg="#050507", ink="#fdfff5", muted="#a8a8b0", line="#33333d",
                 ok="#6fd39b", retry="#f2c46b", bad="#ff8b80", dup="#8c8cf0"),
}
W, H, R, GAP = 1200, 470, 9, 26
COLS = [40, 330, 620, 910]


def groups_from(result) -> list:
    """Dot groups per column, read from the measured demo steps."""
    s = {x["step"]: x for x in result["steps"]}
    assert all(x["pass"] for x in result["steps"]), "demo failed; refusing to draw it"
    return [
        ("Sender: 7 requests", [("ok", 3, "stored (evt_1, evt_2, evt_3)"), ("dup", 1, "same id again: 200, not stored"),
                                ("bad", 1, "same id, other body: 409"), ("bad", 2, "forged or 15 min old: 401")]),
        ("Inbox: 3 events", [("ok", 3, "committed, then 2xx")]),
        ("Worker: 7 attempts", [("retry", 2, "503 + Retry-After: backoff"), ("ok", 1, "evt_1 delivered"),
                                ("retry", 1, "worker killed after send"), ("ok", 1, "evt_2 again, fenced lease"),
                                ("bad", 1, "422: dead letter"), ("ok", 1, "replayed by operator")]),
        ("Receiver: 3 effects", [("ok", 3, "one per event")]),
    ], s


def svg(theme: str, result) -> str:
    t = THEMES[theme]
    cols, _ = groups_from(result)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif">',
           f'<rect width="{W}" height="{H}" fill="{t["bg"]}"/>',
           f'<text x="40" y="44" font-size="22" font-weight="700" fill="{t["ink"]}">One effect per event, measured</text>',
           f'<text x="40" y="70" font-size="14" fill="{t["muted"]}">Each dot is one HTTP request or delivery attempt from the demo run (same scale in every column).</text>']
    arrows = ["verify signature, dedupe id,\nCOMMIT, then answer",
              "lease + fencing token,\nbackoff with full jitter",
              "Idempotency-Key stored in\nthe effect's transaction"]
    for i, (title, groups) in enumerate(cols):
        x0 = COLS[i]
        out.append(f'<text x="{x0}" y="120" font-size="16" font-weight="700" fill="{t["ink"]}">{escape(title)}</text>')
        y = 150
        for kind, n, label in groups:
            for k in range(n):
                out.append(f'<circle cx="{x0 + R + k * GAP}" cy="{y}" r="{R}" fill="{t[kind]}"/>')
            out.append(f'<text x="{x0 + n * GAP + 6}" y="{y + 5}" font-size="13" fill="{t["muted"]}">{escape(label)}</text>')
            y += 38
        if i < 3:
            ax = COLS[i + 1] - 34
            out.append(f'<path d="M{ax - 24} 115 L{ax + 10} 115" stroke="{t["line"]}" stroke-width="2" fill="none"/>'
                       f'<path d="M{ax + 4} 109 L{ax + 12} 115 L{ax + 4} 121" stroke="{t["line"]}" stroke-width="2" fill="none"/>')
    for i, text in enumerate(arrows):
        for j, line in enumerate(text.split("\n")):
            out.append(f'<text x="{COLS[i + 1]}" y="{H - 52 + j * 18}" font-size="13" fill="{t["ink"]}">{escape(line)}</text>')
    legend = [("ok", "success"), ("retry", "retried"), ("dup", "duplicate"), ("bad", "refused")]
    for j, (kind, name) in enumerate(legend):
        lx = 780 + j * 100
        out.append(f'<circle cx="{lx}" cy="{38}" r="6" fill="{t[kind]}"/>'
                   f'<text x="{lx + 12}" y="{43}" font-size="13" fill="{t["muted"]}">{name}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main():
    result = run()
    docs = Path(__file__).resolve().parents[1] / "docs"
    for theme in THEMES:
        (docs / f"how-it-works-{theme}.svg").write_text(svg(theme, result), encoding="utf-8")
    print("written", ", ".join(f"how-it-works-{t}.svg" for t in THEMES))


if __name__ == "__main__":
    main()
