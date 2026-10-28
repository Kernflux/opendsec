"""Render a `script --log-timing` recording as an animated SVG.

    script -q -c ./play.sh --log-out demo.out --log-timing demo.tm
    python3 render.py demo.out demo.tm > demo.svg
    python3 render.py demo.out demo.tm 12.5 > still.svg   # the screen at 12.5 s

Understands what play.sh prints: text, CR/LF and SGR colours (bold, dim,
green). Each version of a screen row is one <text> shown for its time span,
so the file stays small; the animation loops after a pause at the end.
"""
import html
import re
import sys

COLS, ROWS = 92, 27
CW, LH, PAD = 8.4, 18, 14          # char width, line height, padding (px)
HOLD = 4.0                         # seconds the last screen stays
COLORS = {"32": "#7ee787"}


def events(out, tm):
    data = open(out, "rb").read()
    data = data[data.index(b"\n") + 1:]          # "Script started ..." header
    t, pos = 0.0, 0
    for line in open(tm):
        f = line.split()
        if len(f) == 3 and f[0] != "O":      # advanced format: inputs, signals
            continue
        delay, n = f[-2:]
        t += float(delay)
        yield t, data[pos:pos + int(n)].decode("utf-8", "replace")
        pos += int(n)


def screens(evs):
    """Yield (time, rows) after each output chunk; a row is [(text, style)]."""
    rows, r, c, style = [[]], 0, 0, ()
    for t, s in evs:
        for tok in re.findall(r"\x1b\[[0-9;]*[A-Za-z]|\r|\n|[^\x1b\r\n]+", s):
            if tok == "\n":
                r, c = r + 1, 0
                if r == len(rows):
                    rows.append([])
                if len(rows) > ROWS:
                    rows.pop(0)
                    r -= 1
            elif tok == "\r":
                c = 0
            elif tok.startswith("\x1b["):
                if tok[-1] == "m":
                    codes = tok[2:-1].split(";")
                    style = () if codes in ([""], ["0"]) else style + tuple(codes)
            else:
                row = rows[r]
                text = "".join(x for x, _ in row)
                if c < len(text):        # overwrite from c: keep it simple
                    keep, n = [], 0
                    for x, st in row:
                        if n + len(x) <= c:
                            keep.append((x, st))
                        elif n < c:
                            keep.append((x[:c - n], st))
                        n += len(x)
                    rows[r] = row = keep
                row.append((tok, style))
                c += len(tok)
        yield t, [tuple(x) for x in rows]


def tspans(row):
    merged = []
    for text, st in row:
        if merged and merged[-1][1] == st:
            merged[-1] = (merged[-1][0] + text, st)
        else:
            merged.append((text, st))
    out = []
    for text, st in merged:
        attrs = ""
        if "1" in st:
            attrs += ' font-weight="bold"'
        if "2" in st:
            attrs += ' opacity=".55"'
        for code, col in COLORS.items():
            if code in st:
                attrs += f' fill="{col}"'
        out.append(f"<tspan{attrs}>{html.escape(text)}</tspan>")
    return "".join(out)


def main(out, tm, at=None):
    shots = list(screens(events(out, tm)))
    end = shots[-1][0] + HOLD
    spans = {}        # (row index, row) -> list of [start, stop]
    live = {}
    for i, (t, rows) in enumerate(shots):
        now = {(k, row) for k, row in enumerate(rows) if row}
        for key in list(live):
            if key not in now:
                spans.setdefault(key, []).append((live.pop(key), t))
        for key in now:
            live.setdefault(key, t)
    for key, start in live.items():
        spans.setdefault(key, []).append((start, end))

    w, h = COLS * CW + 2 * PAD, ROWS * LH + 2 * PAD + 22
    css, body = [], []
    for n, ((k, row), windows) in enumerate(sorted(spans.items(), key=lambda kv: kv[1][0][0])):
        for m, (a, b) in enumerate(windows):
            if at is not None and not a <= float(at) < b:
                continue
            name = f"k{n}_{m}"
            pa, pb = 100 * a / end, 100 * b / end
            css.append(f"@keyframes {name}{{0%,{pa:.3f}%{{visibility:hidden}}"
                       f"{pa:.3f}%,{pb:.3f}%{{visibility:visible}}"
                       f"{min(pb + 0.001, 100):.3f}%,100%{{visibility:hidden}}}}"
                       f".{name}{{animation:{name} {end:.2f}s step-end infinite}}"
                       if at is None else f".{name}{{visibility:visible}}")
            y = PAD + 22 + LH * (k + 1) - 4
            body.append(f'<text class="{name}" x="{PAD}" y="{y}" xml:space="preserve">{tspans(row)}</text>')
    print(f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="{h:.0f}" viewBox="0 0 {w:.0f} {h:.0f}" role="img" aria-label="OpenDsec demo: quickstart, then a microVM runs print(6*7) and forks">
<style>text{{visibility:hidden;font:13.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;fill:#d6d6d6}}{"".join(css)}</style>
<rect width="100%" height="100%" rx="8" fill="#16181d"/>
<circle cx="20" cy="16" r="5" fill="#ff5f57"/><circle cx="38" cy="16" r="5" fill="#febc2e"/><circle cx="56" cy="16" r="5" fill="#28c840"/>
{chr(10).join(body)}
</svg>''')


if __name__ == "__main__":
    main(*sys.argv[1:4])
