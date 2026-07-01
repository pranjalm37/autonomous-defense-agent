"""
Minimal, dependency-free PDF writer.

Enough to render a paginated text report (headings, paragraphs, bullets, key/value
rows, rules) with Helvetica — no reportlab/weasyprint, so the export works
anywhere with zero install and is unit-testable. Content streams are uncompressed
for debuggability; the structure is a valid PDF 1.4 with an xref table.

This is intentionally small: production may swap in a richer HTML→PDF renderer,
but the exporter API (build bytes from an IncidentReport) stays the same.
"""
from __future__ import annotations

PAGE_W, PAGE_H, MARGIN = 612.0, 792.0, 54.0   # US Letter
FONT, FONT_BOLD = "F1", "F2"
CYAN = (0.13, 0.83, 0.93)
DARK = (0.10, 0.12, 0.18)
GREY = (0.40, 0.45, 0.52)


class PDFWriter:
    def __init__(self):
        self._pages: list[str] = []   # finished page content streams
        self._ops: list[str] = []     # current page operators
        self._y = PAGE_H - MARGIN

    # ── public flowables ──
    def heading(self, text: str, *, size: float = 15, color=CYAN, top_gap: float = 10):
        self._y -= top_gap
        self._ensure(size * 1.6)
        self._draw(text, MARGIN, size, FONT_BOLD, color)
        self._y -= size * 1.4

    def subheading(self, text: str, *, size: float = 11.5, color=DARK):
        self._ensure(size * 1.6)
        self._draw(text, MARGIN, size, FONT_BOLD, color)
        self._y -= size * 1.35

    def paragraph(self, text: str, *, size: float = 10, color=DARK, indent: float = 0, gap: float = 5):
        usable = PAGE_W - 2 * MARGIN - indent
        for line in _wrap(text, size, usable):
            self._ensure(size * 1.35)
            self._draw(line, MARGIN + indent, size, FONT, color)
            self._y -= size * 1.35
        self._y -= gap

    def bullet(self, text: str, *, size: float = 10, color=DARK):
        usable = PAGE_W - 2 * MARGIN - 16
        lines = _wrap(text, size, usable)
        for i, line in enumerate(lines):
            self._ensure(size * 1.35)
            prefix = "•  " if i == 0 else "   "
            self._draw(prefix + line, MARGIN + 6, size, FONT, color)
            self._y -= size * 1.35

    def kv(self, key: str, value: str, *, size: float = 10):
        self._ensure(size * 1.4)
        self._draw(key, MARGIN, size, FONT_BOLD, GREY)
        self._draw(value, MARGIN + 110, size, FONT, DARK)
        self._y -= size * 1.4

    def rule(self, *, color=CYAN):
        self._ensure(8)
        r, g, b = color
        self._ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG 0.7 w "
                         f"{MARGIN:.1f} {self._y:.1f} m {PAGE_W - MARGIN:.1f} {self._y:.1f} l S")
        self._y -= 8

    def spacer(self, h: float = 6):
        self._y -= h

    # ── internals ──
    def _ensure(self, needed: float):
        if self._y - needed < MARGIN:
            self._flush()

    def _flush(self):
        self._pages.append("\n".join(self._ops))
        self._ops = []
        self._y = PAGE_H - MARGIN

    def _draw(self, text: str, x: float, size: float, font: str, color):
        r, g, b = color
        self._ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg")
        self._ops.append(f"BT /{font} {size} Tf 1 0 0 1 {x:.2f} {self._y:.2f} Tm ({_esc(text)}) Tj ET")

    def build(self) -> bytes:
        if self._ops:
            self._flush()
        if not self._pages:
            self._pages = [""]

        objs: list[tuple[int, bytes]] = []
        page_ids: list[int] = []
        nid = 5
        for content in self._pages:
            cid, pid = nid, nid + 1
            nid += 2
            stream = content.encode("cp1252", "replace")
            objs.append((cid, b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"))
            page = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W:.0f} {PAGE_H:.0f}] "
                    f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {cid} 0 R >>")
            objs.append((pid, page.encode()))
            page_ids.append(pid)

        kids = " ".join(f"{p} 0 R" for p in page_ids)
        static = [
            (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
            (2, f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()),
            (3, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"),
            (4, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"),
        ]
        allobjs = sorted(static + objs, key=lambda o: o[0])

        out = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        offsets: dict[int, int] = {}
        for oid, body in allobjs:
            offsets[oid] = len(out)
            out += b"%d 0 obj\n" % oid + body + b"\nendobj\n"
        xref_pos = len(out)
        n = len(allobjs) + 1
        out += b"xref\n0 %d\n0000000000 65535 f \n" % n
        for oid in range(1, n):
            out += b"%010d 00000 n \n" % offsets[oid]
        out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (n, xref_pos)
        return out


# ── helpers ──
# Map glyphs not present in WinAnsi/CP1252 to ASCII equivalents.
_CHARMAP = {
    "→": "->", "←": "<-", "↔": "<->",
    "≥": ">=", "≤": "<=", "…": "...",
}


def _esc(s: str) -> str:
    for src, dst in _CHARMAP.items():
        if src in s:
            s = s.replace(src, dst)
    # CP1252 (WinAnsi) covers the bullet (•), em/en dashes, curly quotes, ·, etc.
    s = s.encode("cp1252", "replace").decode("cp1252")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(text: str, size: float, width: float, avg: float = 0.52) -> list[str]:
    """Greedy word-wrap using an average Helvetica advance width."""
    max_chars = max(8, int(width / (size * avg)))
    lines: list[str] = []
    cur = ""
    for word in (text or "").split():
        if len(cur) + len(word) + 1 <= max_chars:
            cur = (cur + " " + word).strip()
        else:
            if cur:
                lines.append(cur)
            while len(word) > max_chars:
                lines.append(word[:max_chars])
                word = word[max_chars:]
            cur = word
    if cur:
        lines.append(cur)
    return lines or [""]
