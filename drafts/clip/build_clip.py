"""Builds the silent demo clip: real results, boxes around each point, Thai callouts.

Run from the repository root with .venv/bin/python, with `trustkit serve` running.
Output: drafts/clip/. Nothing here uploads anything, and only the listed cases are requested.
"""

import html
import json
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image

ROOT = Path("drafts")
FILES = ROOT / "clip-files"
OUT = ROOT / "clip"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PAGE = "http://127.0.0.1:18770"
W, H = 1920, 1080
FONT = "Thonburi, 'Helvetica Neue', sans-serif"
ACCENT = "#d6336c"
FADE = 0.3

# The right panel: 720 CSS px at 1.3 is about 940 px wide. The results table: 1200 CSS px at 1.6 is 1920.
RIGHT = {"x": 960, "y": 20, "w": 936, "h": 1040, "css": 720, "scale": 1.3}
TABLE = {"x": 0, "y": 0, "w": W, "h": 860, "css": 1200, "scale": 1.6}
LEFT_X, PDF_TOP = 56, 150
CALLOUT_LEFT = {"x": 56, "y": 690, "w": 840}
CALLOUT_TABLE = {"x": 260, "y": 890, "w": 1400}

COLLECT = """
<script>
const rect = e => { const r = e.getBoundingClientRect();
  return [r.left + scrollX, r.top + scrollY, r.width, r.height]; };
const out = {height: document.documentElement.scrollHeight};
const panels = [...document.querySelectorAll('.panel')];
panels.forEach((panel, i) => {
  out['verdict' + i] = rect(panel.querySelector('.verdict'));
  panel.querySelectorAll('li').forEach(li => {
    out[li.textContent.split(':')[0].replace(' ', '_') + i] = rect(li);
  });
});
document.querySelectorAll('thead th').forEach((th, i) => { out['th' + i] = rect(th); });
document.querySelectorAll('.run li').forEach(li => {
  if (li.textContent.includes('network route')) out.network = rect(li);
});
document.querySelectorAll('p').forEach(p => {
  if (p.textContent.includes('Cases withheld')) out.withheld = rect(p);
  if (p.textContent.includes('not a ranking')) out.ranking = rect(p);
});
document.body.setAttribute('data-rects', JSON.stringify(out));
</script></body>"""

# Keeps the three cards in one view. Raw output stays out, because it holds machine paths.
COMPACT = """<style>
main { padding: 8px 16px; } h1, .lead, .muted, details, p > a { display: none; }
.run li:not(:first-child) { display: none; }
.panel { margin-bottom: 12px; padding: 12px 16px; } .panel h2 { margin-bottom: 4px; }
.panel p { margin: 4px 0; } ul { margin: 4px 0; } li { margin: 2px 0; }
</style></head>"""


@dataclass
class Step:
    text: str
    # ("r", key) or ("r", key, key2) for a box around both, or ("l", line index) or ("l", "xml").
    boxes: list = field(default_factory=list)


CASES = {
    "A1": {
        "heading": "Signed, then left alone",
        "steps": [
            Step("เอกสารปกติ ลงนามแล้วไม่มีการแก้ไข ยอดบนหน้าคือ 1000.00", [("l", 2)]),
            Step("ทั้งสามเครื่องมือตอบ VALID", [("r", "verdict0"), ("r", "verdict1"), ("r", "verdict2")]),
        ],
    },
    "C4": {
        "heading": "Changed after signing",
        "steps": [
            Step("ตอนลงนามยอดคือ 1000.00 แต่มีการแก้ไขต่อท้ายหลังลงนาม ยอดบนหน้าจึงกลายเป็น 9000.00", [("l", 2)]),
            Step("pyHanko ตอบ INVALID และจัดระดับการแก้ไขนี้เป็น OTHER", [("r", "verdict0"), ("r", "modification_level0")]),
            Step("pdfsig ให้ลายเซ็นผ่าน แต่รายงานว่าลายเซ็นไม่ครอบคลุมทั้งไฟล์", [("r", "verdict1"), ("r", "coverage1")]),
            Step("DSS ให้ลายเซ็นผ่าน พร้อมรายงานการเปลี่ยนแปลงและคำเตือน", [("r", "verdict2"), ("r", "modifications2"), ("r", "warnings2")]),
            Step("ข้อมูลมีอยู่ในทุกเครื่องมือ แต่ถ้าอ่านแค่บรรทัดบนสุด อาจพลาดได้", [("r", "verdict0"), ("r", "verdict1"), ("r", "verdict2")]),
        ],
    },
    "D1": {
        "heading": "A name on the page",
        "steps": [
            Step("หน้าเอกสารเขียนว่าลงนามโดย Example Other Person", [("l", 3)]),
            Step("แต่ชื่อในใบรับรองคือ TEST ONLY Signer ไม่ตรงกับหน้าเอกสาร", [("r", "signer_subject0"), ("r", "signer_subject1"), ("r", "signer_subject2")]),
            Step("ทั้งสามเครื่องมือตอบ VALID ซึ่งถูกต้อง เพราะลายเซ็นไม่ได้เทียบข้อความบนหน้า คนอ่านต้องดูชื่อในใบรับรองเอง", [("r", "verdict0"), ("r", "verdict1"), ("r", "verdict2")]),
        ],
    },
    "F3": {
        "heading": "Disagrees from the start",
        "steps": [
            Step("หน้าเอกสารเขียนยอด 1000.00", [("l", 2)]),
            Step("แต่ XML ที่แนบเขียน 9000.00 สองค่านี้ขัดกันตั้งแต่ก่อนลงนาม", [("l", "xml")]),
            Step("ไม่มีอะไรแก้หลังลงนาม ทุกเครื่องมือจึงตอบ VALID ลายเซ็นยืนยันว่าไฟล์ไม่เปลี่ยน ไม่ได้ยืนยันว่าเนื้อหาถูกต้อง", [("r", "verdict0"), ("r", "verdict1"), ("r", "verdict2")]),
        ],
    },
}
TABLE_INTRO = [
    Step("ไฟล์ทั้งหมดเป็น PDF สังเคราะห์ ใช้ใบรับรองทดสอบที่ใช้แล้วทิ้ง และตรวจโดยไม่มีเครือข่ายออกข้างนอก", ["network"]),
    Step("ผลที่คาดหวังของแต่ละเคสถูกกำหนดไว้ก่อนรันจริง", ["th1"]),
    Step("pyHanko, pdfsig และ EU DSS ตรวจไฟล์เดียวกัน", ["th3", "th4", "th5"]),
]
TABLE_OUTRO = [
    Step("ชุดนี้มี 20 เคส ตารางนี้แสดง 19 เคส และงดแสดง 1 เคส", ["withheld"]),
    Step("ผลเป็นพฤติกรรมตามเวอร์ชันและการตั้งค่าที่ทดสอบ ไม่ใช่การจัดอันดับเครื่องมือ", ["ranking"]),
]


def run(*command) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def chrome(*args) -> str:
    return run(
        CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
        f"--user-data-dir={tempfile.mkdtemp(prefix='clip-chrome-')}", *args,
    )


def shot(source: Path, target: Path, width: int, height: int, scale: float = 1) -> None:
    chrome(f"--force-device-scale-factor={scale}", f"--window-size={width},{height}",
           f"--screenshot={target.resolve()}", source.resolve().as_uri())


def capture(work: Path, name: str, page: str, view: dict) -> tuple[Path, dict]:
    """Screenshots a page, and reads where its elements are."""
    source = work / f"{name}.html"
    probe = work / f"{name}-probe.html"
    page = page.replace('<html lang="en">', '<html lang="en" data-theme="light">')
    source.write_text(page, encoding="utf-8")
    probe.write_text(page.replace("</body>", COLLECT), encoding="utf-8")
    dom = chrome(f"--window-size={view['css']},3000", "--dump-dom", probe.resolve().as_uri())
    rects = json.loads(html.unescape(re.search(r'data-rects="([^"]*)"', dom).group(1)))
    image = work / f"{name}.png"
    shot(source, image, view["css"], int(rects["height"]) + 120, view["scale"])
    return image, rects


def result_page(case: str) -> str:
    request = urllib.request.Request(
        f"{PAGE}/sample", data=urllib.parse.urlencode({"case": case}).encode()
    )
    with urllib.request.urlopen(request, timeout=280) as response:
        return response.read().decode().replace("</head>", COMPACT)


def pdf_image(work: Path, name: str) -> tuple[Path, list[tuple[int, int]]]:
    """The page's text, enlarged, and the rows of each text line."""
    base = work / f"pdf-{name}.png"
    run("sips", "-s", "format", "png", "-Z", "2600", str(FILES / f"{name}.pdf"), "--out", str(base))
    target = work / f"pdf-{name}-top.png"
    run("magick", str(base), "-background", "white", "-alpha", "remove", "-fuzz", "5%", "-trim", "+repage",
        "-bordercolor", "white", "-border", "60", "-resize", "840x",
        "-bordercolor", "#dcdad5", "-border", "2", str(target))
    with Image.open(target) as image:
        gray = image.convert("L")
        width, height = gray.size
        rows = [
            gray.crop((6, y, width - 6, y + 1)).getextrema()[0] < 140 for y in range(4, height - 4)
        ]
    lines, start = [], None
    for y, dark in enumerate(rows, start=4):
        if dark and start is None:
            start = y
        elif not dark and start is not None:
            lines.append((start, y))
            start = None
    return target, lines


def view_offset(boxes: list[list[float]], view: dict, total: float) -> float:
    top = min(box[1] for box in boxes) * view["scale"]
    bottom = max(box[1] + box[3] for box in boxes) * view["scale"]
    if bottom - top > view["h"] - 40:
        raise ValueError(f"boxes do not fit: {top} to {bottom}")
    offset = max(bottom - view["h"] + 40, 0)
    offset = min(offset, max(top - 30, 0))
    return min(offset, max(total * view["scale"] - view["h"], 0))


def box_div(x, y, width, height) -> str:
    return (
        f'<div style="position:absolute;left:{x - 8}px;top:{y - 6}px;width:{width + 16}px;'
        f"height:{height + 12}px;border:5px solid {ACCENT};border-radius:8px;box-sizing:border-box;"
        f'box-shadow:0 0 0 3px rgba(255,255,255,.85)"></div>'
    )


def callout_div(text: str, spot: dict) -> str:
    return (
        f'<div style="position:absolute;left:{spot["x"]}px;top:{spot["y"]}px;width:{spot["w"]}px;'
        f"background:#1f2328;color:#fff;border-left:10px solid {ACCENT};border-radius:8px;"
        f'padding:22px 28px;box-sizing:border-box;font-size:36px;line-height:1.5">{html.escape(text)}</div>'
    )


def connector(start: tuple[float, float], end: tuple[float, float]) -> str:
    return (
        f'<svg width="{W}" height="{H}" style="position:absolute;left:0;top:0">'
        f'<line x1="{start[0]}" y1="{start[1]}" x2="{end[0]}" y2="{end[1]}" stroke="{ACCENT}" stroke-width="5"/>'
        f'<circle cx="{end[0]}" cy="{end[1]}" r="9" fill="{ACCENT}"/></svg>'
    )


def frame(work: Path, name: str, body: str) -> Path:
    source = work / f"frame-{name}.html"
    source.write_text(
        f"""<!doctype html><meta charset="utf-8"><style>
html,body {{ margin:0; width:{W}px; height:{H}px; overflow:hidden; background:#fbfaf8;
  color:#1f2328; font-family:{FONT}; }}
b {{ font-weight:700; }}
</style>{body}""",
        encoding="utf-8",
    )
    target = work / f"frame-{name}.png"
    shot(source, target, W, H)
    with Image.open(target) as image:
        if image.size != (W, H):
            image.crop((0, 0, W, H)).save(target)
    return target


def image_in_view(image: Path, view: dict, offset: float) -> str:
    return (
        f'<div style="position:absolute;left:{view["x"]}px;top:{view["y"]}px;width:{view["w"]}px;'
        f'height:{view["h"]}px;overflow:hidden"><img src="{image.resolve().as_uri()}" '
        f'style="position:absolute;left:0;top:{-offset}px;width:{view["w"]}px"></div>'
    )


def case_frames(work: Path, case: str, spec: dict) -> list[tuple[Path, str]]:
    pdf, lines = pdf_image(work, case)
    with Image.open(pdf) as image:
        pdf_h = image.size[1]
    result, rects = capture(work, f"result-{case}", result_page(case), RIGHT)
    note_y = PDF_TOP + pdf_h + 20
    xml = ""
    if case == "F3":
        xml = (
            f'<div style="position:absolute;left:{LEFT_X}px;top:{note_y}px;font-size:32px">'
            "Embedded XML: <code>&lt;amount&gt;9000.00&lt;/amount&gt;</code></div>"
        )
    left = (
        f'<div style="position:absolute;left:{LEFT_X}px;top:48px;font-size:28px;color:#5d646d">{case}.pdf</div>'
        f'<div style="position:absolute;left:{LEFT_X}px;top:86px;font-size:40px;font-weight:700">'
        f'{html.escape(spec["heading"])}</div>'
        f'<img src="{pdf.resolve().as_uri()}" style="position:absolute;left:{LEFT_X}px;top:{PDF_TOP}px;width:844px">'
        f"{xml}"
    )
    frames = []
    for number, step in enumerate(spec["steps"]):
        right_keys = [box[1] for box in step.boxes if box[0] == "r"]
        offset = (
            view_offset([rects[key] for key in right_keys], RIGHT, rects["height"]) if right_keys else 0
        )
        marks = []
        for box in step.boxes:
            if box[0] == "r":
                x, y, width, height = rects[box[1]]
                scale = RIGHT["scale"]
                marks.append((RIGHT["x"] + x * scale, RIGHT["y"] + y * scale - offset, width * scale, height * scale))
            elif box[1] == "xml":
                marks.append((LEFT_X - 4, note_y, 720, 50))
            else:
                top, bottom = lines[box[1]]
                marks.append((LEFT_X + 30, PDF_TOP + top, 700, bottom - top))
        first = marks[0]
        if first[0] < W / 2:
            line = connector((CALLOUT_LEFT["x"] + 120, CALLOUT_LEFT["y"]), (first[0] + 100, first[1] + first[3] + 6))
        else:
            line = connector((CALLOUT_LEFT["x"] + CALLOUT_LEFT["w"], CALLOUT_LEFT["y"] + 50), (first[0] - 8, first[1] + first[3] / 2))
        body = (
            left
            + image_in_view(result, RIGHT, offset)
            + "".join(box_div(*mark) for mark in marks)
            + line
            + callout_div(step.text, CALLOUT_LEFT)
        )
        frames.append((frame(work, f"{case}-{number}", body), step.text))
    return frames


def table_frames(work: Path, name: str, steps: list[Step], image: Path, rects: dict) -> list[tuple[Path, str]]:
    frames = []
    scale = TABLE["scale"]
    for number, step in enumerate(steps):
        chosen = [rects[key] for key in step.boxes]
        offset = view_offset(chosen, TABLE, rects["height"])
        marks = [(x * scale, y * scale - offset, w * scale, h * scale) for x, y, w, h in chosen]
        target = marks[len(marks) // 2]
        line = connector(
            (CALLOUT_TABLE["x"] + CALLOUT_TABLE["w"] / 2, CALLOUT_TABLE["y"]),
            (target[0] + target[2] / 2, target[1] + target[3] + 6),
        )
        body = (
            image_in_view(image, TABLE, offset)
            + "".join(box_div(*mark) for mark in marks)
            + line
            + callout_div(step.text, CALLOUT_TABLE)
        )
        frames.append((frame(work, f"{name}-{number}", body), step.text))
    return frames


def text_slide(work: Path, name: str, body: str, reading: str) -> tuple[Path, str]:
    return frame(work, name, body), reading


def duration_for(text: str) -> float:
    return max(3.5, 1.5 + len(text) * 0.075)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="clip-") as temp:
        work = Path(temp)
        table, rects = capture(
            work, "table", (ROOT / "results-clip.html").read_text(encoding="utf-8"), TABLE
        )
        title = """
<div style="position:absolute;left:120px;right:120px;top:290px">
<div style="font-size:82px;font-weight:700;line-height:1.15">PDF Signature Trust Test Kit</div>
<div style="font-size:50px;margin-top:40px;line-height:1.5">"ลายเซ็นตรวจผ่าน" กับ "เอกสารนี้เชื่อถือได้" เป็นคนละคำถาม</div>
<div style="font-size:32px;color:#5d646d;margin-top:36px">ชุดทดสอบนี้แสดงว่าลายเซ็นตอบคำถามอะไรได้ และตอบอะไรไม่ได้</div>
</div>"""
        end = """
<div style="position:absolute;left:120px;right:120px;top:150px">
<div style="font-size:56px;font-weight:700;line-height:1.45">ลายเซ็นตอบว่าไฟล์เปลี่ยนไหมและใครลงนาม<br>จะเชื่อเอกสารได้หรือไม่ ต้องดูมากกว่านั้น</div>
<div style="font-size:32px;line-height:1.75;margin-top:56px;color:#3a4048">
Synthetic test files and throw-away keys only<br>
DSS 6.5.1 | pdfsig 24.02.0 in the table, 26.04.0 in the case results | pyHanko 0.38.0<br>
Behavior per version and configuration. Not a ranking of tools.<br>
Not a legal or compliance verdict. Not an e-Tax conformance test.<br>
A disagreement with the expected verdict is not by itself a defect in a tool.
</div></div>"""
        frames = [text_slide(work, "title", title, "x" * 50)]
        frames += table_frames(work, "intro", TABLE_INTRO, table, rects)
        for case, spec in CASES.items():
            frames += case_frames(work, case, spec)
        frames += table_frames(work, "outro", TABLE_OUTRO, table, rects)
        frames.append(text_slide(work, "end", end, "x" * 110))

        inputs: list[str] = []
        durations = [duration_for(text) for _, text in frames]
        for (image, _), length in zip(frames, durations):
            inputs += ["-loop", "1", "-t", f"{length + FADE:.2f}", "-i", str(image)]
        chain, current, elapsed = "", "0:v", durations[0]
        for number in range(1, len(frames)):
            chain += (
                f"[{current}][{number}:v]xfade=transition=fade:duration={FADE}:offset={elapsed:.2f}[v{number}];"
            )
            current = f"v{number}"
            elapsed += durations[number]
        target = OUT / "pdf-signature-trust-demo.mp4"
        run("ffmpeg", "-y", "-v", "error", *inputs, "-filter_complex",
            f"{chain}[{current}]format=yuv420p,fps=30[out]", "-map", "[out]", "-an",
            "-c:v", "libx264", "-crf", "20", "-preset", "medium", "-movflags", "+faststart", str(target))

        checks = OUT / "check-frames"
        checks.mkdir(exist_ok=True)
        for number, (image, _) in enumerate(frames):
            run("magick", str(image), "-resize", "960x", str(checks / f"{number:02d}.png"))
        print(target, f"{sum(durations):.1f}s", len(frames), "steps")


if __name__ == "__main__":
    main()
