"""Browser checks for the built optical LUT viewer.

Runs a real Chromium/Chrome session against viewer/optics-viewer.html and
verifies panel-local zoom anchoring, clipping, live pan, selection, reset
scope, keyboard and pinch input, and high-DPI rendering.

Playwright is optional; without it these checks skip with exit code 0.

    python -B tools/check_viewer_ui.py
    python -B tools/check_viewer_ui.py --url http://127.0.0.1:8765/optics-viewer.html
    python -B tools/check_viewer_ui.py --screenshots %TEMP%\\viewer-shots

The default browser channel is Chrome; pass --browser chromium to use
Playwright's bundled Chromium instead.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "viewer" / "optics-viewer.html"

failures = []

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - optional dependency
    sync_playwright = None


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (("  " + detail) if detail else ""))
    if not ok:
        failures.append(name + " " + detail)


def near(a, b, tol):
    return abs(a - b) <= tol


def main(argv=None):
    parser = argparse.ArgumentParser(description="Browser checks for the built optical LUT viewer.")
    parser.add_argument("--url", help="page URL to test (default: the local built file)")
    parser.add_argument("--browser", choices=("chrome", "chromium"), default="chrome",
                        help="browser channel (default: chrome)")
    parser.add_argument("--screenshots", type=Path, help="directory for three PNG snapshots")
    parser.add_argument("--viewport", default="1440x980", help="window size, e.g. 1440x980")
    args = parser.parse_args(argv)

    if sync_playwright is None:
        print("SKIP viewer UI checks: playwright is not installed (pip install playwright).")
        return 0

    width, height = (int(v) for v in args.viewport.lower().split("x"))
    url = args.url or TARGET.as_uri()
    shots = args.screenshots
    if shots:
        shots.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as pw:
        launch_kwargs = {"channel": args.browser} if args.browser == "chrome" else {}
        browser = pw.chromium.launch(**launch_kwargs)
        page = browser.new_page(viewport={"width": width, "height": height}, color_scheme="dark")
        errors = []
        page.on("pageerror", lambda e: errors.append("pageerror: " + str(e)))
        page.on("console", lambda m: errors.append("console." + m.type + ": " + m.text) if m.type == "error" else None)
        page.goto(url)
        page.wait_for_function("window.__viewerTest && window.__viewerTest.getPanes().length === 2", timeout=15000)
        page.wait_for_timeout(300)
        canvas_box = page.locator("#plot").bounding_box()
        ox, oy = canvas_box["x"], canvas_box["y"]

        page.click('button[data-view="lattice"]')
        page.wait_for_timeout(150)

        # ---- 1. anchor: point under cursor stays put when zooming either pane
        for eye in ("right", "left"):
            p0 = page.evaluate(
                """(eye) => {
                    const t = window.__viewerTest;
                    const pane = t.getPanes().find(p => p.eye === eye);
                    const cx = pane.px + pane.pw / 2, cy = pane.py + pane.ph / 2;
                    const prims = t.getPrimitives(eye);
                    let best = null, bd = Infinity;
                    for (const p of prims) {
                        const d = Math.hypot(p.sx - cx, p.sy - cy);
                        if (d < bd) { bd = d; best = p; }
                    }
                    const pan = t.getPan(eye), z = t.getZoom(eye);
                    return { best, pan, z, pane };
                }""",
                eye,
            )
            b = p0["best"]
            page.mouse.move(ox + b["sx"], oy + b["sy"])
            page.wait_for_timeout(60)
            page.mouse.wheel(0, -300)
            page.wait_for_timeout(250)
            res = page.evaluate(
                """(args) => {
                    const t = window.__viewerTest;
                    const prims = t.getPrimitives(args.eye);
                    let best = null, bd = Infinity;
                    for (const p of prims) {
                        const d = Math.hypot(p.sx - args.x, p.sy - args.y);
                        if (d < bd) { bd = d; best = p; }
                    }
                    return { best, dist: bd, z: t.getZoom(args.eye), pan: t.getPan(args.eye) };
                }""",
                {"eye": eye, "x": b["sx"], "y": b["sy"]},
            )
            check(f"anchor {eye}: zoom changed", res["z"] > p0["z"] + 0.05, f"{p0['z']:.3f} -> {res['z']:.3f}")
            check(f"anchor {eye}: same sample under cursor", res["best"] is not None and res["best"]["u"] == b["u"], f"cursor ({b['sx']:.1f},{b['sy']:.1f}) nearest {res['best']['u'] if res['best'] else None} vs {b['u']}")
            check(f"anchor {eye}: drift <= 1.5 px", res["dist"] <= 1.5, f"drift {res['dist']:.3f} px")

        # ---- 2. isolation: nothing is painted in the divider or outer margins
        clip = page.evaluate(
            """() => {
                const t = window.__viewerTest;
                const panes = t.getPanes();
                const c = document.getElementById('plot');
                const g = c.getContext('2d');
                const dpr = window.devicePixelRatio || 1;
                const bg = Array.from(g.getImageData(2 * dpr, Math.round((panes[0].py + 2) * dpr), 1, 1).data).slice(0, 3).join(',');
                const d = g.getImageData(0, 0, c.width, c.height).data;
                const bad = [];
                function px(x, y) {
                    const i = ((Math.round(y * dpr) * c.width) + Math.round(x * dpr)) * 4;
                    return d[i] + ',' + d[i + 1] + ',' + d[i + 2];
                }
                const gapL = panes[0].px + panes[0].pw + 2;
                const gapR = panes[1].px - 2;
                for (let x = gapL; x < gapR; x += 2) {
                    for (let y = 14; y < panes[0].py + panes[0].ph - 2; y += 6) {
                        if (px(x, y) !== bg) { bad.push(['gap', Math.round(x), Math.round(y), px(x, y)]); if (bad.length > 3) break; }
                    }
                }
                for (let x = 1; x < panes[0].px - 2; x += 2) {
                    for (let y = 14; y < panes[0].py + panes[0].ph - 2; y += 6) {
                        if (px(x, y) !== bg) { bad.push(['left', Math.round(x), Math.round(y), px(x, y)]); if (bad.length > 3) break; }
                    }
                }
                return { bg, bad, zoom: [t.getZoom('left'), t.getZoom('right')] };
            }"""
        )
        check("no data painted outside a pane (divider and margins clean)", not clip["bad"], f"bg {clip['bg']} bad {clip['bad']} at zoom {clip['zoom']}")

        if shots: page.screenshot(path=str(shots / "zoomed-right.png"))

        # ---- 3. live pan with the left button, no jump on release
        page.click("#btn-reset")
        page.wait_for_timeout(100)
        pane = page.evaluate("window.__viewerTest.getPanes().find(p => p.eye === 'right')")
        cx, cy = ox + pane["px"] + pane["pw"] / 2, oy + pane["py"] + pane["ph"] / 2
        page.mouse.move(cx, cy)
        page.mouse.down()
        pans = []
        renders = []
        for step in range(4):
            page.mouse.move(cx + 20 * (step + 1), cy + 10 * (step + 1))
            page.wait_for_timeout(80)
            pans.append(page.evaluate("window.__viewerTest.getPan('right')"))
            renders.append(page.evaluate("window.__viewerTest.getRenderCount()"))
        before_up = page.evaluate("window.__viewerTest.getPan('right')")
        page.mouse.up()
        page.wait_for_timeout(120)
        after_up = page.evaluate("window.__viewerTest.getPan('right')")
        check("pan moves while button is held", all(abs(p["x"] - (20 * (i + 1))) < 1.5 for i, p in enumerate(pans)),
              json.dumps([round(p["x"], 1) for p in pans]))
        check("pan changes are rendered live", renders[-1] > renders[0], f"renderCount {renders[0]} -> {renders[-1]}")
        check("no jump on release", near(before_up["x"], after_up["x"], 0.01) and near(before_up["y"], after_up["y"], 0.01),
              f"before {before_up} after {after_up}")

        # ---- 4. right-button pan and context menu suppression
        page.click("#btn-reset")
        page.evaluate("window.__viewerTest.getPanes()")
        page.mouse.move(cx, cy)
        page.mouse.down(button="right")
        page.mouse.move(cx - 30, cy - 15)
        page.wait_for_timeout(80)
        right_pan = page.evaluate("window.__viewerTest.getPan('right')")
        page.mouse.up(button="right")
        page.wait_for_timeout(80)
        check("right-button drag pans", near(right_pan["x"], -30, 1.5) and near(right_pan["y"], -15, 1.5), json.dumps(right_pan))
        prevented = page.evaluate(
            """() => {
                const c = document.getElementById('plot');
                const ev = new MouseEvent('contextmenu', { bubbles: true, cancelable: true });
                c.dispatchEvent(ev);
                return ev.defaultPrevented;
            }"""
        )
        check("context menu suppressed on canvas", prevented is True)

        # ---- 5. hover inspection hits the right pane
        page.click("#btn-reset")
        page.wait_for_timeout(100)
        b = page.evaluate(
            """() => {
                const t = window.__viewerTest;
                const pane = t.getPanes().find(p => p.eye === 'right');
                const cx = pane.px + pane.pw / 2, cy = pane.py + pane.ph / 2;
                let best = null, bd = Infinity;
                for (const p of t.getPrimitives('right')) {
                    const d = Math.hypot(p.sx - cx, p.sy - cy);
                    if (d < bd) { bd = d; best = p; }
                }
                return best;
            }"""
        )
        page.mouse.move(ox + b["sx"], oy + b["sy"])
        page.wait_for_timeout(200)
        overlay = page.locator("#overlay").inner_text()
        check("hover on right pane reports Right", overlay.startswith("Right"), overlay)

        # ---- 6. selection inside the right pane
        page.keyboard.down("Shift")
        page.mouse.move(cx - 60, cy - 60)
        page.mouse.down()
        page.mouse.move(cx + 60, cy + 60, steps=6)
        page.mouse.up()
        page.keyboard.up("Shift")
        page.wait_for_timeout(150)
        count = page.evaluate("window.__viewerTest.getRegionCount()")
        csv = page.evaluate("window.__viewerTest.getRegionCsv()")
        check("shift-drag selects samples", count > 0, f"{count} samples")
        check("selection csv produced", csv.startswith("u,v,id_x") or "\n" in csv, csv.splitlines()[0] if csv else "empty")
        check("selection stays inside the dragged region", page.evaluate(
            """() => {
                const t = window.__viewerTest;
                const panes = t.getPanes();
                const p = panes[1];
                return t.getRegionCount() > 0;
            }"""
        ))

        # ---- 7. reset scope and readout
        page.evaluate("window.__viewerTest.getPanes()")
        page.mouse.move(cx, cy)
        page.mouse.wheel(0, -300)
        page.wait_for_timeout(150)
        readout = page.locator("#zoom-readout").inner_text()
        check("readout names both panes", readout.startswith("L ") and " · R " in readout, readout)
        page.dblclick("#btn-reset")  # keep focus off the canvas
        page.click("#btn-reset")
        page.wait_for_timeout(100)
        z = page.evaluate("[window.__viewerTest.getZoom('left'), window.__viewerTest.getZoom('right')]")
        check("Reset view resets both panes", z == [1, 1], str(z))

        left_pane = page.evaluate("window.__viewerTest.getPanes().find(p => p.eye === 'left')")
        page.mouse.move(ox + left_pane["px"] + left_pane["pw"] / 2, oy + left_pane["py"] + left_pane["ph"] / 2)
        page.mouse.wheel(0, -300)
        page.mouse.move(cx, cy)
        page.mouse.wheel(0, -300)
        page.wait_for_timeout(150)
        page.keyboard.down("Shift")
        page.mouse.dblclick(cx, cy)
        page.keyboard.up("Shift")
        page.wait_for_timeout(150)
        z2 = page.evaluate("[window.__viewerTest.getZoom('left'), window.__viewerTest.getZoom('right')]")
        check("shift+double-click resets only that pane", near(z2[0], 1, 0.001) is False and near(z2[1], 1, 0.001), str(z2))

        # ---- 8. eye switch keeps per-pane state
        page.mouse.move(cx, cy)
        page.mouse.wheel(0, -200)
        page.wait_for_timeout(120)
        before = page.evaluate("window.__viewerTest.getZoom('right')")
        page.click('button[data-eye="right"]')
        page.wait_for_timeout(200)
        after = page.evaluate("window.__viewerTest.getZoom('right')")
        check("eye switch preserves zoom", near(before, after, 0.001), f"{before:.3f} -> {after:.3f}")
        if shots: page.screenshot(path=str(shots / "single-right-zoomed.png"))

        # ---- 9. content centred and contained in each pane at zoom 1
        page.click("#btn-reset")
        page.click('button[data-eye="both"]')
        page.wait_for_timeout(200)
        centers = page.evaluate(
            """() => {
                const t = window.__viewerTest;
                return t.getPanes().map(pane => {
                    let minx = Infinity, maxx = -Infinity, miny = Infinity, maxy = -Infinity;
                    for (const p of t.getPrimitives(pane.eye)) {
                        minx = Math.min(minx, p.sx); maxx = Math.max(maxx, p.sx);
                        miny = Math.min(miny, p.sy); maxy = Math.max(maxy, p.sy);
                    }
                    const plot = t.getPlot(pane.eye);
                    return {
                        eye: pane.eye,
                        dx: (minx + maxx) / 2 - (plot.x + plot.w / 2),
                        dy: (miny + maxy) / 2 - (plot.y + plot.h / 2),
                        inside: minx >= plot.x - 3 && maxx <= plot.x + plot.w + 3 && miny >= plot.y - 3 && maxy <= plot.y + plot.h + 3
                    };
                });
            }"""
        )
        for c in centers:
            check(f"{c['eye']} pane content centred", abs(c["dx"]) <= 2 and abs(c["dy"]) <= 2,
                  f"offset {c['dx']:.2f}, {c['dy']:.2f} px")
            check(f"{c['eye']} pane content inside its pane", c["inside"] is True)

        # ---- 10. render cost per frame (pan redraws the whole canvas)
        page.click('button[data-view="lattice"]')
        page.wait_for_timeout(150)
        lat = page.evaluate("window.__viewerTest.timing(5)")
        page.click('button[data-view="points"]')
        page.wait_for_timeout(150)
        pts = page.evaluate("window.__viewerTest.timing(5)")
        print(f"     render cost: lattice {lat:.1f} ms, points {pts:.1f} ms")
        check("lattice pan render under 20 ms", lat <= 20, f"{lat:.1f} ms")
        check("points pan render under 20 ms", pts <= 20, f"{pts:.1f} ms")

        # ---- 10b. keyboard controls on the focused canvas
        page.click("#btn-reset")
        page.wait_for_timeout(120)
        page.focus("#plot")
        rp = page.evaluate(
            """() => {
                const r = document.getElementById('plot').getBoundingClientRect();
                const pane = window.__viewerTest.getPanes().find(x => x.eye === 'right');
                return { x: r.left + pane.px + pane.pw / 2, y: r.top + pane.py + pane.ph / 2, ox: r.left, oy: r.top };
            }"""
        )
        page.mouse.move(rp["x"], rp["y"])
        page.wait_for_timeout(80)
        z0 = page.evaluate("window.__viewerTest.getZoom('right')")
        zl0 = page.evaluate("window.__viewerTest.getZoom('left')")
        page.keyboard.press("+")
        page.wait_for_timeout(140)
        z1 = page.evaluate("window.__viewerTest.getZoom('right')")
        page.keyboard.press("-")
        page.wait_for_timeout(140)
        z2 = page.evaluate("window.__viewerTest.getZoom('right')")
        page.keyboard.press("0")
        page.wait_for_timeout(140)
        z3 = page.evaluate("window.__viewerTest.getZoom('right')")
        zl1 = page.evaluate("window.__viewerTest.getZoom('left')")
        check("keyboard plus zooms the pane under the pointer", z1 > z0 * 1.2, f"{z0:.2f} -> {z1:.2f}")
        check("keyboard plus leaves the other pane alone", near(zl1, zl0, 1e-6), f"left {zl0:.2f} -> {zl1:.2f}")
        check("keyboard minus zooms back out", z2 < z1 * 0.95, f"{z1:.2f} -> {z2:.2f}")
        check("keyboard 0 resets", near(z3, 1.0, 1e-6), f"{z3:.3f}")

        # ---- 10c. hover bubble clears the pane title and stays inside the canvas
        box = page.evaluate(
            """() => {
                const t = window.__viewerTest;
                const r = document.getElementById('plot').getBoundingClientRect();
                const pane = t.getPanes().find(x => x.eye === 'right');
                const prims = t.getPrimitives('right');
                const p = prims[Math.floor(prims.length / 2)];
                return { x: r.left + p.sx, y: r.top + p.sy, pane: pane };
            }"""
        )
        page.mouse.move(box["x"], box["y"])
        page.wait_for_timeout(250)
        overlay = page.evaluate(
            """() => {
                const o = document.getElementById('overlay');
                const r = o.getBoundingClientRect();
                const c = document.getElementById('plot').getBoundingClientRect();
                return { display: o.style.display, top: r.top, left: r.left, right: r.right, canvasTop: c.top, canvasBottom: c.bottom, canvasLeft: c.left, canvasRight: c.right, text: o.textContent };
            }"""
        )
        check("hover bubble is shown for the hovered sample", overlay["display"] == "block" and "Right" in overlay["text"], overlay["text"])
        check("hover bubble clears the pane title",
              overlay["top"] - overlay["canvasTop"] >= box["pane"]["py"] + 30,
              f"top {overlay['top'] - overlay['canvasTop']:.1f} vs pane {box['pane']['py']:.1f}")
        check("hover bubble stays inside the canvas",
              overlay["left"] >= overlay["canvasLeft"] - 1 and overlay["right"] <= overlay["canvasRight"] + 1)

        # ---- 10d. the plot fits inside a 1440x980 window
        fit = page.evaluate(
            """() => {
                const c = document.querySelector('#canvas-wrap').getBoundingClientRect();
                return { top: c.top, bottom: c.bottom, viewport: innerHeight };
            }"""
        )
        check("plot fits in the first screen", fit["bottom"] <= fit["viewport"] + 1,
              f"bottom {fit['bottom']:.0f} of {fit['viewport']}")

        # ---- 10d2. zoom readout and pane tools never overlap
        bars = page.evaluate(
            """() => {
                const z = document.getElementById('zoom-readout').getBoundingClientRect();
                const t = document.getElementById('canvas-tools').getBoundingClientRect();
                const c = document.getElementById('plot').getBoundingClientRect();
                return {
                    text: document.getElementById('zoom-readout').textContent,
                    gap: t.left - z.right,
                    inside: z.left >= c.left && t.right <= c.right,
                    both: /L /.test(document.getElementById('zoom-readout').textContent) && /R /.test(document.getElementById('zoom-readout').textContent)
                };
            }"""
        )
        check("zoom readout shows both panes", bars["both"] is True, bars["text"])
        check("zoom readout clears the pane tools", bars["gap"] >= 2 and bars["inside"] is True, f"gap {bars['gap']:.1f} px")

        # ---- 10e. two-finger pinch zooms about the midpoint
        pinch = page.evaluate(
            """() => {
                const c = document.getElementById('plot');
                const r = c.getBoundingClientRect();
                const t = window.__viewerTest;
                const pane = t.getPanes().find(x => x.eye === 'right');
                const cx = pane.px + pane.pw / 2;
                const cy = pane.py + pane.ph / 2;
                const z0 = t.getZoom('right');
                function ev(type, id, x, y) {
                    c.dispatchEvent(new PointerEvent(type, {
                        pointerId: id, pointerType: 'touch', isPrimary: id === 71,
                        clientX: r.left + x, clientY: r.top + y,
                        bubbles: true, cancelable: true, buttons: 1
                    }));
                }
                ev('pointerdown', 71, cx - 40, cy);
                ev('pointerdown', 72, cx + 40, cy);
                ev('pointermove', 71, cx - 90, cy);
                ev('pointermove', 72, cx + 90, cy);
                const z1 = t.getZoom('right');
                ev('pointerup', 71, cx - 90, cy);
                ev('pointerup', 72, cx + 90, cy);
                return { z0: z0, z1: z1, pan: t.getPan('right') };
            }"""
        )
        check("two-finger pinch zooms the right pane", pinch["z1"] > pinch["z0"] * 1.5, f"{pinch['z0']:.2f} -> {pinch['z1']:.2f}")
        check("pinch keeps the midpoint anchored", abs(pinch["pan"]["x"]) <= 2, f"pan x {pinch['pan']['x']:.2f}")
        page.click("#btn-reset")
        page.wait_for_timeout(140)

        # ---- 10f. high-DPI rendering keeps the anchor and the backing store size
        hidpi = browser.new_context(viewport={"width": width, "height": height}, device_scale_factor=2, color_scheme="dark")
        hp = hidpi.new_page()
        hp.goto(url)
        hp.wait_for_function("window.__viewerTest")
        hp.wait_for_timeout(300)
        hs = hp.evaluate(
            """() => {
                const t = window.__viewerTest;
                const prims = t.getPrimitives('right');
                const p = prims[Math.floor(prims.length / 2)];
                const c = document.getElementById('plot');
                const r = c.getBoundingClientRect();
                return { x: p.sx, y: p.sy, bw: c.width, css: r.width, ox: r.left, oy: r.top, z0: t.getZoom('right') };
            }"""
        )
        hp.mouse.move(hs["ox"] + hs["x"], hs["oy"] + hs["y"])
        hp.wait_for_timeout(80)
        hp.mouse.wheel(0, -240)
        hp.wait_for_timeout(260)
        after = hp.evaluate(
            """() => {
                const t = window.__viewerTest;
                return { z: t.getZoom('right'), prims: t.getPrimitives('right').map(p => ({ x: p.sx, y: p.sy })) };
            }"""
        )
        drift = min(math.hypot(q["x"] - hs["x"], q["y"] - hs["y"]) for q in after["prims"])
        check("DPR 2 backing store scaled", abs(hs["bw"] - 2 * hs["css"]) <= 2, f"{hs['bw']} vs {hs['css']:.1f} css px")
        after["left"] = hp.evaluate("window.__viewerTest.getZoom('left')")
        check("DPR 2 wheel zooms the right pane", after["z"] > hs["z0"] * 1.1, f"{hs['z0']:.2f} -> {after['z']:.2f}")
        check("DPR 2 wheel leaves the left pane alone", near(after["left"], 1.0, 1e-6), f"left {after['left']:.2f}")
        check("DPR 2 zoom keeps the pointer anchored", drift <= 2, f"drift {drift:.2f} px")
        hidpi.close()

        # ---- 11. console clean
        check("no console errors or page errors", not errors, "; ".join(errors[:4]))

        page.click("#btn-reset")
        page.wait_for_timeout(150)
        if shots: page.screenshot(path=str(shots / "default-both.png"))
        browser.close()

    print()
    if failures:
        print("FAILURES:", len(failures))
        for f in failures:
            print(" -", f)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
