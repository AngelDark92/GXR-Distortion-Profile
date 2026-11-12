"""Serve the built optical LUT viewer over loopback HTTP.

The viewer is a single self-contained HTML file. Opening it straight from
disk works in most browsers, but some file-association and browser policies
block local pages, so this launcher serves the folder on 127.0.0.1 and opens
the page over HTTP instead. Nothing leaves the machine.

Usage:
    python -B tools/serve_viewer.py [--root viewer] [--file optics-viewer.html]
                                    [--port 0] [--no-browser]
"""

from __future__ import annotations

import argparse
import functools
import http.server
import os
import sys
import threading
import webbrowser

DEFAULT_ROOT = "viewer"
DEFAULT_FILE = "optics-viewer.html"


class Handler(http.server.SimpleHTTPRequestHandler):
    """Static handler that never caches, so a rebuilt viewer shows up."""

    def end_headers(self) -> None:  # noqa: D102 - stdlib hook
        self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: D102
        sys.stderr.write("  %s\n" % (fmt % args))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Serve the built viewer over loopback HTTP.")
    p.add_argument("--root", default=DEFAULT_ROOT, help="folder to serve (default: viewer)")
    p.add_argument("--file", default=DEFAULT_FILE, help="page to open (default: optics-viewer.html)")
    p.add_argument("--port", type=int, default=0, help="port, 0 picks a free one (default: 0)")
    p.add_argument("--bind", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = os.path.abspath(args.root)
    target = os.path.join(root, args.file)
    if not os.path.isfile(target):
        print("Viewer not found: %s" % target, file=sys.stderr)
        print("Build it first: python -B build_viewer.py data\\analysis.json -o viewer\\optics-viewer.html", file=sys.stderr)
        return 1

    handler = functools.partial(Handler, directory=root)
    try:
        httpd = http.server.ThreadingHTTPServer((args.bind, args.port), handler)
    except OSError as exc:
        print("Could not start the local server on %s:%s: %s" % (args.bind, args.port, exc), file=sys.stderr)
        return 1

    host = "127.0.0.1" if args.bind in ("0.0.0.0", "") else args.bind
    url = "http://%s:%d/%s" % (host, httpd.server_address[1], args.file.replace(os.sep, "/"))
    print("Serving %s" % root)
    print("  %s" % url)
    print("Close this window or press Ctrl+C to stop the server.")
    sys.stdout.flush()

    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
