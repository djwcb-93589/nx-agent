from __future__ import annotations

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import argparse


STATIC_ROOT = Path(__file__).resolve().parent / "static"


class StaticFrontendHandler(SimpleHTTPRequestHandler):
    api_base = "http://127.0.0.1:8765"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

    def do_OPTIONS(self) -> None:
        if self.path.startswith("/api/"):
            self.send_response(204)
            self._send_cors_headers()
            self.end_headers()
            return
        super().do_OPTIONS()

    def do_GET(self) -> None:
        if self.path.startswith("/api/"):
            self._proxy_api_request()
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self.path.startswith("/api/"):
            self._proxy_api_request()
            return
        self.send_error(404)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def _proxy_api_request(self) -> None:
        target = f"{self.api_base.rstrip('/')}{self.path}"
        body = None
        if self.command in {"POST", "PUT", "PATCH"}:
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(length) if length else b""

        headers = {}
        content_type = self.headers.get("Content-Type")
        if content_type:
            headers["Content-Type"] = content_type
        accept = self.headers.get("Accept")
        if accept:
            headers["Accept"] = accept

        request = Request(target, data=body, headers=headers, method=self.command)
        try:
            with urlopen(request, timeout=None) as response:
                self.send_response(response.status)
                self._send_cors_headers()
                self._copy_proxy_headers(response)
                self.end_headers()
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except HTTPError as exc:
            payload = exc.read()
            self.send_response(exc.code)
            self._send_cors_headers()
            self._copy_proxy_headers(exc)
            self.end_headers()
            self.wfile.write(payload)
        except URLError as exc:
            payload = f'{{"error": "Backend API is unavailable: {exc.reason}"}}'.encode("utf-8")
            self.send_response(502)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def _copy_proxy_headers(self, response) -> None:
        blocked = {
            "connection",
            "content-encoding",
            "content-length",
            "date",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "server",
            "transfer-encoding",
            "upgrade",
        }
        for name, value in response.headers.items():
            if name.lower() not in blocked:
                self.send_header(name, value)

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Static frontend server for the log agent.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5173)
    parser.add_argument("--api_base", default="http://127.0.0.1:8765")
    args = parser.parse_args(argv)

    parsed_api = urlsplit(args.api_base)
    if parsed_api.scheme not in {"http", "https"} or not parsed_api.netloc:
        raise ValueError("--api_base must be an absolute http(s) URL")
    StaticFrontendHandler.api_base = args.api_base.rstrip("/")

    server = ThreadingHTTPServer((args.host, args.port), StaticFrontendHandler)
    print(f"Frontend static server: http://{args.host}:{args.port}", flush=True)
    print(f"Proxying /api to: {StaticFrontendHandler.api_base}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
