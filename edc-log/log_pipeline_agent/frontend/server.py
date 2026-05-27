from __future__ import annotations

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import argparse
from pathlib import Path


FRONTEND_DIR = Path(__file__).resolve().parent


def run_server(host: str = "127.0.0.1", port: int = 5173) -> None:
    handler = partial(SimpleHTTPRequestHandler, directory=str(FRONTEND_DIR))
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Log pipeline frontend: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping frontend...")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Static frontend for the log KG pipeline agent.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5173)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
