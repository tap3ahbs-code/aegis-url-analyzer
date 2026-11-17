"""Run the local URL analyzer with: python server.py"""

from __future__ import annotations

import json
import mimetypes
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from analyzer import InvalidURL, analyze_url
from threat_db import feed_status, lookup

ROOT = Path(__file__).resolve().parent / "web"
HOST = "127.0.0.1"
PORT = 8765


class Handler(BaseHTTPRequestHandler):
    def _json(self, status: int, data: dict):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path != "/api/analyze":
            return self._json(404, {"error": "Маршрут не найден."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 8192:
                return self._json(413, {"error": "Слишком большой запрос."})
            data = json.loads(self.rfile.read(length))
            result = analyze_url(data.get("url"))
            result["database"] = feed_status()
            result["database_match"] = lookup(result["normalized_url"])
            if result["database_match"]:
                result["score"] = 100
                result["level"] = "high"
                result["label"] = "Есть совпадение в базе"
                result["summary"] = "URL найден в базе PhishTank. Не открывайте его."
                result["indicators"].insert(0, {"code": "database_match", "points": 100, "title": "Совпадение с PhishTank", "detail": "Найдено точное совпадение URL в локальной базе. Дата снимка указана ниже."})
        except (json.JSONDecodeError, AttributeError):
            return self._json(400, {"error": "Неверный формат запроса."})
        except InvalidURL as exc:
            return self._json(400, {"error": str(exc)})
        return self._json(200, result)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/health":
            return self._json(200, {"status": "ok"})
        if path == "/api/status":
            return self._json(200, {"database": feed_status()})
        if path == "/":
            path = "/index.html"
        target = (ROOT / path.lstrip("/")).resolve()
        if not target.is_relative_to(ROOT) or not target.is_file():
            self.send_error(404)
            return
        body = target.read_bytes()
        mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") or mime == "application/javascript" else ""))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Do not print submitted URLs or browser requests into the console.
        pass


def main():
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError:
        print(f"Port {PORT} is busy. The service may already be running: http://{HOST}:{PORT}")
        return
    address = f"http://{HOST}:{PORT}"
    print(f"Service running: {address}")
    print("Press Ctrl+C to stop.")
    threading.Timer(0.7, lambda: webbrowser.open(address)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nService stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
