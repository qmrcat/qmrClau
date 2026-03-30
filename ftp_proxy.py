#!/usr/bin/env python3
"""
qmrClau FTP Proxy
-----------------
Permet que la PWA del navegador accedeixi a servidors FTP.
El navegador no pot fer connexions TCP/FTP directes, per això
aquest script actua de pont entre la PWA i el servidor FTP.

Ús:
    python ftp_proxy.py

Manté aquest script en execució mentre uses l'opció FTP a la PWA.
La PWA ha d'estar servida des de http://localhost (no GitHub Pages)
per evitar restriccions de contingut mixt del navegador.

Accedeix a la PWA a: http://localhost:8766/app/
"""

import base64
import ftplib
import io
import json
import mimetypes
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PROXY_PORT = 8766
PWA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pwa")


class FTPProxyHandler(BaseHTTPRequestHandler):

    # ── CORS ──────────────────────────────────────────────────────────────
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    # ── GET ───────────────────────────────────────────────────────────────
    def do_GET(self):
        # Health check
        if self.path == "/ping":
            self._json(200, {"status": "ok", "app": "qmrClau FTP Proxy"})
            return

        # Serve PWA files at /app/
        if self.path.startswith("/app"):
            rel = self.path[4:] or "/"
            if rel == "/" or rel == "":
                rel = "/index.html"
            file_path = os.path.join(PWA_DIR, rel.lstrip("/"))
            if os.path.isfile(file_path):
                mime, _ = mimetypes.guess_type(file_path)
                with open(file_path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", mime or "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self._json(404, {"error": "File not found: " + rel})
            return

        self._json(404, {"error": "Not found"})

    # ── POST ──────────────────────────────────────────────────────────────
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(length))
        except Exception:
            self._json(400, {"error": "JSON invàlid"})
            return

        if self.path == "/download":
            self._handle_download(req)
        elif self.path == "/upload":
            self._handle_upload(req)
        else:
            self._json(404, {"error": "Ruta desconeguda"})

    # ── FTP helpers ───────────────────────────────────────────────────────
    def _ftp_connect(self, req):
        host     = req.get("host", "")
        port     = int(req.get("port", 21))
        username = req.get("username", "")
        password = req.get("password", "")
        tls      = req.get("tls", False)

        if not host:
            raise ValueError("El camp 'host' és obligatori")

        if tls:
            ftp = ftplib.FTP_TLS()
        else:
            ftp = ftplib.FTP()

        ftp.connect(host, port, timeout=20)
        ftp.login(username, password)
        if tls:
            ftp.prot_p()
        return ftp

    def _handle_download(self, req):
        try:
            ftp  = self._ftp_connect(req)
            path = req.get("path", "")
            buf  = io.BytesIO()
            ftp.retrbinary("RETR " + path, buf.write)
            ftp.quit()
            data = buf.getvalue()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except ftplib.error_perm as e:
            code = str(e)[:3]
            if code == "550":
                self._json(404, {"error": "Fitxer no trobat al servidor FTP: " + str(e)})
            else:
                self._json(403, {"error": "Error FTP: " + str(e)})
        except Exception as e:
            self._json(500, {"error": str(e)})

    def _handle_upload(self, req):
        try:
            ftp  = self._ftp_connect(req)
            path = req.get("path", "")
            data = base64.b64decode(req.get("data", ""))
            buf  = io.BytesIO(data)

            # Crear directoris intermedis si cal
            parts = path.replace("\\", "/").split("/")
            dir_path = "/".join(parts[:-1])
            if dir_path:
                dirs = dir_path.split("/")
                current = ""
                for d in dirs:
                    if not d:
                        continue
                    current = current + "/" + d if current else d
                    try:
                        ftp.mkd(current)
                    except ftplib.error_perm:
                        pass  # Ja existeix

            ftp.storbinary("STOR " + path, buf)
            ftp.quit()
            self._json(200, {"status": "ok"})
        except Exception as e:
            self._json(500, {"error": str(e)})

    # ── Helpers ───────────────────────────────────────────────────────────
    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Mostrar únicament les peticions POST per no omplir la consola
        if args and str(args[0]).startswith("POST"):
            print(f"[FTP Proxy] {fmt % args}")


def main():
    if not os.path.isdir(PWA_DIR):
        print(f"AVÍS: No s'ha trobat el directori de la PWA a: {PWA_DIR}")
        print("El servidor proxy funcionarà igualment, però no servirà la PWA.")

    print("=" * 55)
    print("  qmrClau FTP Proxy")
    print("=" * 55)
    print(f"  Proxy actiu a:  http://localhost:{PROXY_PORT}")
    print(f"  PWA disponible: http://localhost:{PROXY_PORT}/app/")
    print()
    print("  Manté aquesta finestra oberta mentre uses FTP.")
    print("  Prem Ctrl+C per aturar.")
    print("=" * 55)

    server = HTTPServer(("localhost", PROXY_PORT), FTPProxyHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nProxy aturat.")
        server.server_close()


if __name__ == "__main__":
    main()
