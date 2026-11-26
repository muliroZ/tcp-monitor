"""Servidor HTTP do laboratório (porta e backlog vêm da linha de comando)."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CORPO = b"ok\n"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # o servidor fecha a conexão após a resposta

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(CORPO)))
        self.end_headers()
        self.wfile.write(CORPO)

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--porta", type=int, required=True)
    ap.add_argument("--backlog", type=int, required=True)
    a = ap.parse_args()

    class Servidor(ThreadingHTTPServer):
        request_queue_size = a.backlog
        daemon_threads = True

    Servidor(("0.0.0.0", a.porta), Handler).serve_forever()


if __name__ == "__main__":
    main()
