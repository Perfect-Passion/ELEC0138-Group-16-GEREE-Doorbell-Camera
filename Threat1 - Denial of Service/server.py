# server.py
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

PORT = 80

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Server received your request.")

with TCPServer(("", PORT), Handler) as httpd:
    print(f"[INFO] HTTP Server running on port {PORT}")
    httpd.serve_forever()
