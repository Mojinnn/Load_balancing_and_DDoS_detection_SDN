import http.server, sys, time, os

SERVER_IP   = sys.argv[1] if len(sys.argv) > 1 else '10.0.0.1'
SERVER_NAME = sys.argv[2] if len(sys.argv) > 2 else 'h?'
DELAY       = float(sys.argv[3]) if len(sys.argv) > 3 else 3.0
PORT        = 80

class SlowHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(DELAY)
        body = (
            f'<html><body>'
            f'<h2>SLOW Server: {SERVER_NAME} ({SERVER_IP})</h2>'
            f'<p>Delay: {DELAY}s</p>'
            f'<!-- server_ip:{SERVER_IP} -->'
            f'</body></html>\n'
        ).encode()
        self.send_response(200)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

print(f'[SLOW SERVER] {SERVER_NAME} ({SERVER_IP}) delay={DELAY}s port={PORT}')
http.server.HTTPServer(('', PORT), SlowHandler).serve_forever()
