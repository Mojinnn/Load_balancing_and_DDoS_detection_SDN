import http.server, sys, os, time, socket

SERVER_IP   = sys.argv[1] if len(sys.argv) > 1 else '10.0.0.1'
SERVER_NAME = sys.argv[2] if len(sys.argv) > 2 else 'h?'
PORT        = 80
TEST_FILE   = '/tmp/testfile_10mb'

if not os.path.exists(TEST_FILE):
    print(f'[{SERVER_NAME}] Create file test 10MB...')
    with open(TEST_FILE, 'wb') as f:
        f.write(os.urandom(10 * 1024 * 1024))
    print(f'[{SERVER_NAME}] File test is ready.')


class IdentifiableHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        # Serve large file to measure bandwidth
        if self.path == '/testfile_10mb' or self.path == '/testfile_10mb/':
            try:
                with open(TEST_FILE, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type',   'application/octet-stream')
                self.send_header('Content-Length', len(data))
                self.send_header('X-Server-IP',    SERVER_IP)
                self.send_header('X-Server-Name',  SERVER_NAME)
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
            return

        body = (
            f'<html><body>'
            f'<h2>Server: {SERVER_NAME} ({SERVER_IP})</h2>'
            f'<p>Time: {time.strftime("%H:%M:%S")}</p>'
            f'<!-- server_ip:{SERVER_IP} -->'
            f'</body></html>\n'
        ).encode()

        self.send_response(200)
        self.send_header('Content-Type',   'text/html')
        self.send_header('Content-Length', len(body))
        self.send_header('X-Server-IP',    SERVER_IP)
        self.send_header('X-Server-Name',  SERVER_NAME)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


if __name__ == '__main__':
    print(f'[SERVER] {SERVER_NAME} ({SERVER_IP}) listening :{PORT}')
    httpd = http.server.HTTPServer(('', PORT), IdentifiableHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f'\n[SERVER] {SERVER_NAME} stopped')