import http.server
import ssl
import os
import datetime
from openai import OpenAI

# Load environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
LOG_FILE = os.getenv("LOG_FILE", "honeypot-https.log")
TLS_CERT_FILE = os.getenv("TLS_CERT_FILE", "cert.pem")
TLS_CERT_KEY = os.getenv("TLS_CERT_KEY", "key.pem")

client = OpenAI(api_key=OPENAI_API_KEY)

# Logging function
def log_request(ip, method, path, headers, body, tls_version):
    with open(LOG_FILE, 'a') as log:
        log.write(f"{datetime.datetime.now(datetime.UTC).isoformat()} | IP: {ip} | TLS: {tls_version}\n")
        log.write(f"Method: {method} Path: {path}\n")
        log.write(f"Headers: {headers}\n")
        if body:
            log.write(f"Body: {body}\n")
        log.write("-" * 60 + "\n")

# Custom request handler
class HoneypotHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Log request
        ip = self.client_address[0]
        headers = dict(self.headers)
        log_request(ip, "GET", self.path, headers, None, self.request_version)

        # robots.txt trap
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            traps = "Disallow: /admin\nDisallow: /db-backup.zip\n"
            self.wfile.write(traps.encode())
            return

        # Generate fake page
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a vulnerable-looking HTTPS server. Respond with realistic HTML pages, login panels, or admin pages, depending on requested path. Do not explain."},
                {"role": "user", "content": f"Serve HTML page for path: {self.path}"}
            ]
        )
        html_content = response.choices[0].message.content.replace('```html', '').replace('```', '')

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html_content.encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else b''

        # Log request
        ip = self.client_address[0]
        headers = dict(self.headers)
        log_request(ip, "POST", self.path, headers, post_data.decode(), self.request_version)

        # Fake login page handler
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a vulnerable-looking HTTPS server. Respond to any GET or POST requests with realistic error messages or login responses. Do not explain. Remove any Markdown tag or syntax before serving the HTML."},
                {"role": "user", "content": f"POST request to path {self.path} with body {post_data.decode()}"}
            ]
        )
        reply = response.choices[0].message.content

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(reply.encode())

def run():
    server_address = ('', 443)
    httpd = http.server.HTTPServer(server_address, HoneypotHandler)

    # SSL setup
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=f'./{TLS_CERT_FILE}', keyfile=f'./{TLS_CERT_KEY}')
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("Honeypot HTTPS Server listening on port 443...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
