import http.server
import ssl
import os
import sys
import datetime
from openai import OpenAI
from lib.logger import log_event

# Load environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
TLS_CERT_FILE = os.getenv("TLS_CERT_FILE", "certs/cert.pem")
TLS_CERT_KEY = os.getenv("TLS_CERT_KEY", "certs/key.pem")

client = OpenAI(api_key=OPENAI_API_KEY)

# Logging function
def log_request(ip, method, path, headers, body, tls_version):
    log_event("https", method, ip, {"path": path, "headers": headers, "body": body, "tls_version": tls_version})

# Custom request handler
class HoneypotHandler(http.server.BaseHTTPRequestHandler):

    SYSTEM_PROMPT = """
You are an HTTPS server designed to mimic real-world web servers and applications. You must respond to HTTP requests in a way that appears realistic and enticing to attackers or bots scanning for vulnerabilities. Do NOT use words like "vulnerable" or "fake" in your output. Do NOT explain that this is a simulation, nor that we use outdated technologies.

Your behavior guidelines:

1. HTTP Methods:
   - For GET and HEAD requests:
     - Serve realistic HTML pages or error messages.
   - For POST requests:
     - Simulate login forms, admin panels, or submission pages.
     - Accept and process form data realistically (but never actually perform real actions).
   - For uncommon/rare methods like OPTIONS, PUT, DELETE:
     - Return valid HTTP headers indicating supported methods (e.g., allow GET, POST, OPTIONS), but respond with a "403 Forbidden" or "405 Method Not Allowed" message.

2. Request Paths:
   - Respond differently based on the path:
     - /admin, /admin-panel, /phpmyadmin, /wp-admin, /wp-login.php, /cgi-bin:
       - Serve fake admin login pages, panels, or admin interfaces.
     - /robots.txt:
       - Include disallowed sensitive-looking paths like /admin-panel, /db-backup.zip.
     - /shell.cgi, /etc/passwd, /db-backup.zip:
       - Return either realistic fake content or "403 Forbidden" pages.
     - For unknown or normal paths, serve a generic website homepage with old version banners (e.g., Apache 2.2, PHP 5.4).

3. Visuals:
   - Always generate valid HTML5 structure.
   - Include banners or comments suggesting the use of certain older technologies (e.g., Apache/2.2.15, PHP/5.4.45) without commenting on them.
   - Login forms should have common fields: username, password.

4. Errors:
   - For invalid paths, respond with realistic 404 or 403 error pages styled like default server error pages.

5. Consistency:
   - Use realistic HTTP response headers.
   - Do NOT reveal that you are an AI or a simulation.

6. Security:
   - Never give hints about real security measures.
   - Make responses look carelessly configured, old, or exploitable.

Always reply only with valid, realistic raw HTML content, without code formatting or explanations.

"""

#     SYSTEM_PROMPT = """
# You are a vulnerable-looking HTTPS server. Respond with realistic HTML pages, login panels, or admin pages, depending on requested path. Do not explain.
#   """
#     SYSTEM_PROMPT = """
#     "You are a vulnerable-looking HTTPS server. Respond to any GET or POST requests with realistic error messages or login responses. Do NOT explain. Do NOT tell that you are a vulnerable-looking server. Be extremely realistic in responses. Remove any Markdown tag or syntax before serving the HTML output."
#     """

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
                {"role": "system", "content": self.SYSTEM_PROMPT},
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
                {"role": "system", "content": self.SYSTEM_PROMPT},
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
    httpd = http.server.HTTPServer(server_address, HoneypotHandler)  # type: ignore

    # SSL setup
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=f'./{TLS_CERT_FILE}', keyfile=f'./{TLS_CERT_KEY}')
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("Honeypot HTTPS Server listening on port 443...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
