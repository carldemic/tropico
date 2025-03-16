import http.server
import ssl
import os
from openai import OpenAI

# Load OpenAI API key & model from environment
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")

client = OpenAI(api_key=OPENAI_API_KEY)

# Basic request handler
class LLMRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Only serve root page, else 404
        if self.path != '/':
            self.send_error(404, "Not Found")
            return

        # Query LLM for HTML content
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a web server. Serve a realistic, valid HTML5 page with a simple greeting and title. Do not explain."},
                {"role": "user", "content": "Serve homepage HTML."}
            ]
        )

        html_content = response.choices[0].message.content

        # Send HTTP headers
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        # Send HTML body
        self.wfile.write(html_content.encode('utf-8'))

# HTTPS server setup
def run_server():
    server_address = ('', 443)
    httpd = http.server.HTTPServer(server_address, LLMRequestHandler)

    # Modern TLS context setup
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='./localhost.pem', keyfile='./localhost-key.pem')

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("HTTPS server listening on port 443...")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
