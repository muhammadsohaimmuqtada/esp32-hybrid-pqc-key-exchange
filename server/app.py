import ssl
import http.server
import logging
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] TLS_SERVER: %(message)s', datefmt='%H:%M:%S')

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        logging.info(f"Received {len(post_data)} bytes from {self.client_address[0]}")
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
        
    def log_message(self, format, *args):
        pass # Suppress default logging

def main():
    server_address = ('0.0.0.0', 8443)
    httpd = http.server.HTTPServer(server_address, SimpleHTTPRequestHandler)
    
    # Configure TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # context.minimum_version = ssl.TLSVersion.TLSv1_3
    import os
    cert_path = "certs/server.crt"
    key_path = "certs/server.key"
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        logging.error(f"Certificates not found. Please generate them in {cert_path} and {key_path}.")
        return

    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    logging.info("Starting TLS 1.3 server on port 8443...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Server stopped.")

if __name__ == '__main__':
    main()
