import requests
from flask import Flask, request
from stegnet.core.steg_base import StegNetBase
from stegnet.core.packet_utils import PacketUtils

class HTTPHandler(StegNetBase):
    def __init__(self, encryption_key):
        super().__init__(encryption_key)

    def send_covert_message(self, url, message):
        """Encodes a hidden message inside an HTTP User-Agent header."""
        encrypted_msg = self.encrypt(message)
        encoded_msg = PacketUtils.encode_payload(encrypted_msg).decode()
        headers = {"User-Agent": encoded_msg}
        requests.get(url, headers=headers)
        print(f"[*] Sent covert HTTP message to {url}")

    def start_http_listener(self, host="0.0.0.0", port=8080):
        """Starts an HTTP server to extract covert messages from incoming requests."""
        app = Flask(__name__)

        @app.route("/", methods=["GET"])
        def handle_request():
            if "User-Agent" in request.headers:
                encoded_msg = request.headers["User-Agent"]
                extracted_msg = PacketUtils.decode_payload(encoded_msg.encode())
                hidden_msg = self.decrypt(extracted_msg)
                if hidden_msg:
                    print(f"[+] Extracted HTTP message: {hidden_msg}")
            return "OK"

        print(f"[*] Listening for covert HTTP messages on {host}:{port}. Press Ctrl+C to stop.")
        try:
            app.run(host=host, port=port)
        except KeyboardInterrupt:
            print("\n[!] Sniffing stopped by user.")
