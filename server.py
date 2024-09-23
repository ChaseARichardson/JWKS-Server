from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

# Define the hostname and server port
host_name = "localhost"
server_port = 8080

# Generate a private key for signing JWTs
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
# Generate an expired private key
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Serialize the private key to PEM format for use in JWT signing
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
# Serialize the expired private key to PEM format
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Get the private numbers of the generated private key for JWKS
numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length for hex representation
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    # Base64 URL-safe encoding without padding
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    # Handle PUT requests (not allowed)
    def do_PUT(self):
        self.send_response(405)  # Method Not Allowed
        self.end_headers()
        return

    # Handle PATCH requests (not allowed)
    def do_PATCH(self):
        self.send_response(405)  # Method Not Allowed
        self.end_headers()
        return

    # Handle DELETE requests (not allowed)
    def do_DELETE(self):
        self.send_response(405)  # Method Not Allowed
        self.end_headers()
        return

    # Handle HEAD requests (not allowed)
    def do_HEAD(self):
        self.send_response(405)  # Method Not Allowed
        self.end_headers()
        return

    # Handle POST requests for authentication
    def do_POST(self):
        parsed_path = urlparse(self.path)  # Parse the request path
        params = parse_qs(parsed_path.query)  # Parse query parameters
        if parsed_path.path == "/auth":  # Check if the path is '/auth'
            headers = {
                "kid": "goodKID"  # Set key ID for the token
            }
            token_payload = {
                "user": "username",  # User information
                # Expiration time
                "exp": (
                    datetime.datetime.now(datetime.UTC) +
                    datetime.timedelta(hours=1)
                )
            }
            # If expired parameter is present, modify the token for expired JWT
            if 'expired' in params:
                headers["kid"] = "expiredKID"  # Change key ID
                # Set expired time
                token_payload["exp"] = (
                    datetime.datetime.now(datetime.UTC)
                    - datetime.timedelta(hours=1)
                )
            # Encode the JWT
            encoded_jwt = jwt.encode(
                token_payload,
                pem,
                algorithm="RS256",
                headers=headers
            )
            self.send_response(200)  # Successful response
            self.end_headers()
            # Send the token back to the client
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)  # Method Not Allowed for other paths
        self.end_headers()
        return

    # Handle GET requests for JWKS
    def do_GET(self):
        # Check if the path is for JWKS
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)  # Successful response
            # Set content type
            self.send_header("Content-type", "application/json")
            self.end_headers()
            # Prepare the JWKS keys response
            keys = {
                "keys": [
                    {
                        "alg": "RS256",  # Algorithm
                        "kty": "RSA",  # Key type
                        "use": "sig",  # Use for signature
                        "kid": "goodKID",  # Key ID
                        # Modulus
                        "n": int_to_base64(numbers.public_numbers.n),
                        # Exponent
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            # Send JWKS response
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)  # Method Not Allowed for other paths
        self.end_headers()
        return


# Start the server
if __name__ == "__main__":
    # Create server instance
    web_server = HTTPServer((host_name, server_port), MyServer)
    try:
        web_server.serve_forever()  # Keep the server running
    except KeyboardInterrupt:
        pass  # End server with CTRL+C interrupt

    web_server.server_close()
