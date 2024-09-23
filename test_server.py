import unittest
from http.server import HTTPServer
from urllib.parse import urlencode
from http.client import HTTPConnection
from threading import Thread
import json
import jwt
import datetime

# Assuming your server code is in a file called `jwks_server.py`
from server import MyServer, host_name, server_port, int_to_base64

class TestJWKSAuthEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer((host_name, server_port), MyServer)
        cls.server_thread = Thread(target=cls.server.serve_forever)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server_thread.join()

    def make_request(self, method, path, params=None):
        conn = HTTPConnection(host_name, server_port)
        
        if method in ["POST", "PUT", "PATCH"]:
            conn.request(method, path, urlencode(params) if params else "")
        else:
            conn.request(method, path)

        response = conn.getresponse()
        data = response.read().decode()
        conn.close()
        return response.status, data
    
    def test_int_to_base64(self):
        self.assertEqual(int_to_base64(65537), "AQAB")

    def test_auth_success(self):
        # Test successful JWT creation
        status, token = self.make_request("POST", "/auth")
        self.assertEqual(status, 200)
        self.assertIsNotNone(token)
        self.assertIn("ey", token)  # Check for JWT format

        # Decode and verify the token
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded_token["user"], "username")
        self.assertIn("exp", decoded_token)  # Ensure exp claim is present

    def test_auth_expired(self):
        # Test JWT creation with expired flag
        status, token = self.make_request("POST", "/auth", params={"expired": "true"})
        self.assertEqual(status, 200)
        self.assertIsNotNone(token)
        self.assertIn("ey", token)  # Check for JWT format

        # Decode and verify the token
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded_token["user"], "username")
        self.assertIn("exp", decoded_token)  # Ensure exp claim is present
        self.assertTrue(decoded_token["exp"] < datetime.datetime.now(datetime.UTC).timestamp())  # Verify expiration

    def test_method_not_allowed_for_other_paths(self):
        # Test POST request on a different path
        status, _ = self.make_request("POST", "/invalid_path")
        self.assertEqual(status, 405)

    def test_put_method(self):
        # Test PUT request
        status, _ = self.make_request("PUT", "/auth")
        self.assertEqual(status, 405)

    def test_patch_method(self):
        # Test PATCH request
        status, _ = self.make_request("PATCH", "/auth")
        self.assertEqual(status, 405)

    def test_delete_method(self):
        # Test DELETE request
        status, _ = self.make_request("DELETE", "/auth")
        self.assertEqual(status, 405)

    def test_head_method(self):
        # Test HEAD request
        status, _ = self.make_request("HEAD", "/auth")
        self.assertEqual(status, 405)

    def test_invalid_path(self):
        # Test for an unsupported path to check that it responds with 405
        status, _ = self.make_request("POST", "/invalid")
        self.assertEqual(status, 405)

    def test_no_params(self):
        # Test POST request without parameters
        status, token = self.make_request("POST", "/auth")
        self.assertEqual(status, 200)
        self.assertIn("ey", token)

    def test_expired_token(self):
        # Test POST request with the expired parameter
        status, token = self.make_request("POST", "/auth", params={"expired": "true"})
        self.assertEqual(status, 200)
        self.assertIn("ey", token)

    def test_jwks_endpoint(self):
        # Test JWKS endpoint
        status, data = self.make_request("GET", "/.well-known/jwks.json")
        self.assertEqual(status, 200)
        self.assertIn("keys", json.loads(data))

if __name__ == "__main__":
    unittest.main()