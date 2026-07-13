import os
import sys
import unittest
from fastapi.testclient import TestClient

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.main import app
from backend.ml.detector import AnomalyDetector

class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)

    def test_root_route(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("app", response.json())

    def test_interfaces_route(self):
        response = self.client.get("/api/interfaces")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)

    def test_settings_get(self):
        response = self.client.get("/api/settings")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("mock_mode", data)
        self.assertIn("packet_limit", data)

    def test_system_metrics_route(self):
        response = self.client.get("/api/system/metrics")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("cpu_usage", data)
        self.assertIn("ram_usage", data)

if __name__ == "__main__":
    unittest.main()
