import unittest

from app import create_app


class FlaskApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_index_documents_local_endpoints(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("/api/monitor", response.get_json()["endpoints"])

    def test_monitor_memory_network_and_security_endpoints(self):
        for path in ("/api/monitor", "/api/memory", "/api/network", "/api/security"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIsInstance(response.get_json(), dict)

    def test_sandbox_allows_only_bounded_text_message(self):
        response = self.client.post("/api/sandbox", json={"message": "Hello"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["stdout"], "Hello")
        response = self.client.post("/api/sandbox", json={"message": "x" * 257})
        self.assertEqual(response.status_code, 400)

    def test_sandbox_rejects_non_json_or_missing_message(self):
        self.assertEqual(self.client.post("/api/sandbox", data="no").status_code, 400)
        self.assertEqual(self.client.post("/api/sandbox", json={}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
