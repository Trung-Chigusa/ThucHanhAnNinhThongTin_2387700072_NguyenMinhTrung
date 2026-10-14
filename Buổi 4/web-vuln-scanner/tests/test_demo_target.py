import unittest

from demo_target import create_demo_app


class DemoTargetTests(unittest.TestCase):
    def setUp(self):
        self.client = create_demo_app().test_client()

    def test_search_reflects_harmless_marker_and_has_unprotected_form(self):
        marker = "<lab04-marker-test>"
        response = self.client.get("/search", query_string={"q": marker})
        self.assertEqual(response.status_code, 200)
        self.assertIn(marker.encode(), response.data)
        self.assertIn(b'<form method="post"', response.data)

    def test_form_route_uses_only_local_demo_html(self):
        response = self.client.get("/form")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"method=\"post\"", response.data)

    def test_lookup_and_inspect_do_not_execute_sql_or_fetch_urls(self):
        lookup = self.client.get("/lookup", query_string={"id": "1 OR 1=1"})
        inspect = self.client.get("/inspect", query_string={"url": "http://169.254.169.254/latest"})
        self.assertIn(b"Local demo received", lookup.data)
        self.assertIn(b"Local demo received", inspect.data)


if __name__ == "__main__":
    unittest.main()
