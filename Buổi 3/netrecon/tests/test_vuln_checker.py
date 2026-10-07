import unittest

from modules.vuln_checker import review_exposure


class ExposureReviewTests(unittest.TestCase):
    def test_plaintext_services_emit_informational_notes(self):
        for service in ("ftp", "telnet"):
            with self.subTest(service=service):
                notes = review_exposure(21 if service == "ftp" else 23, service)
                self.assertTrue(notes)
                self.assertTrue(all("informational" in note.lower() for note in notes))

    def test_no_note_claims_a_cve_or_vulnerability(self):
        notes = review_exposure(23, "telnet")
        combined = " ".join(notes).lower()
        self.assertNotIn("cve", combined)
        self.assertNotIn("vulnerab", combined)
        self.assertNotIn("exploit", combined)


if __name__ == "__main__":
    unittest.main()
