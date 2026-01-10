from __future__ import annotations

import unittest

from protoscan import payload_library


class PayloadLibraryTests(unittest.TestCase):
    def test_fingerprint_lookup(self) -> None:
        dompurify = payload_library.fingerprint_for_alias("gadget.client.dom.dompurify")
        self.assertIsNotNone(dompurify)
        assert dompurify is not None
        self.assertIn("DOMPurify", dompurify["name"])
        self.assertTrue(dompurify["impact"])
        fallback = payload_library.fingerprint_for_alias("gadget.unknown")
        self.assertIsNone(fallback)

    def test_ppmap_fingerprints_loaded(self) -> None:
        embedly = payload_library.fingerprint_for_alias("gadget.client.media.embedly")
        self.assertIsNotNone(embedly)
        assert embedly is not None
        self.assertIn("Embedly", embedly["name"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
