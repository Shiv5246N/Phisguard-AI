"""
Unit tests for EmailProcessor module
"""

import unittest
from src.preprocessing import EmailProcessor


class TestEmailProcessor(unittest.TestCase):
    """Test cases for EmailProcessor."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = EmailProcessor()
    
    def test_extract_urls(self):
        """Test URL extraction."""
        text = "Visit https://example.com and http://test.org for more info"
        urls = self.processor.extract_urls(text)
        self.assertIn("https://example.com", urls)
        self.assertIn("http://test.org", urls)
    
    def test_extract_emails(self):
        """Test email extraction."""
        text = "Contact us at support@example.com or info@test.org"
        emails = self.processor.extract_emails(text)
        self.assertIn("support@example.com", emails)
        self.assertIn("info@test.org", emails)
    
    def test_extract_domain_from_email(self):
        """Test domain extraction from email."""
        domain = self.processor.extract_domain_from_email("user@example.com")
        self.assertEqual(domain, "example.com")
    
    def test_clean_text(self):
        """Test text cleaning."""
        dirty_text = "  Hello   World!!!  "
        clean = self.processor.clean_text(dirty_text)
        self.assertEqual(clean, "Hello World ! ! !")


if __name__ == '__main__':
    unittest.main()

