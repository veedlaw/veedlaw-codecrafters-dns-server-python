import unittest
from app.dns_message.dns_question import DNSquestion

class TestDNSquestion(unittest.TestCase):

    def test_from_message_domain_name_parsing(self):
        """
        Test parsing of various domain names from a DNS message.
        """
        test_cases = [
            (b'\x00' * 12 + b'\x03www\x07example\x03com\x00\x00\x01\x00\x01' + b'\x00' * 12, ['www', 'example', 'com']),
            (b'\x00' * 12 + b'\x03api\x04shop\x03www\x07example\x03com\x00\x00\x01\x00\x01' + b'\x00' * 12, ['api', 'shop', 'www', 'example', 'com']),
        ]

        for message, expected_name in test_cases:
            with self.subTest(message=message):
                question = DNSquestion.from_message(message)
                self.assertEqual(question.name, expected_name)