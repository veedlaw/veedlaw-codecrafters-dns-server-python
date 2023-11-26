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
                question, buf_ptr_new = DNSquestion.from_message(message, buf_ptr=12)
                self.assertEqual(question.name, expected_name)
    
    def test_from_message_compressed_packet_parsing(self):

        num_queries = 2
        buf = b'\x86-\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03def\xc0\x10\x00\x01\x00\x01'
        expected_labels = [['abc', 'longassdomainname', 'com'],
            ['def', 'longassdomainname']]
        
        buf_ptr = 12
        parsed_labels = []
        for i in range(len(expected_labels)):
            question, buf_ptr = DNSquestion.from_message(buf, buf_ptr)
            parsed_labels.append(question.name)
            print(f'{question=}')       


        for i, expected_label in enumerate(expected_labels):
            with self.subTest():
                self.assertEqual(expected_label, parsed_labels[i])
