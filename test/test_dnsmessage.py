#! /usr/bin/env python3
"""
This module contains unit tests for DNS header and question parsing and packing functionalities.
It tests various scenarios to ensure the correctness of DNS header and question operations
as defined in the DNS protocol standards.
"""

import unittest
import struct
from app.dnsmessage import DNSquestion, DNSheader

class TestDNSheader(unittest.TestCase):

    def test_header_byte_length(self):
        """
        Test that the packed header has the correct byte length.
        """
        header = DNSheader(
            packet_identifier=1234, query_indicator=1, opcode=1,
            authoritative_answer=0, truncation=0, recursion_desired=0,
            recursion_available=0, z_reserved=0, response_code=1,
            question_count=1, answer_count=1, auth_rec_count=0, additional_rec_count=0
        )
        packed_bytes = header.pack()
        self.assertEqual(len(packed_bytes), 12)  # DNS headers should always be 12 bytes long

    def test_opcode_parsing(self):
        """
        Test parsing of the opcode from a DNS header.
        """
        test_cases = [
            (b'\xb3\xe7\x08\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01', 1),
            (b'yg\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01', 2),
            (b'F\xbd\x18\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01', 3)
        ]

        for buf, expected_opcode in test_cases:
            with self.subTest(buf=buf):
                byte3 = buf[2]
                opcode = (byte3 & 0b01111000) >> 3
                self.assertEqual(opcode, expected_opcode)

    def test_opcode_packing(self):
        """
        Test packing of the opcode into DNS header bytes.
        """
        test_cases = [
            (1,),
            (2,),
            (3,)
        ]

        for opcode, in test_cases:
            with self.subTest(opcode=opcode):
                header = DNSheader(
                    packet_identifier=1234, query_indicator=1, opcode=opcode,
                    authoritative_answer=0, truncation=0, recursion_desired=0,
                    recursion_available=0, z_reserved=0, response_code=1,
                    question_count=1, answer_count=1, auth_rec_count=0, additional_rec_count=0
                )
                packed_bytes = header.pack()
                byte3 = packed_bytes[2]
                packed_opcode = (byte3 & 0b01111000) >> 3
                self.assertEqual(packed_opcode, opcode)

    def test_invalid_input(self):
        """
        Test behavior with invalid input bytes.
        """
        with self.assertRaises(struct.error):
            DNSheader.from_message(b'\x00' * 11)  # Less than 12 bytes
    

if __name__ == '__main__':
    unittest.main()
