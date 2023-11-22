"""
Packet Identifier (ID)
16 bits, used by the requester to match up replies to outstanding queries.

Query/Response Indicator (QR)
1 bit, indicates whether the message is a query (0) or a response (1).

Operation Code (OPCODE)
4 bits, indicates "kind" of query for the message.

Authoritative Answer (AA)
1 bit, indicates whether the response is authoritative (1) or not (0).

Truncation (TC)
1 bit, whether the response was truncated (1) or not (0).

Recursion Desired (RD)
1 bit, whether the query should be pursued recursively (1) or not (0).

Recursion Available (RA)
1 bit, used in response to signal recursion availability (1) or not (0).

Reserved (Z)
3 bits, three reserved bits set to zero.

Response Code (RCODE)
4 bits, set in responses
- 0 no error
- 1 format error (Invalid query format, server could not interpret)
- 2 server failure (i.e. internal server error)
- 3 name error (the queried domain name does not exist)
- 4 not implemented
- 5 refused

Question Count (QDCOUNT)
Number of entries in the question section.

Answer Record Count (ANCOUNT)
Number of entries in the answer section.

Authoritative Record Count (NSCOUNT)
Number of name server resource records.

Additional Record Count (ARCOUNT)
Number of resource records in additional records section.

"""
from dataclasses import dataclass
from typing import Self
import struct

NETWORK_BYTE_ORDER = 'big'
# '!' marks network byte order
# 'H' is unsigned short: 2 bytes
# 'c' is char: 1 byte
DNS_HEADER_FORMAT = '!HccHHHH'
DNS_HEADER_STRUCT = struct.Struct(DNS_HEADER_FORMAT)
assert DNS_HEADER_STRUCT.size == 12  # DNS headers are 12 bytes



@dataclass
class DNSheader:
    """Class for handling DNS message contents."""
    packet_identifier: int
    query_indicator: int
    opcode: int
    authoritative_answer: int
    truncation: int
    recursion_desired: int
    recursion_available: int
    z_reserved: int
    response_code: int
    question_count: int
    answer_count: int
    auth_rec_count: int
    additional_rec_count: int


    @classmethod
    def from_message(cls, message: bytes) -> Self:
        """
        Construct a DNSheader instance from a DNS message (bytes).

        This is an alternative contstructor method for the DNSheader class.
        It extracts the relevant bits and bytes from the DNS message into 
        separate fields and returns the corresponding DNSheader dataclass.

        Args:
            cls: The type of the class 
            message (bytes): DNS message contents

        Returns:
            Initialized DNSheader
        """
        # First entry is 2 bytes
        next_byte = 2

        # Byte 1 & 2: first 2 bytes are the ID
        packet_identifier = message[0:next_byte]
        packet_identifier = int.from_bytes(packet_identifier,
                                             NETWORK_BYTE_ORDER,
                                             signed=False)

        # Byte 3: various flags and codes
        query_indicator = 0b0000_0001 & message[next_byte]
        opcode          = 0b0001_1110 & message[next_byte]
        authoritative_answer     = 0b0010_0000 & message[next_byte]
        truncation      = 0b0100_0000 & message[next_byte]
        recursion_desired = 0b1000_0000 & message[next_byte]
        next_byte += 1

        # Byte 4: various flags and codes continued
        recursion_avail = 0b0000_0001 & message[next_byte]
        z_reserved      = 0b0000_1110 & message[next_byte]
        response_code   = 0b1111_0000 & message[next_byte]
        next_byte += 1

        # Byte 5 & 6: Question count
        question_count = message[next_byte: next_byte+2]
        question_count = int.from_bytes(question_count,
                                     NETWORK_BYTE_ORDER,
                                     signed=False)
        next_byte += 2
        # Byte 7 & 8: Answer record count
        answer_count = message[next_byte: next_byte+2]
        answer_count = int.from_bytes(answer_count,
                                     NETWORK_BYTE_ORDER,
                                     signed=False)

        next_byte += 2
        # Byte 9 & 10: Authoritative record count
        auth_rec_count = message[next_byte: next_byte+2]
        auth_rec_count = int.from_bytes(auth_rec_count,
                                     NETWORK_BYTE_ORDER,
                                     signed=False)

        next_byte += 2
        # Byte 11 & 12: Additional record count
        additional_rec_count = message[next_byte: next_byte+2]
        additional_rec_count = int.from_bytes(additional_rec_count,
                                     NETWORK_BYTE_ORDER,
                                     signed=False)
        
        return cls(
            packet_identifier,
            query_indicator,
            opcode,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_avail,
            z_reserved,
            response_code,
            question_count,
            answer_count,
            auth_rec_count,
            additional_rec_count
        )


    def pack(self) -> bytes:
        H_packet_identifier = self.packet_identifier

        # byte 3: various flags and codes continued
        c_flags_and_codes_byte3 = bytes(1)
        c_flags_and_codes_byte3 = 0b0000_0001 | self.query_indicator
        c_flags_and_codes_byte3 = 0b0001_1110 | self.opcode
        c_flags_and_codes_byte3 = 0b0010_0000 | self.authoritative_answer
        c_flags_and_codes_byte3 = 0b0100_0000 | self.truncation
        c_flags_and_codes_byte3 = 0b1000_0000 | self.recursion_desired
        c_flags_and_codes_byte3 = c_flags_and_codes_byte3.to_bytes(
            byteorder=NETWORK_BYTE_ORDER, signed=False)

        # byte 4: various flags and codes continued
        c_flags_and_codes_byte4 = 0
        c_flags_and_codes_byte4 = 0b0000_0001 | self.recursion_available
        c_flags_and_codes_byte4 = 0b0000_1110 | self.z_reserved
        c_flags_and_codes_byte4 = 0b1111_0000 | self.response_code
        c_flags_and_codes_byte4 = c_flags_and_codes_byte4.to_bytes(
            byteorder=NETWORK_BYTE_ORDER, signed=False)

        H_qd_count = self.question_count
        H_an_count = self.answer_count
        H_ns_count = self.auth_rec_count
        H_ar_count = self.additional_rec_count

        return DNS_HEADER_STRUCT.pack(
            H_packet_identifier,
            c_flags_and_codes_byte3,
            c_flags_and_codes_byte4,
            H_qd_count,
            H_an_count,
            H_ns_count,
            H_ar_count
        )

