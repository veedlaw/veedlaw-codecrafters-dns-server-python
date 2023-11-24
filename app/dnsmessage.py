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

from app import dns_record_type
from app import dns_record_class

NETWORK_BYTE_ORDER = 'big'



@dataclass
class DNSheader:
    """Class for handling DNS header section contents."""
    packet_identifier: int
    query_indicator: int
    opcode: int
    authoritative_answer: int
    truncation: int
    recursion_desired: int
    recursion_available: int
    z_reserved: int
    response_code: int
    question_count: int  # https://www.ietf.org/archive/id/draft-bellis-dnsop-qdcount-is-one-00.html
    answer_count: int
    auth_rec_count: int
    additional_rec_count: int

    # '!' marks network byte order
    # 'H' is unsigned short: 2 bytes
    # 'c' is char: 1 byte
    DNS_HEADER_FORMAT = '!HccHHHH'
    DNS_HEADER_SIZE = 12
    DNS_HEADER_STRUCT = struct.Struct(DNS_HEADER_FORMAT)
    assert DNS_HEADER_STRUCT.size == DNS_HEADER_SIZE

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
        (packet_identifier, 
        byte3,  # requires bit-level unpacking
        byte4,  # requires bit-level unpacking
        q_count, 
        an_count, 
        ns_count, 
        ar_count) = cls.DNS_HEADER_STRUCT.unpack(message[:cls.DNS_HEADER_SIZE])

        # Byte 3: various flags and codes
        byte3 = int.from_bytes(byte3, byteorder=NETWORK_BYTE_ORDER, signed=False)
        query_indicator = 0b1000_0000 & byte3
        opcode          = 0b0111_1000 & byte3
        authoritative_answer     = 0b0000_0100 & byte3
        truncation      = 0b0000_0010 & byte3
        recursion_desired = 0b0000_0001 & byte3

        # Byte 4: various flags and codes continued
        byte4 = int.from_bytes(byte4, byteorder=NETWORK_BYTE_ORDER, signed=False)
        recursion_avail = 0b1000_0000 & byte4
        z_reserved      = 0b0111_0000 & byte4
        response_code   = 0b0000_1111 & byte4

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
            q_count,
            1, #an_count,
            ns_count,
            ar_count
        )

    def pack(self) -> bytes:
        """
        Packs the DNS header fields into a bytes object suitable for network transmission.
        Returns:
            bytes: The packed DNS header as a byte string.
        """
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

        return self.DNS_HEADER_STRUCT.pack(
            H_packet_identifier,
            c_flags_and_codes_byte3,
            c_flags_and_codes_byte4,
            H_qd_count,
            H_an_count,
            H_ns_count,
            H_ar_count
        )

    def __str__(self) -> str:
        return (f'DNSheader:\n'
            f'\tid: {self.packet_identifier}\n'
            f'\tresponse: {"true" if self.query_indicator else "false"}\n'
            f'\topcode: {self.opcode}\n'
            f'\tauthoritative_answer: {"true" if self.authoritative_answer else "false"}\n'
            f'\ttruncated_message: {"true" if self.truncation else "false"}\n'
            f'\trecursion_desired: {"true" if self.recursion_desired else "false"}\n'
            f'\trecursion_available: {"true" if self.recursion_available else "false"}\n'
            f'\trecursion_desired: {"true" if self.recursion_desired else "false"}\n'
            f'\tz_reserved: {self.z_reserved}\n'
            f'\tresponse_code: {self.response_code}\n'
            f'\tqd_count: {self.question_count}\n'
            f'\tan_count: {self.answer_count}\n'
            f'\tns_count: {self.auth_rec_count}\n'
            f'\tar_count: {self.additional_rec_count}'
        )


@dataclass
class DNSquestion:
    """Class for handling DNS question section contents."""
    name: list[str]
    record_type: int
    clazz: int

    @classmethod
    def from_message(cls, message: bytes) -> Self:
        """
        Construct a DNSquestion instance from a DNS message (bytes).

        This is an alternative constructor method for the DNSquestion class.
        It extracts the relevant bits and bytes from the DNS message into 
        separate fields and returns the corresponding DNSquestion dataclass.

        Args:
            cls: The type of the class 
            message (bytes): DNS message contents

        Returns:
            Initialized DNSquestion
        """

        # TODO
        return cls(['codecrafters', 'io'], 1, 1)

    def pack(self) -> bytes:
        """
        Packs the DNS question fields into a bytes object suitable for network transmission.
        Returns:
            bytes: The packed DNS question as a byte string.
        
        """
        name = b''

        for label in self.name:
            name += struct.pack('!B', len(label)) + label.encode()
        name += b'\x00'

        return name + struct.pack('!HH', self.record_type, self.clazz)

    def __str__(self) -> str:
        return (f'DNSquestion:\n'
            f'\tname: {self.name}\n'
            f'type: {self.record_type}\n'
            f'class: {self.clazz}\n'
        )


@dataclass
class DNSanswer:
    name: list[str] 
    record_type: int
    clazz: int
    ttl: int
    rdlength: int
    rdata: str

    @classmethod
    def from_message(cls, message: bytes) -> Self:
        # TODO HARDCODED
        name = ['codecrafters', 'io']
        record_type = dns_record_type.RecordType.A.value
        clazz = dns_record_class.RecordClass.IN.value
        # ttl = struct.pack('!I', 60)
        ttl = 60
        # rdlength = struct.pack('!H', 4)
        rdata = '8.8.8.8'

        return cls(name, record_type, clazz, ttl, len(rdata)-3, rdata)

    def pack(self) -> bytes:
        """
        Packs the DNS answer fields into a bytes object suitable for network transmission.
        Returns:
            bytes: The packed DNS answer as a byte string.
        
        """
        name = b''

        for label in self.name:
            name += struct.pack('!B', len(label)) + label.encode()
        name += b'\x00'

        # convert rdata to integer format
        rdata_encoded = b''
        for ip_part in '8.8.8.8'.split('.'):
            rdata_encoded += struct.pack('!B', int(ip_part))

        # pack fixed length fields: type, class, TTL length and data
        format_str = '!HHIH'
        packed_fields = struct.pack(format_str, 
            self.record_type,
            self.clazz,
            self.ttl,
            self.rdlength,
        )

        return name + packed_fields + rdata_encoded

    def __str__(self) -> str:
        return (f'DNSanswer:\n'
            f'\tname: {self.name}\n'
            f'type: {self.record_type}\n'
            f'class: {self.clazz}\n'
            f'ttl: {self.ttl}\n'
            f'rdlength: {self.rdlength}\n'
            f'rdata: {self.rdata}\n'
        )



@dataclass
class DNSmessage:
    header: DNSheader
    question: DNSquestion
    answer: DNSanswer

    @classmethod
    def from_message(cls, message: bytes) -> Self:
        header = DNSheader.from_message(message)
        question = DNSquestion.from_message(message)
        answer = DNSanswer.from_message(message)
        return cls(header, question, answer)
    
    def pack(self) -> bytes:
        """
        Packs the DNS message fields into a bytes object suitable for network transmission.
        Returns:
            bytes: The packed DNS message as a byte string.
        
        """
        header_bytes = self.header.pack()
        question_bytes = self.question.pack()
        answer_bytes = self.answer.pack()

        return header_bytes + question_bytes + answer_bytes
