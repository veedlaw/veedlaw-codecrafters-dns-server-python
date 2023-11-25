from dataclasses import dataclass
from typing import Self
import struct

from app import dns_record_type
from app import dns_record_class
from app.dns_message.dns_header import DNSheader
from app.dns_message.dns_question import DNSquestion

NETWORK_BYTE_ORDER = 'big'

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
