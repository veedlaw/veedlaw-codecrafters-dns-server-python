from dataclasses import dataclass
from typing import Self
import struct

from app import dns_record_type
from app import dns_record_class
from app.dns_message.dns_header import DNSheader
from app.dns_message.dns_question import DNSquestion
from app.dns_message.dns_answer import DNSanswer

NETWORK_BYTE_ORDER = 'big'



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
