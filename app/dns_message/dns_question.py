from dataclasses import dataclass
from typing import Self
import struct

from app.dns_message.dns_record_class import RecordClass
from app.dns_message.dns_record_type import RecordType

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
        # Skip the header section:
        DNS_HEADER_LEN_BYTES = 12
        buf = message[DNS_HEADER_LEN_BYTES:]
        labels = []

        # Parse the string
        next_byte = 0
        while buf[next_byte] != '\x00':
            # Read the length of the string 
            strlen = buf[next_byte]
            # Cut the appropriate slice
            string = buf[next_byte + 1: next_byte + 1 + strlen]
            labels.append(string.decode())

            next_byte += strlen + 1
            if buf[next_byte] == 0:
                break
        
        # HARDCODED
        record_type = RecordType.A.value
        clazz = RecordClass.IN.value
        return cls(labels, record_type, clazz)

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
