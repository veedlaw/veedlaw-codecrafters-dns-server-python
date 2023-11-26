from dataclasses import dataclass
from typing import Self
import struct

from app.dns_message.dns_record_class import RecordClass
from app.dns_message.dns_record_type import RecordType

@dataclass
class DNSanswer:
    """Class for handling DNS answer section contents."""
    name: list[str] 
    record_type: int
    clazz: int
    ttl: int
    rdlength: int
    rdata: str

    @classmethod
    def from_message(cls, message: bytes, buf_ptr: int) -> Self:
        """
        Construct a DNSanswer instance from a DNS message (bytes).

        This is an alternative constructor method for the DNSanswer class.
        It extracts the relevant bits and bytes from the DNS message into 
        separate fields and returns the corresponding DNSanswer dataclass.

        Args:
            cls: The type of the class 
            buf (bytes): DNS message contents
            buf_ptr (int): Index of the message to start parsing from.

        Returns:
            A tuple (DNSanswer, int), where the int signifies the byte where parsing was finished.
        """

        # TODO

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
        
        name = labels 
        record_type = RecordType.A.value
        clazz = RecordClass.IN.value
        # ttl = struct.pack('!I', 60)
        ttl = 60
        # rdlength = struct.pack('!H', 4)
        rdata = '8.8.8.8'

        return cls(name, record_type, clazz, ttl, len(rdata)-3, rdata), buf_ptr

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
