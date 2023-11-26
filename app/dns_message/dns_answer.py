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

    PACKET_COMPRESSION_SIGNAL_BYTE = 0xC0

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

        Returns:
            Initialized DNSanswer
        """

        labels = []
        buf=message

        # Parse the string
        while buf[buf_ptr] != '\x00':
            strlen = buf[buf_ptr]
            
            if (strlen & cls.PACKET_COMPRESSION_SIGNAL_BYTE == cls.PACKET_COMPRESSION_SIGNAL_BYTE):
                # The two highest bits set signal packet compression, however then to obtain the jump
                # address we must consider it as part of a 2 byte value where we need to unset the 
                # two highest order bits
                jump_addr = int.from_bytes(buf[buf_ptr: buf_ptr+2]) ^ 0xC000
                strlen = buf[jump_addr]
                string = buf[jump_addr + 1: jump_addr + 1 + strlen]
                labels.append(string.decode())

                # Since the compression is 2 bytes, overwrite the proxy value
                # Setting to 1 instead of 2 because +1 gets added later
                strlen = 1

            # Cut the appropriate slice
            else:
                string = buf[buf_ptr + 1: buf_ptr + 1 + strlen]
                labels.append(string.decode())

            buf_ptr += strlen + 1
            if buf[buf_ptr] == 0:
                buf_ptr += 1
                break
        
        # HARDCODED
        name = labels 
        record_type = RecordType.A.value
        buf_ptr += 2
        clazz = RecordClass.IN.value
        buf_ptr += 2
        ttl = 60
        buf_ptr += 4
        # Only handling IP addresses (from guaranteed record type)
        rdlength = len(b'\x08\x08\x08\x08')
        buf_ptr += 2
        rdata = buf[buf_ptr: buf_ptr+rdlength]

        return cls(name, record_type, clazz, ttl, rdlength, rdata)

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
        for ip_part in self.rdata:
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
