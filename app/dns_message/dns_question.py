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

    PACKET_COMPRESSION_SIGNAL_BYTE = 0xC0

    @classmethod
    def from_message(cls, buf: bytes, buf_ptr: int) -> (Self, int):
        """
        Construct a DNSquestion instance from a DNS message (bytes).

        This is an alternative constructor method for the DNSquestion class.
        It extracts the relevant bits and bytes from the DNS message into 
        separate fields and returns the corresponding DNSquestion dataclass.

        Args:
            cls: The type of the class 
            buf (bytes): DNS message contents
            buf_ptr (int): Index of the message to start parsing from.

        Returns:
            A tuple (DNSquestion, int), where the int signifies the byte where parsing was finished.
        """
        labels = []

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
        record_type = RecordType.A.value
        buf_ptr += 2
        clazz = RecordClass.IN.value
        buf_ptr += 2
        return cls(labels, record_type, clazz), buf_ptr

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

    def _parse_label(self):
        pass

    def __str__(self) -> str:
        return (f'DNSquestion:\n'
            f'\tname: {self.name}\n'
            f'type: {self.record_type}\n'
            f'class: {self.clazz}\n'
        )
