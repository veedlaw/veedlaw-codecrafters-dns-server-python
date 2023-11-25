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
        next_byte = 0

        print(f'{buf.hex()=}')
        # Read the length of the string 
        strlen = buf[next_byte]
        print(f'{buf[next_byte]=}; {format(buf[next_byte], "x")}')
        print(f'{buf[next_byte+1]=}; {format(buf[next_byte+1], "x")}')

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