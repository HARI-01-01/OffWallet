import struct

class Canon:
    """
    Shadow v1 Canonical Encoding (Python)
    One deterministic byte representation of every signed payload.
    """

    @staticmethod
    def enc(fields: list) -> bytes:
        out = bytearray()
        for field in fields:
            type_char = field[0]
            val = field[1]

            if type_char == 'u8':
                out.extend(struct.pack('>B', val & 0xFF))
            elif type_char == 'u64':
                out.extend(struct.pack('>Q', val))
            elif type_char == 'bytes':
                if not isinstance(val, (bytes, bytearray)):
                    raise TypeError("Expected bytes or bytearray for 'bytes' field")
                if len(val) > 65535:
                    raise ValueError(f"Bytes field too large: {len(val)}")
                out.extend(struct.pack('>H', len(val)))
                out.extend(val)
            elif type_char == 'str':
                if not isinstance(val, str):
                    raise TypeError("Expected str for 'str' field")
                bytes_val = val.encode('utf-8')
                if len(bytes_val) > 65535:
                    raise ValueError(f"String field too large: {len(bytes_val)}")
                if '\0' in val:
                    raise ValueError("String contains null byte")
                out.extend(struct.pack('>H', len(bytes_val)))
                out.extend(bytes_val)
            else:
                raise ValueError(f"Unknown field type: {type_char}")

        return bytes(out)
