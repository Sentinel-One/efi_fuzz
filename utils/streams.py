import io

class AutoFillBytesIO(io.BytesIO):
    """
    Similar to BytesIO, but on EOF keeps returning a default value instead of an empty byte sequence.
    """
    def __init__(self, initial_bytes, default_val=b'\x00'):
        super().__init__(initial_bytes)
        self.default_val = default_val

    def read(self, size=-1):
        val = super().read(size)
        if val == b'':
            val = self.default_val * size
        return val