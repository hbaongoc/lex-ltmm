from .sbox import SBOX

ByteData = bytes | bytearray | memoryview

def _validate_bytes16(data: ByteData, name: str) -> bytes:
    """Kiem tra du lieu dau vao phai la bytes-like va dung 16 byte."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes, bytearray, or memoryview")
    raw = bytes(data)
    if len(raw) != 16:
        raise ValueError(f"{name} length must be exactly 16 bytes")
    return raw


def _xtime(value: int) -> int:
    """Nhan mot byte voi x (0x02) trong truong huu han GF(2^8)."""
    return ((value << 1) ^ 0x1B) & 0xFF if (value & 0x80) else (value << 1)


def sub_bytes(state: ByteData) -> bytearray:
    """Thay the tung byte trong state bang bang tra S-Box (ham thuan)."""
    raw = _validate_bytes16(state, "state")
    return bytearray(SBOX[b] for b in raw)


def shift_rows(state: ByteData) -> bytearray:
    """Dich trai hang r di r vi tri theo thu tu column-major (FIPS-197)."""
    raw = _validate_bytes16(state, "state")
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[4 * c + r] = raw[4 * ((c + r) % 4) + r]
    return out

def mix_columns(state: ByteData) -> bytearray:
    """Tron tung cot 4 byte tren truong GF(2^8) (ham thuan)."""
    raw = _validate_bytes16(state, "state")
    out = bytearray(16)
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = raw[i], raw[i + 1], raw[i + 2], raw[i + 3]
        t = a0 ^ a1 ^ a2 ^ a3
        out[i] = a0 ^ t ^ _xtime(a0 ^ a1)
        out[i + 1] = a1 ^ t ^ _xtime(a1 ^ a2)
        out[i + 2] = a2 ^ t ^ _xtime(a2 ^ a3)
        out[i + 3] = a3 ^ t ^ _xtime(a3 ^ a0)
    return out

def add_round_key(state: ByteData, round_key: ByteData) -> bytearray:
    """XOR state 16 byte voi round_key 16 byte theo thu tu column-major."""
    raw_state = _validate_bytes16(state, "state")
    raw_key = _validate_bytes16(round_key, "round_key")
    return bytearray(a ^ b for a, b in zip(raw_state, raw_key))
