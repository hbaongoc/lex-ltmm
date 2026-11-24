
from collections.abc import Sequence

from .transforms import (
    add_round_key,
    mix_columns,
    shift_rows,
    sub_bytes,
)

ByteData = bytes | bytearray | memoryview

def _validate_block(block: ByteData) -> bytes:
    if not isinstance(block, (bytes, bytearray, memoryview)):
        raise TypeError("block must be bytes, bytearray, or memoryview")
    block = bytes(block)
    if len(block) != 16:
        raise ValueError("block length must be exactly 16 bytes")
    return block

def _validate_round_keys(
    round_keys: Sequence[bytes],
) -> tuple[bytes, ...]:
    if isinstance(round_keys, (str, bytes, bytearray, memoryview)):
        raise TypeError("round_keys must be a sequence of 11 keys")
    if not isinstance(round_keys, Sequence):
        raise TypeError("round_keys must be a sequence of 11 keys")
    if len(round_keys) != 11:
        raise ValueError("AES-128 requires exactly 11 round keys")
    checked_keys = []
    for index, key in enumerate(round_keys):
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError(f"round_keys[{index}] must be bytes-like")
        key = bytes(key)
        if len(key) != 16:
            raise ValueError(
                f"round_keys[{index}] must be exactly 16 bytes"
            )
        checked_keys.append(key)
    return tuple(checked_keys)
def encrypt_block(
    round_keys: Sequence[bytes],
    block: ByteData,
) -> bytes:
    """Encrypt a 16-byte block using AES-128."""
    block = _validate_block(block)
    checked_keys = _validate_round_keys(round_keys)
    state = bytearray(block)
    # Initial round
    state = add_round_key(state, checked_keys[0])
    # Rounds 1-9
    for round_no in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, checked_keys[round_no])
    # Final round (without MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, checked_keys[10])
    return bytes(state)
