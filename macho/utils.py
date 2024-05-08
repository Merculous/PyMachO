
from binascii import hexlify
from struct import unpack, pack
from typing import Any, List


def readStruct(fmt: str, struct: Any, data: bytes) -> Any:
    return struct(*unpack(fmt, data))


def structToBytes(fmt: str, args: tuple) -> bytes:
    return pack(fmt, *args)


def getAllNullTerminatedStrings(data: bytes) -> List[bytes]:
    NULL_CHAR = b'\x00'

    strings = []

    string = b''

    for i in range(len(data)):
        char = data[i:i+1]

        if char == NULL_CHAR:
            if not string:
                continue

            strings.append(string)
            string = b''
            continue

        string += char

    return strings


def formatIOKitPlistData(data: list) -> dict | list | str:
    # This is from ChatGPT cause I'm lazy

    if isinstance(data, dict):
        # If it's a dictionary, recursively convert values
        return {k: formatIOKitPlistData(v) for k, v in data.items()}
    elif isinstance(data, list):
        # If it's a list, recursively convert elements
        return [formatIOKitPlistData(item) for item in data]
    elif isinstance(data, bytes):
        # If it's a byte object, convert to hex string
        return hexlify(data).decode('utf-8')
    else:
        # Otherwise, return the data as it is
        return data
