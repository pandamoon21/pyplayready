import base64
import codecs
from typing import Union
from uuid import UUID

from construct import Struct, Int32ul, Int16ul, Array, this, Bytes, Padded, Switch, Int32ub, Const, Container, FixedSized, Adapter, ConstructError

from pyplayready.wrmheader import WRMHeader

def encodingunit(encoding):
    """Determine the size of an encoding unit."""
    return {
        "utf8": 1,
        "utf16": 2,
        "utf32": 4,
        "ascii": 1
    }.get(encoding, 1)

class NullStripped(Adapter):
    """Strips null bytes on parsing, pads null bytes on building."""
    def __init__(self, subcon, pad):
        super().__init__(subcon)
        self.pad = pad

    def _decode(self, obj, context, path):
        return obj.rstrip(b"\x00")

    def _encode(self, obj, context, path):
        if len(obj) > self.subcon.size:
            raise ConstructError("Encoded string is larger than specified length")
        return obj.ljust(self.subcon.size, b"\x00")

class StringEncoded(Adapter):
    """Encodes/decodes a string using the specified encoding."""
    def __init__(self, subcon, encoding):
        super().__init__(subcon)
        self.encoding = encoding

    def _decode(self, obj, context, path):
        return obj.decode(self.encoding)

    def _encode(self, obj, context, path):
        if not isinstance(obj, str):
            raise ConstructError("Object is not a string")
        return obj.encode(self.encoding)

def PaddedStringFake(length, encoding):
    """
    Configurable, fixed-length or variable-length string field.

    :param length: integer, length in bytes
    :param encoding: string, encoding type like 'utf8', 'utf16', 'utf32', or 'ascii'
    """
    encoding_unit_size = encodingunit(encoding)
    return StringEncoded(
        FixedSized(
            length,
            NullStripped(
                Bytes(length),
                pad=encoding_unit_size
            )
        ),
        encoding
    )

    
class _PlayreadyPSSHStructs:
    PSSHBox = Struct(
        "length" / Int32ub,
        "pssh" / Const(b"pssh"),
        "fullbox" / Int32ub,
        "system_id" / Bytes(16),
        "data_length" / Int32ub,
        "data" / Bytes(this.data_length)
    )

    PlayreadyObject = Struct(
        "type" / Int16ul,
        "length" / Int16ul,
        "data" / Switch(
            this.type,
            {
                1: PaddedStringFake(this.length, "utf16")
            },
            default=Bytes(this.length)
        )
    )

    PlayreadyHeader = Struct(
        "length" / Int32ul,
        "record_count" / Int16ul,
        "records" / Array(this.record_count, PlayreadyObject)
    )


class PSSH:
    SYSTEM_ID = UUID(hex="9a04f07998404286ab92e65be0885f95")

    def __init__(
            self,
            data: Union[str, bytes]
    ):
        """Represents a PlayReady PSSH"""
        if not data:
            raise ValueError("Data must not be empty")

        if isinstance(data, str):
            try:
                data = base64.b64decode(data)
            except Exception as e:
                raise Exception(f"Could not decode data as Base64, {e}")

        try:
            if self._is_playready_pssh_box(data):
                pssh_box = _PlayreadyPSSHStructs.PSSHBox.parse(data)
                if bool(self._is_utf_16(pssh_box.data)):
                    self._wrm_headers = [pssh_box.data.decode("utf-16-le")]
                elif bool(self._is_utf_16(pssh_box.data[6:])):
                    self._wrm_headers = [pssh_box.data[6:].decode("utf-16-le")]
                elif bool(self._is_utf_16(pssh_box.data[10:])):
                    self._wrm_headers = [pssh_box.data[10:].decode("utf-16-le")]
                else:
                    self._wrm_headers = list(self._read_wrm_headers(_PlayreadyPSSHStructs.PlayreadyHeader.parse(pssh_box.data)))
            elif bool(self._is_utf_16(data)):
                self._wrm_headers = [data.decode("utf-16-le")]
            elif bool(self._is_utf_16(data[6:])):
                self._wrm_headers = [data[6:].decode("utf-16-le")]
            elif bool(self._is_utf_16(data[10:])):
                self._wrm_headers = [data[10:].decode("utf-16-le")]
            else:
                self._wrm_headers = list(self._read_wrm_headers(_PlayreadyPSSHStructs.PlayreadyHeader.parse(data)))
        except Exception:
            raise Exception("Could not parse data as a PSSH Box nor a PlayReadyHeader")

    @staticmethod
    def _downgrade(wrm_header: str) -> str:
        return WRMHeader(wrm_header).to_v4_0_0_0()

    def get_wrm_headers(self, downgrade_to_v4: bool = False):
        return list(map(
            self._downgrade if downgrade_to_v4 else (lambda _: _),
            self._wrm_headers
        ))

    def _is_playready_pssh_box(self, data: bytes) -> bool:
        return data[12:28] == self.SYSTEM_ID.bytes

    @staticmethod
    def _is_utf_16(data: bytes) -> bool:
        return all(map(lambda i: data[i] == 0, range(1, len(data), 2)))

    @staticmethod
    def _read_wrm_headers(wrm_header: Container):
        for record in wrm_header.records:
            if record.type == 1:
                yield record.data
