import logging
from typing import Union

from iso15118.shared.exceptions import (
    InvalidPayloadTypeError,
    InvalidProtocolError,
    InvalidV2GTPMessageError,
)
from iso15118.shared.messages.enums import (
    UINT_32_MAX,
    DINPayloadTypes,
    ISOV2PayloadTypes,
    ISOV20PayloadTypes,
    Protocol,
    V2GTPVersion,
)

logger = logging.getLogger(__name__)


class V2GTPMessage:
    def __init__(
        self,
        protocol: Protocol,
        payload_type: Union[DINPayloadTypes, ISOV2PayloadTypes, ISOV20PayloadTypes],
        payload: bytes,
    ):
        """
        The V2G PDU (Protocol Data Unit) consists of a header and a
        payload section

                |  Header |         Payload        |
                | 8 Bytes |   0 - 4294967296 Bytes |

        The payload contains the application data (e.g. V2G Message).
        The header separates the payloads within a byte stream and provides
        info how to process the payload received.
        The header consists of 8 octets:

        -     0     -        1         -      2-3    -      4-5-6-7      -
         ____________ __________________ _____________ __________________
        |  Protocol |      Inverse     |    Payload  |      Payload     |
        |  Version  | Protocol Version |     Type    |      Length      |
         ____________ __________________ _____________ _________________
        |  1 Byte   |     1 Byte       |    2 Bytes  |    4 Bytes      |

        protocol_version (0x01): Identifies the version of V2GTP messages
        inverse_protocol_version (0xFE): The bitwise inverse of the previous
                                         to ensure that a correctly formatted
                                         V2GTP message was received
        payload_type: Contains info of how to decode the payload
        payload_length: Contains the length of the V2GTP message in bytes
        """
        if protocol not in Protocol.options():
            raise InvalidProtocolError(
                f"'{protocol.name}' is not a "
                "valid protocol. Allowed: "
                f"{Protocol.allowed_protocols()}"
            )

        if not self.is_payload_type_valid(protocol, payload_type):
            raise InvalidPayloadTypeError(
                f"Protocol {protocol} doesn't support" f" payload type {payload_type}"
            )

        self.protocol = protocol
        self.protocol_version = V2GTPVersion.PROTOCOL_VERSION
        self.inv_protocol_version = V2GTPVersion.INV_PROTOCOL_VERSION
        self.payload_type = payload_type
        self.payload_length = len(payload)
        self.payload = payload

    @staticmethod
    def get_payload_type(header: bytes) -> int:
        if len(header) == 8:
            return int.from_bytes(header[2:4], "big")

        # Returning a non-positive number guarantees that any upper-level checks
        # comparing the returned payload type with an expected one will fail
        return -1

    @staticmethod
    def get_payload_length(header: bytes) -> int:
        if len(header) == 8:
            return int.from_bytes(header[4:], "big")

        # Return -1 to show we're unable to determine the payload length
        return -1

    @classmethod
    def is_payload_type_valid(cls, protocol: Protocol, payload_type: int) -> bool:
        if (
            protocol in [Protocol.ISO_15118_2, Protocol.UNKNOWN]
            and payload_type not in ISOV2PayloadTypes.options()
        ) or (
            protocol.ns.startswith("urn:iso:std:iso:15118:-20")
            and payload_type not in ISOV20PayloadTypes.options()
        ):
            logger.error(
                f"{str(protocol)} does not support payload type " f"{payload_type}"
            )
            return False

        return True

    @classmethod
    def is_header_valid(cls, protocol: Protocol, header: bytes) -> bool:
        """
        This method processes the V2GTP header as required by ISO 15118
        (Check section 7.8.3.2 15118-2, Ed.1)
        """
        is_valid: bool = True
        if len(header) != 8:
            logger.error(
                f"No proper V2GTP message, header is "
                f"{len(header)} bytes long. Expected: 8 bytes"
            )
            is_valid = False

        if protocol not in Protocol.options():
            logger.error(
                f"Unable to identify protocol version. " f"Received: {protocol}"
            )
            is_valid = False

        protocol_version = header[0]
        if protocol_version != V2GTPVersion.PROTOCOL_VERSION:
            logger.error(
                f"Incorrect protocol version '{protocol_version}' "
                f"for V2GTP message. "
                f"Expected: {V2GTPVersion.PROTOCOL_VERSION}"
            )
            is_valid = False

        inv_protocol_version = header[1]
        if inv_protocol_version != V2GTPVersion.INV_PROTOCOL_VERSION:
            logger.error(
                f"Incorrect inverse protocol version "
                f"'{inv_protocol_version}' for V2GTP message. "
                f"Expected: {V2GTPVersion.INV_PROTOCOL_VERSION}"
            )
            is_valid = False

        if not cls.is_payload_type_valid(protocol, cls.get_payload_type(header)):
            is_valid = False

        payload_length = cls.get_payload_length(header)
        if payload_length > UINT_32_MAX:
            logger.error(
                f"Payload length of {payload_length} bytes for V2GTP "
                f"message exceeds limit of {UINT_32_MAX} bytes"
            )
            is_valid = False

        if payload_length < 0:
            logger.error(
                "Couldn't determine payload length of V2GTP message " "(got -1)"
            )
            is_valid = False

        return is_valid

    def to_bytes(self) -> bytes:
        header = (
            self.protocol_version.to_bytes(1, "big")
            + self.inv_protocol_version.to_bytes(1, "big")
            + self.payload_type.to_bytes(2, "big")
            + self.payload_length.to_bytes(4, "big")
        )

        return bytes(header) + self.payload

    @classmethod
    def from_bytes(cls, protocol: Protocol, data: bytes) -> "V2GTPMessage":
        """
        Creates a V2G Transfer Protocol (V2GTP) message from the given
        bytearray, either received by the
        UDP client/server or TCP client/server

        Args:
            protocol: Either DIN SPEC 70121, ISO 15118-2 or ISO 15118-20
            data: The bytearray received by the UDP client/server or
                  TCP client/server

        Returns: A V2GTPMessage instance, if the bytearray turns out to be a
                 valid V2GTPMessage

        Raises:
            InvalidV2GTPMessageError
        """
        # The smallest possible datagram is a V2GTP message with an
        # SDP request of 2 bytes
        if len(data) >= 10:
            header = data[:8]

            payload_type: Union[ISOV2PayloadTypes, ISOV20PayloadTypes]
            if cls.is_header_valid(protocol, header):
                if protocol.ns.startswith("urn:iso:std:iso:15118:-20"):
                    payload_type = ISOV20PayloadTypes(cls.get_payload_type(header))
                else:
                    payload_type = ISOV2PayloadTypes(cls.get_payload_type(header))
                return V2GTPMessage(protocol, payload_type, data[8:])
            raise InvalidV2GTPMessageError(
                "Not a valid V2GTP message " "(header check failed)"
            )
        raise InvalidV2GTPMessageError(
            f"Incoming data is too short to be "
            "a valid V2GTP message"
            f" (only {len(data)} bytes)"
        )

    def __repr__(self):
        return (
            f"[Header = [{hex(self.protocol_version)}, "
            f"{hex(self.inv_protocol_version)}, {hex(self.payload_type)}, "
            f"{self.payload_length}], Payload = {self.payload.hex()})"
            "]"
        )
