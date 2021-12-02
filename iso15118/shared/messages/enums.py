import logging.config
from enum import Enum, IntEnum, auto
from typing import List, Union

from iso15118.shared import settings

logging.config.fileConfig(
    fname=settings.LOGGER_CONF_PATH, disable_existing_loggers=False
)
logger = logging.getLogger(__name__)

INT_32_MAX = 4294967295


class AuthEnum(str, Enum):
    """
    The enum values for the authorisation options differ between ISO 15118-2 and
    ISO 15118-20. This enumeration helps to unify different values.

    The default value for the enum members (EIM and PNC) are the ones from
    ISO 15118-20. They are used in the session variables and evcc/secc settings.

    For the ISO 15118-2 messages (see class AuthOptions), we add enum values
    EIM_V2 and PNC_V2, which provide the specific string value used in that
    standard.
    """

    EIM = "EIM"
    PNC = "PnC"
    EIM_V2 = "ExternalPayment"
    PNC_V2 = "Contract"


class V2GTPVersion(IntEnum):
    """
    These enums are used in the header of a V2G Transfer Protocol (V2GTP)
    message, as defined in both ISO 15118-2 and ISO 15118-20
    """

    PROTOCOL_VERSION = 0x01
    INV_PROTOCOL_VERSION = 0xFE

    @classmethod
    def options(cls) -> list:
        return list(cls)


class DINPayloadTypes(IntEnum):
    """
    The following payload types are defined in
    Table 16 of DIN SPEC 70121, Section 8.7.3.1
    """

    EXI_ENCODED = 0x8001
    SDP_REQUEST = 0x9000
    SDP_RESPONSE = 0x9001
    # 0xA000 - 0xFFFF: Available for manufacturer specific use.
    # Uniqueness of those identifiers is not guaranteed.
    # All other values not mentioned are Reserved

    @classmethod
    def options(cls) -> list:
        return list(cls)


class ISOV2PayloadTypes(IntEnum):
    """
    The following payload types are defined in
    Table 10 of ISO 15118-2, Ed. 1, 2014-04-01, Section 7.8.3
    """

    EXI_ENCODED = 0x8001
    SDP_REQUEST = 0x9000
    SDP_RESPONSE = 0x9001
    # 0xA000 - 0xFFFF: Available for manufacturer specific use.
    # Uniqueness of those identifiers is not guaranteed.
    # All other values not mentioned are Reserved

    @classmethod
    def options(cls) -> list:
        return list(cls)


class ISOV20PayloadTypes(IntEnum):
    """See Table 12 of ISO 15118-20"""

    SAP = 0x8001
    MAINSTREAM = 0x8002
    AC_MAINSTREAM = 0x8003
    DC_MAINSTREAM = 0x8004
    ACDP_MAINSTREAM = 0x8005
    WPT_MAINSTREAM = 0x8006
    # 0x8007 - 0x8100: Reserved for future use
    SCHEDULE_RENEGOTIATION = 0x8101
    METERING_CONFIRMATION = 0x8102
    ACDP_SYSTEM_STATUS = 0x8103
    PARKING_STATUS = 0x8104
    # 0x8105 - 0x8FFF: Reserved for future use
    SDP_REQUEST = 0x9000
    SDP_RESPONSE = 0x9001
    SDP_REQUEST_WIRELESS = 0x9002  # Used e.g. for ACDP (ACD Pantograph)
    SDP_RESPONSE_WIRELESS = 0x9003  # Used e.g. for ACDP (ACD Pantograph)
    # 0x9004 - 0x9FFF: Reserved for future use
    # 0xA000 - 0xFFFF: Available for manufacturer specific use. Uniqueness of
    #                  those identifiers is not guaranteed.

    @classmethod
    def options(cls) -> list:
        return list(cls)


class Namespace(str, Enum):
    """
    The namespaces used in DIN SPEC 70121, ISO 15118-2, and ISO 15118-20.
    They are used for the AppProtocol entries in the SupportedAppProtocolReq
    and for the EXI codec.
    """

    DIN_MSG_DEF = "urn:din:70121:2012:MsgDef"
    DIN_MSG_BODY = "urn:din:70121:2012:MsgBody"
    DIN_MSG_DT = "urn:din:70121:2012:MsgDataTypes"
    ISO_V2_MSG_DEF = "urn:iso:15118:2:2013:MsgDef"
    ISO_V2_MSG_BODY = "urn:iso:15118:2:2013:MsgBody"
    ISO_V2_MSG_DT = "urn:iso:15118:2:2013:MsgDataTypes"
    ISO_V20_BASE = "urn:iso:std:iso:15118:-20"
    ISO_V20_COMMON_MSG = "urn:iso:std:iso:15118:-20:CommonMessages"
    ISO_V20_COMMON_TYPES = "urn:iso:std:iso:15118:-20:CommonTypes"
    ISO_V20_AC = "urn:iso:std:iso:15118:-20:AC"
    ISO_V20_DC = "urn:iso:std:iso:15118:-20:DC"
    ISO_V20_WPT = "urn:iso:std:iso:15118:-20:WPT"
    ISO_V20_ACDP = "urn:iso:std:iso:15118:-20:ACDP"
    XML_DSIG = "http://www.w3.org/2000/09/xmldsig#"
    SAP = "urn:iso:15118:2:2010:AppProtocol"


class Protocol(Enum):
    """
    Available communication protocols supported by Josev. The values of these
    enum members are tuples, with the first tuple entry being the namespace
    (given as a string) and the second tuple entry being the according payload
    types (given as enums).
    """

    UNKNOWN = ("", ISOV2PayloadTypes)
    DIN_SPEC_70121 = (Namespace.DIN_MSG_DEF, DINPayloadTypes)
    ISO_15118_2 = (Namespace.ISO_V2_MSG_DEF, ISOV2PayloadTypes)
    ISO_15118_20_AC = (Namespace.ISO_V20_AC, ISOV20PayloadTypes)
    ISO_15118_20_DC = (Namespace.ISO_V20_DC, ISOV20PayloadTypes)
    ISO_15118_20_WPT = (Namespace.ISO_V20_WPT, ISOV20PayloadTypes)
    ISO_15118_20_ACDP = (Namespace.ISO_V20_ACDP, ISOV20PayloadTypes)

    def __init__(
        self,
        namespace: Namespace,
        payload_types: Union[DINPayloadTypes, ISOV2PayloadTypes, ISOV20PayloadTypes],
    ):
        """
        The value of each enum member is a tuple, where the first tuple entry
        is the associated protocol namespace (ns) and the second tuple entry are
        the associated payload types, given as an enum itself.
        """
        self.namespace = namespace
        self.payload_types = payload_types

    @property
    def ns(self) -> Namespace:
        return self.namespace

    @property
    def payloads(self) -> Union[DINPayloadTypes, ISOV2PayloadTypes, ISOV20PayloadTypes]:
        return self.payload_types

    @classmethod
    def options(cls) -> list:
        return list(cls)

    @classmethod
    def names(cls) -> list:
        return [protocol.name for protocol in cls]

    @classmethod
    def allowed_protocols(cls) -> list:
        return [
            protocol.name
            for protocol in cls
            if protocol.name not in ["UNKNOWN", "ISO_15118_20"]
        ]

    @classmethod
    def get_by_ns(cls, namespace: str) -> "Protocol":
        """Retrieves a Protocol entry by namespace"""
        for protocol in cls.options():
            if protocol.ns == namespace:
                return protocol

        logger.error(f"No available protocol matching namespace '{namespace}'")
        return Protocol.UNKNOWN

    def __str__(self):
        return str(self.name)

    @classmethod
    def v20_namespaces(cls) -> List[str]:
        return [
            protocol.namespace
            for protocol in cls
            if "urn:iso:std:iso:15118:-20" in protocol.namespace
        ]
