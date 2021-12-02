from enum import Enum


class Timeouts(float, Enum):
    """
    Timeout restrictions for request/response message pairs and
    message sequences according to both ISO 15118-2 and ISO 15118-20.
    Given in seconds
    """

    SDP_REQ = 0.25
    SUPPORTED_APP_PROTOCOL_REQ = 2.0
    V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT = 20.0
    V2G_SECC_SEQUENCE_TIMEOUT = 60
    V2G_EVCC_ONGOING_TIMEOUT = 60
