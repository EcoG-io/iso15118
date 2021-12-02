"""
This modules contains all timeouts relevant for ISO 15118-2, given in seconds.
A Timeouts enum is used to refer to both message-specific timeouts (e.g.
SESSION_SETUP_REQ) and timeouts related to a loop of message pairs
(e.g. V2G_EVCC_ONGOING_TIMEOUT).
"""

from enum import Enum


class Timeouts(float, Enum):
    """
    Timeout restrictions for request/response message pairs and looping
    messages according to ISO 15118-2. Given in seconds
    """

    # Non message specific timings
    V2G_EVCC_CABLE_CHECK_TIMEOUT = 40
    V2G_EVCC_PRE_CHARGE_TIMEOUT = 7

    # Message specific timings
    SESSION_SETUP_REQ = 2
    SERVICE_DISCOVERY_REQ = 2
    SERVICE_DETAIL_REQ = 5
    PAYMENT_SERVICE_SELECTION_REQ = 2
    CERTIFICATE_INSTALLATION_REQ = 5
    CERTIFICATE_UPDATE_REQ = 5
    PAYMENT_DETAILS_REQ = 5
    AUTHORIZATION_REQ = 2
    CHARGE_PARAMETER_DISCOVERY_REQ = 2
    CHARGING_STATUS_REQ = 2
    METERING_RECEIPT_REQ = 2
    POWER_DELIVERY_REQ = 5
    CABLE_CHECK_REQ = 2
    PRE_CHARGE_REQ = 2
    CURRENT_DEMAND_REQ = 0.25
    WELDING_DETECTION_REQ = 2
    SESSION_STOP_REQ = 2
