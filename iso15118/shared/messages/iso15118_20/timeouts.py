"""
This modules contains all timeouts relevant for ISO 15118-20, given in seconds.
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
    V2G_EVCC_ONGOING_TIMEOUT = 60
    V2G_EVCC_CABLE_CHECK_TIMEOUT = 40
    V2G_EVCC_PRE_CHARGE_TIMEOUT = 10
    V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT = 20
    V2G_SECC_SEQUENCE_TIMEOUT = 60

    # Message specific timings (Common messages)
    SESSION_SETUP_REQ = 2
    VEHICLE_CHECKIN_REQ = 2
    VEHICLE_CHECKOUT_REQ = 2
    AUTHORIZATION_SETUP_REQ = 2
    AUTHORIZATION_REQ = 2
    CERTIFICATE_INSTALLATION_REQ = 5
    SERVICE_DISCOVERY_REQ = 2
    SERVICE_DETAIL_REQ = 5
    SERVICE_SELECTION_REQ = 2
    CHARGE_PARAMETER_DISCOVERY_REQ = 2
    SCHEDULE_EXCHANGE_REQ = 2
    POWER_DELIVERY_REQ = 2
    METERING_CONFIRMATION_REQ = 2
    SESSION_STOP_REQ = 2

    # Message specific timings (AC messages)
    AC_CHARGE_LOOP_REQ = 0.5
    V2G_SECC_SEQUENCE_TIMEOUT_AC_CL = 0.5  # CL = Charge Loop

    # Message specific timings (DC messages)
    DC_CABLE_CHECK_REQ = 2
    DC_PRE_CHARGE_REQ = 2
    DC_CHARGE_LOOP_REQ = 0.5
    DC_WELDING_DETECTION_REQ = 2
    V2G_SECC_SEQUENCE_TIMEOUT_DC_CL = 0.5  # CL = Charge Loop

    # Message specific timings (ACD messages)
    ACDP_VEHICLE_POSITIONING_REQ = 2
    ACDP_CONNECT_REQ = 2
    ACDP_DISCONNECT_REQ = 2
    ACDP_SYSTEM_STATUS_REQ = 2

    # Message specific timings (WPT messages)
    V2G_SECC_SEQUENCE_TIMEOUT_WPT_CL = 0.5  # CL = Charge Loop
