"""
This modules contains all timeouts relevant for DIN SPEC 72101, given in seconds.
Refer section 9.6.2
"""

from enum import Enum


class Timeouts(float, Enum):
    """
    Timeout restrictions for request/response message pairs and looping
    messages according to DIN SPEC 72101. Given in seconds
    """

    # Non message specific timings
    # Refer Section 9.6.5.5 (Table 77)
    V2G_EVCC_READYTOCHARGE_TIMEOUT = 150
    V2G_EVCC_COMMUNICATIONSETUP_TIMEOUT = 20
    V2G_EVCC_CABLE_CHECK_TIMEOUT = 40
    V2G_EVCC_PRE_CHARGE_TIMEOUT = 7
    V2G_SECC_CPState_Detection_Timeout = 1.5
    V2G_SECC_CPOscillator_Retain_time = 1.5

    # Message specific timings
    # Refer section 9.6.2 (Table 75)
    SUPPORTED_APP_PROTOCOL_REQ = 2
    SESSION_SETUP_REQ = 2
    SERVICE_DISCOVERY_REQ = 2
    SERVICE_PAYMENT_SELECTION_REQ = 2
    CONTRACT_AUTHENTICATION_REQ = 2
    CHARGE_PARAMETER_DISCOVERY_REQ = 2
    POWER_DELIVERY_REQ = 2
    CABLE_CHECK_REQ = 2
    PRE_CHARGE_REQ = 2
    CURRENT_DEMAND_REQ = 0.25
    WELDING_DETECTION_REQ = 2
    SESSION_STOP_REQ = 2

    V2G_SECC_SEQUENCE_TIMEOUT = 60
