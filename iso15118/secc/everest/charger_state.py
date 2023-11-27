# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 - 2023 Pionix GmbH and Contributors to EVerest
from dataclasses import dataclass, field

@dataclass
class ChargerState:
    # Common
    EVSEID = ''
    EVSEID_DIN = ''
    PaymentOptions: list[str] = field(default_factory=list)
    SupportedEnergyTransferMode: list[str] = field(default_factory=list)
    ReceiptRequired = False
    FreeService = False
    EVSEEnergyToBeDelivered = 0
    debug_mode = False
    stop_charging = False
    auth_status = 'Ongoing'
    certificate_status = 'Ongoing'
    EVSE_UtilityInterruptEvent = False
    EVSE_EmergencyShutdown = False
    EVSE_Malfunction = False
    powermeter: dict = field(default_factory=dict)
    certificate_service_supported = False
    existream_status: dict = field(default_factory=dict)
    dlink_ready = False

    # AC
    EVSENominalVoltage = 0
    ContactorError = False
    RCD_Error = False
    EVSEMaxCurrent = 0
    contactorClosed = False
    contactorOpen = True

    # DC
    EVSEPeakCurrentRipple = 0
    EVSECurrentRegulationTolerance = 0
    EVSEPresentVoltage = 0
    EVSEPresentCurrent = 0
    EVSEMaximumCurrentLimit = 0
    EVSEMaximumPowerLimit = 0
    EVSEMaximumVoltageLimit = 0
    EVSEMinimumCurrentLimit = 0
    EVSEMinimumVoltageLimit = 0
    EVSEIsolationStatus = 'Invalid'
    cableCheck_Finished = False

    def reset(self):
        # Common
        self.stop_charging = False
        self.auth_status = 'Ongoing'
        self.certificate_status = 'Ongoing'
        self.EVSE_UtilityInterruptEvent = False
        self.EVSE_EmergencyShutdown = False
        self.EVSE_Malfunction = False
        self.existream_status = dict()

        # AC
        self.ContactorError = False
        self.contactorClosed = False
        self.contactorOpen = True
        self.RCD_Error = False

        # DC
        self.EVSEIsolationStatus = 'Invalid'
        self.cableCheck_Finished = False
