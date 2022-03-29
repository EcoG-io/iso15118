"""
This module contains the abstract class for an SECC to retrieve data from the EVSE
(Electric Vehicle Supply Equipment).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Union

from iso15118.shared.messages.enums import Protocol
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVSEChargeParameter,
    ACEVSEStatus,
    DCEVSEChargeParameter,
    DCEVSEStatus,
    EnergyTransferModeEnum, PVEVTargetVoltage, PVEVTargetCurrent, PVEVSEMaxVoltageLimit, PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
)
from iso15118.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
    SAScheduleTupleEntry,
)
from iso15118.shared.messages.iso15118_20.common_messages import ProviderID
from iso15118.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20


@dataclass
class ev_data_context:
    dc_current: Optional[int] = None
    dc_voltage: Optional[int] = None
    ac_current: Optional[dict] = None # {"l1": 10, "l2": 10, "l3": 10}
    ac_voltage: Optional[dict] = None # {"l1": 230, "l2": 230, "l3": 230}
    soc: Optional[int] = None # 0-100


class EVSEControllerInterface(ABC):

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================

    @abstractmethod
    def get_evse_id(self) -> str:
        """
        Gets the ID of the EVSE (Electric Vehicle Supply Equipment), which is
        controlling the energy flow to the connector the EV is plugged into.

        Relevant for:
        - DIN SPEC 70121
        - ISO 15118-2
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    def get_supported_energy_transfer_modes(self) -> List[EnergyTransferModeEnum]:
        """
        The MQTT interface needs to provide the information on the available energy
        transfer modes, which depends on the socket the EV is connected to

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def is_authorised(self) -> bool:
        """
        Provides the information on whether or not the user is authorised to charge at
        this EVSE. The auth token could be an RFID card, a whitelisted MAC address
        of the EV (Autocharge), a contract certificate (Plug & Charge), or a payment
        authorization via NFC or credit card.

        Relevant for:
        - DIN SPEC 70121
        - ISO 15118-2
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    def get_sa_schedule_list(
        self, max_schedule_entries: Optional[int], departure_time: int = 0
    ) -> Optional[List[SAScheduleTupleEntry]]:
        """
        Requests the charging schedule from a secondary actor (SA) like a
        charge point operator, if available. If no backend information is given
        regarding the restrictions imposed on an EV charging profile, then the
        charging schedule is solely influenced by the max rating of the charger
        and the ampacity of the charging cable.

        Args:
            max_schedule_entries: The maximum amount of schedule entries the EVCC
                                  can handle, or None if not provided
            departure_time: The departure time given in seconds from the time of
                            sending the ChargeParameterDiscoveryReq. If the
                            request doesn't provide a departure time, then this
                            implies the need to start charging immediately.

        Returns:
            A list of SAScheduleTupleEntry values to influence the EV's charging profile
            if the backend/charger can provide the information already, or None if
            the calculation is still ongoing.

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_meter_info(self, protocol: Protocol) -> Union[MeterInfoV2, MeterInfoV20]:
        """
        Provides the MeterInfo from the EVSE's smart meter

        Args:
            protocol: The communication protocol enum, used to distinguish between
                      the different MeterInfo types per protocol

        Returns:
            A MeterInfo instance, which contains the meter reading

        Raises:
            InvalidProtocolError

        Relevant for:
        - DIN SPEC 70121  # TODO Add support for DIN SPEC 70121
        - ISO 15118-2
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    def get_supported_providers(self) -> Optional[List[ProviderID]]:
        """
        Provides a list of eMSPs (E-Mobility Service Providers) supported by the SECC.
        This allows EVCC to filter the list of contract certificates to be utilized
        during the authorization.

        Relevant for:
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    def set_hlc_charging(self, is_ongoing: bool) -> None:
        """
        Notify that high level communication is ongoing or not.
        Args:
            is_ongoing (bool): whether hlc charging is ongoing or not.
        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def stop_charger(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def update_ev_data(self, soc: int = None,
                       dc_current: int = None,
                       dc_voltage: int = None,
                       ac_current: dict = None,
                       ac_voltage: dict = None):
        raise NotImplementedError

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    @abstractmethod
    def get_ac_evse_status(self) -> ACEVSEStatus:
        """
        Gets the AC-specific EVSE status information

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_ac_evse_charge_parameter(self) -> ACEVSEChargeParameter:
        """
        Gets the AC-specific EVSE charge parameter (for ChargeParameterDiscoveryRes)

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    @abstractmethod
    def get_dc_evse_status(self) -> DCEVSEStatus:
        """
        Gets the DC-specific EVSE status information

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_dc_evse_charge_parameter(self) -> DCEVSEChargeParameter:
        """
        Gets the DC-specific EVSE charge parameter (for ChargeParameterDiscoveryRes)

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_evse_present_voltage(self) -> PVEVSEPresentVoltage:
        """
        Gets the presently available voltage at the EVSE

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_evse_present_current(self) -> PVEVSEPresentCurrent:
        """
        Gets the presently available voltage at the EVSE

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def set_precharge(self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent):
        """
        Sets the precharge information coming from the EV.
        The charger must adapt it's output voltage to the requested voltage from the EV.
        The current may not exceed 2A (according 61851-23)

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def start_cable_check(self):
        """
        This method is called at the beginning of the state CableCheck.
        It requests the charger to perform a CableCheck

        Relevant for:
        - ISO 15118-2
        """
        #
        raise NotImplementedError

    @abstractmethod
    def send_charging_command(self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent):
        """
        This method is called in the state CurrentDemand. The values target current
        and target voltage from the EV are passed.
        These information must be provided for the charger's power electronics.

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_evse_current_limit_achieved(self) -> bool:
        """
        Returns true if the current limit of the charger has achieved

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_evse_voltage_limit_achieved(self) -> bool:
        """
        Returns true if the voltage limit of the charger has achieved

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_evse_power_limit_achieved(self) -> bool:
        """
        Returns true if the power limit of the charger has achieved

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
        """
        Gets the max voltage that can be provided by the charger

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
        """
        Gets the max current that can be provided by the charger

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def get_evse_max_power_limit(self) -> PVEVSEMaxPowerLimit:
        """
        Gets the max power that can be provided by the charger

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError
