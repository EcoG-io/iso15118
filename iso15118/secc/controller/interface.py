"""
This module contains the abstract class for an SECC to retrieve data from the EVSE
(Electric Vehicle Supply Equipment).
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Union

from iso15118.shared.messages.enums import Protocol
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVSEChargeParameter,
    ACEVSEStatus,
    DCEVSEChargeParameter,
    DCEVSEStatus,
    EnergyTransferModeEnum,
)
from iso15118.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
    SAScheduleTupleEntry,
)
from iso15118.shared.messages.iso15118_20.common_messages import ProviderID
from iso15118.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20


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
