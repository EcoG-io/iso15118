"""
This module contains the abstract class for an SECC to retrieve data from the EVSE
(Electric Vehicle Supply Equipment).
"""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Union, cast

from iso15118.secc.controller.ev_data import EVDataContext
from iso15118.secc.controller.evse_data import CurrentType, EVSEDataContext
from iso15118.shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    PhysicalValue,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
)
from iso15118.shared.messages.din_spec.datatypes import (
    ResponseCode as ResponseCodeDINSPEC,
)
from iso15118.shared.messages.din_spec.datatypes import (
    SAScheduleTupleEntry as SAScheduleTupleEntryDINSPEC,
)
from iso15118.shared.messages.enums import (
    AuthorizationStatus,
    AuthorizationTokenType,
    ControlMode,
    CpState,
    EnergyTransferModeEnum,
    IsolationLevel,
    Protocol,
    ServiceV20,
    SessionStopAction,
    UnitSymbol,
)
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVSEChargeParameter,
    ACEVSEStatus,
)
from iso15118.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118.shared.messages.iso15118_2.datatypes import ResponseCode as ResponseCodeV2
from iso15118.shared.messages.iso15118_2.datatypes import SAScheduleTuple
from iso15118.shared.messages.iso15118_20.ac import (
    ACChargeParameterDiscoveryResParams,
    BPTACChargeParameterDiscoveryResParams,
    BPTDynamicACChargeLoopResParams,
    BPTScheduledACChargeLoopResParams,
    DynamicACChargeLoopResParams,
    ScheduledACChargeLoopResParams,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    DynamicScheduleExchangeResParams,
    ProviderID,
    ScheduledScheduleExchangeResParams,
    ScheduleExchangeReq,
    SelectedEnergyService,
    ServiceList,
    ServiceParameterList,
)
from iso15118.shared.messages.iso15118_20.common_types import EVSEStatus
from iso15118.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20
from iso15118.shared.messages.iso15118_20.common_types import RationalNumber
from iso15118.shared.messages.iso15118_20.common_types import (
    ResponseCode as ResponseCodeV20,
)
from iso15118.shared.messages.iso15118_20.dc import (
    BPTDCChargeParameterDiscoveryResParams,
    BPTDynamicDCChargeLoopRes,
    BPTScheduledDCChargeLoopResParams,
    DCChargeParameterDiscoveryResParams,
    DynamicDCChargeLoopRes,
    ScheduledDCChargeLoopResParams,
)
from iso15118.shared.states import State

logger = logging.getLogger(__name__)


@dataclass
class AuthorizationResponse:
    authorization_status: AuthorizationStatus
    certificate_response_status: Optional[
        Union[ResponseCodeV2, ResponseCodeV20, ResponseCodeDINSPEC]
    ] = None


class ServiceStatus(str, Enum):
    READY = "ready"
    STARTING = "starting"
    STOPPING = "stopping"
    ERROR = "error"
    BUSY = "busy"


class EVSEControllerInterface(ABC):
    def __init__(self):
        self.ev_data_context = EVDataContext()
        self.evse_data_context = EVSEDataContext()

        self._selected_protocol: Optional[Protocol] = None

    def reset_ev_data_context(self):
        self.ev_data_context = EVDataContext()

    def get_ev_data_context(self) -> EVDataContext:
        return self.ev_data_context

    def set_evse_data_context(self, evse_data_context: EVSEDataContext) -> None:
        self.evse_data_context = evse_data_context

    def get_evse_data_context(self) -> EVSEDataContext:
        return self.evse_data_context

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================

    @abstractmethod
    async def set_status(self, status: ServiceStatus) -> None:
        """
        Sets the new status for the EVSE Controller
        """
        raise NotImplementedError

    @abstractmethod
    async def get_evse_id(self, protocol: Protocol) -> str:
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
    async def get_supported_energy_transfer_modes(
        self, protocol: Protocol
    ) -> List[EnergyTransferModeEnum]:
        """
        The available energy transfer modes, which depends on the socket the EV is
        connected to.

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_schedule_exchange_params(
        self,
        selected_energy_service: SelectedEnergyService,
        control_mode: ControlMode,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> Optional[
        Union[ScheduledScheduleExchangeResParams, DynamicScheduleExchangeResParams]
    ]:
        """
        Gets the parameters for a ScheduleExchangeResponse.
        If the parameters are not yet ready when requested,
        return None.

        Args:
            selected_energy_service: The energy services, which the EVCC selected.
                                     The selected parameter set, that is associated
                                     with that energy service, influences the
                                     parameters for the ScheduleExchangeRes
            control_mode: Control mode for this session - Scheduled/Dynamic
            schedule_exchange_req: The ScheduleExchangeReq, whose parameters influence
                                   the parameters for the ScheduleExchangeRes

        Returns:
            Parameters for the ScheduleExchangeRes, if
            readily available. If you're still waiting for all parameters, return None.

        Relevant for:
        - ISO 15118-20
        """

    @abstractmethod
    async def get_energy_service_list(self) -> ServiceList:
        """
        The available energy transfer services

        Relevant for:
        - ISO 15118-20
        """
        raise NotImplementedError

    def is_eim_authorized(self) -> bool:
        """
        it returns true when an rfid authentication before plugging in.
        Relevant for:
        - ISO 15118-2
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def is_authorized(
        self,
        id_token: Optional[str] = None,
        id_token_type: Optional[AuthorizationTokenType] = None,
        certificate_chain: Optional[bytes] = None,
        hash_data: Optional[List[Dict[str, str]]] = None,
    ) -> AuthorizationResponse:
        """
        Provides the information on whether or not the user is authorized to charge at
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
    async def get_sa_schedule_list(
        self,
        ev_data_context: EVDataContext,
        is_free_charging_service: bool,
        max_schedule_entries: Optional[int],
        departure_time: int = 0,
    ) -> Optional[List[SAScheduleTuple]]:
        """
        Requests the charging schedule from a secondary actor (SA) like a
        charge point operator, if available. If no backend information is given
        regarding the restrictions imposed on an EV charging profile, then the
        charging schedule is solely influenced by the max rating of the charger
        and the ampacity of the charging cable.

        Args:
            ev_data_context: contains all the limits of the EV for AC and DC
            is_free_charging_service: Indicates if free sa schedules are to be returned.
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
    async def get_sa_schedule_list_dinspec(
        self, max_schedule_entries: Optional[int], departure_time: int = 0
    ) -> Optional[List[SAScheduleTupleEntryDINSPEC]]:
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
    async def get_meter_info_v2(self) -> MeterInfoV2:
        """
        Provides the MeterInfo from the EVSE's smart meter

        Returns:
            A MeterInfo instance, which contains the meter reading

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_meter_info_v20(self) -> MeterInfoV20:
        """
        Provides the MeterInfo from the EVSE's smart meter

        Returns:
            A MeterInfo instance, which contains the meter reading

        Relevant for:
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def get_supported_providers(self) -> Optional[List[ProviderID]]:
        """
        Provides a list of eMSPs (E-Mobility Service Providers) supported by the SECC.
        This allows EVCC to filter the list of contract certificates to be utilized
        during the authorization.

        Relevant for:
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def set_hlc_charging(self, is_ongoing: bool) -> None:
        """
        Notify that high level communication is ongoing or not.
        Args:
            is_ongoing (bool): whether hlc charging is ongoing or not.
        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_cp_state(self) -> CpState:
        """
        Returns current cp state

        Relevant for:
        - IEC 61851-1
        """
        raise NotImplementedError

    @abstractmethod
    async def service_renegotiation_supported(self) -> bool:
        """
        Whether or not service renegotiation is supported

        Relevant for:
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def get_service_parameter_list(
        self, service_id: int
    ) -> Optional[ServiceParameterList]:
        """
        Provides a list of parameters for a specific service ID for which the EVCC
        requests additional information.

        Args:
            service_id: The service ID, according to Table 204 (ISO 15118-20)

        Returns:
            A ServiceParameterList instance for the requested service ID, or None if
            that service is not supported.

        Relevant for:
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def stop_charger(self) -> None:
        raise NotImplementedError

    @abstractmethod
    async def is_contactor_opened(self) -> bool:
        """
        Sends a command to the SECC to get the contactor status is opened to terminate
        energy flow

        Relevant for:
        - all protocols
        """
        raise NotImplementedError

    @abstractmethod
    async def is_contactor_closed(self) -> bool:
        """
        Sends a command to the SECC to get the contactor status is closed

        Relevant for:
        - all protocols
        """
        raise NotImplementedError

    @abstractmethod
    async def get_evse_status(self) -> Optional[EVSEStatus]:
        """
        Gets the status of the EVSE

        Relevant for:
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def set_present_protocol_state(self, state: State):
        """
        This method sets the present state of the charging protocol.

        Relevant for:
        - DIN SPEC 70121
        - ISO 15118-2
        """
        raise NotImplementedError

    def set_selected_protocol(self, protocol: Protocol) -> None:
        """Set the selected Protocol.

        Args:
            protocol: An EV communication protocol supported by Josev.
        """
        self._selected_protocol = protocol

    def get_selected_protocol(self) -> Optional[Protocol]:
        """Get the selected Protocol."""
        return self._selected_protocol

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    @abstractmethod
    async def get_ac_evse_status(self) -> ACEVSEStatus:
        """
        Gets the AC-specific EVSE status information

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_ac_charge_params_v2(self) -> ACEVSEChargeParameter:
        """
        Gets the AC-specific EVSE charge parameter (for ChargeParameterDiscoveryRes)

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_ac_charge_params_v20(
        self, energy_service: ServiceV20
    ) -> Optional[
        Union[
            ACChargeParameterDiscoveryResParams, BPTACChargeParameterDiscoveryResParams
        ]
    ]:
        """
        Gets the charge parameters needed for a ChargeParameterDiscoveryRes for
        AC/AC_BPT charging.

        Relevant for:
        - ISO 15118-20
        """
        raise NotImplementedError

    async def get_ac_charge_loop_params_v20(
        self, control_mode: ControlMode, selected_service: ServiceV20
    ) -> Union[
        ScheduledACChargeLoopResParams,
        BPTScheduledACChargeLoopResParams,
        DynamicACChargeLoopResParams,
        BPTDynamicACChargeLoopResParams,
    ]:
        """
        Gets the parameters for the ACChargeLoopRes for the currently set control mode
         and service.
        Args:
            control_mode: Control mode for this session - Scheduled/Dynamic
            selected_service: Enum for this Service - AC/AC_BPT
        Returns:
            ChargeLoop params depending on the selected mode. Return object could be
            one of the following types:
            [
                ScheduledACChargeLoopResParams,
                BPTScheduledACChargeLoopResParams,
                DynamicACChargeLoopResParams,
                BPTDynamicACChargeLoopResParams,
            ]
        Relevant for:
        - ISO 15118-20
        """
        """Get AC CL parameters 15118-20."""
        evse_session_limits = self.evse_data_context.session_limits.ac_limits
        # TODO: read the rated limits
        # Active Power
        target_active_power = evse_session_limits.max_charge_power
        target_active_power_l2 = None
        target_active_power_l3 = None
        target_reactive_power = None
        target_reactive_power_l2 = None
        target_reactive_power_l3 = None
        target_active_power_value = RationalNumber.get_rational_repr(
            target_active_power
        )
        if evse_session_limits.max_charge_power_l2:
            target_active_power_l2 = evse_session_limits.max_charge_power_l2
            target_active_power_l2 = RationalNumber.get_rational_repr(
                target_active_power_l2
            )  # noqa
        if evse_session_limits.max_charge_power_l3:
            target_active_power_l3 = evse_session_limits.max_charge_power_l3
            target_active_power_l3 = RationalNumber.get_rational_repr(
                target_active_power_l3
            )  # noqa
        # Reactive Power
        if evse_session_limits.max_charge_reactive_power:
            target_reactive_power = evse_session_limits.max_charge_reactive_power
            target_reactive_power = RationalNumber.get_rational_repr(
                target_reactive_power
            )  # noqa
        if evse_session_limits.max_charge_reactive_power_l2:
            target_reactive_power_l2 = evse_session_limits.max_charge_reactive_power_l2
            target_reactive_power_l2 = RationalNumber.get_rational_repr(
                target_reactive_power_l2
            )
        if evse_session_limits.max_charge_reactive_power_l3:
            target_reactive_power_l3 = evse_session_limits.max_charge_reactive_power_l3
            target_reactive_power_l3 = RationalNumber.get_rational_repr(
                target_reactive_power_l3
            )
        # Present Power
        present_active_power = self.evse_data_context.present_active_power
        present_active_power = RationalNumber.get_rational_repr(
            present_active_power
        )  # noqa
        present_active_power_l2 = self.evse_data_context.present_active_power_l2
        present_active_power_l2 = RationalNumber.get_rational_repr(
            present_active_power_l2
        )  # noqa
        present_active_power_l3 = self.evse_data_context.present_active_power_l3
        present_active_power_l3 = RationalNumber.get_rational_repr(
            present_active_power_l3
        )  # noqa
        if (
            control_mode == ControlMode.DYNAMIC
            and selected_service == ServiceV20.AC_BPT
        ):
            # BPT Dynamic Message
            bpt_dynamic_params = BPTDynamicACChargeLoopResParams(
                evse_target_active_power=target_active_power_value,
                evse_target_active_power_l2=target_active_power_l2,
                evse_target_active_power_l3=target_active_power_l3,
                evse_target_reactive_power=target_reactive_power,
                evse_target_reactive_power_l2=target_reactive_power_l2,
                evse_target_reactive_power_l3=target_reactive_power_l3,
                evse_present_active_power=present_active_power,
                evse_present_active_power_l2=present_active_power_l2,
                evse_present_active_power_l3=present_active_power_l3,
            )
            return bpt_dynamic_params
        elif (
            control_mode == ControlMode.SCHEDULED
            and selected_service == ServiceV20.AC_BPT
        ):
            bpt_scheduled_params = BPTScheduledACChargeLoopResParams(
                evse_target_active_power=target_active_power_value,
                evse_target_active_power_l2=target_active_power_l2,
                evse_target_active_power_l3=target_active_power_l3,
                evse_target_reactive_power=target_reactive_power,
                evse_target_reactive_power_l2=target_reactive_power_l2,
                evse_target_reactive_power_l3=target_reactive_power_l3,
                evse_present_active_power=present_active_power,
                evse_present_active_power_l2=present_active_power_l2,
                evse_present_active_power_l3=present_active_power_l3,
            )
            return bpt_scheduled_params
        elif control_mode == ControlMode.DYNAMIC and selected_service == ServiceV20.AC:
            dynamic_params = DynamicACChargeLoopResParams(
                evse_target_active_power=target_active_power_value,
                evse_target_active_power_l2=target_active_power_l2,
                evse_target_active_power_l3=target_active_power_l3,
                evse_target_reactive_power=target_reactive_power,
                evse_target_reactive_power_l2=target_reactive_power_l2,
                evse_target_reactive_power_l3=target_reactive_power_l3,
                evse_present_active_power=present_active_power,
                evse_present_active_power_l2=present_active_power_l2,
                evse_present_active_power_l3=present_active_power_l3,
            )
            return dynamic_params
        else:
            scheduled_params = ScheduledACChargeLoopResParams(
                evse_target_active_power=target_active_power_value,
                evse_target_active_power_l2=target_active_power_l2,
                evse_target_active_power_l3=target_active_power_l3,
                evse_target_reactive_power=target_reactive_power,
                evse_target_reactive_power_l2=target_reactive_power_l2,
                evse_target_reactive_power_l3=target_reactive_power_l3,
                evse_present_active_power=present_active_power,
                evse_present_active_power_l2=present_active_power_l2,
                evse_present_active_power_l3=present_active_power_l3,
            )
            return scheduled_params

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    @abstractmethod
    async def get_dc_evse_status(self) -> DCEVSEStatus:
        """
        Gets the DC-specific EVSE status information

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_dc_charge_parameters(self) -> DCEVSEChargeParameter:
        """
        Gets the DC-specific EVSE charge parameter (for ChargeParameterDiscoveryRes)

        Relevant for:
        - ISO 15118-2
        """
        raise NotImplementedError

    async def get_dc_charge_parameters_dinspec(self) -> DCEVSEChargeParameter:
        """
        Gets the DC-specific EVSE charge parameter (for ChargeParameterDiscoveryRes)

        Relevant for:
        - ISO 15118-2
        """
        return await self.get_dc_charge_parameters()

    async def get_dc_charge_parameters_v2(self) -> DCEVSEChargeParameter:
        """
        Gets the DC-specific EVSE charge parameter (for ChargeParameterDiscoveryRes)

        Relevant for:
        - ISO 15118-2
        """
        return await self.get_dc_charge_parameters()

    async def get_evse_present_voltage(
        self, protocol: Protocol
    ) -> Union[PVEVSEPresentVoltage, RationalNumber]:
        """
        Gets the presently available voltage at the EVSE

        Relevant for:
        - ISO 15118-2
        - ISO 15118-20
        - DINSPEC
        """
        if protocol in [Protocol.DIN_SPEC_70121, Protocol.ISO_15118_2]:
            exponent, value = PhysicalValue.get_exponent_value_repr(
                cast(int, self.evse_data_context.present_voltage)
            )
            return PVEVSEPresentVoltage(multiplier=exponent, value=value, unit="V")
        else:
            return RationalNumber.get_rational_repr(
                self.evse_data_context.present_voltage
            )

    async def get_evse_present_current(
        self, protocol: Protocol
    ) -> Union[PVEVSEPresentCurrent, RationalNumber]:
        """
        Gets the presently available voltage at the EVSE

        Relevant for:
        - ISO 15118-2
        - ISO 15118-20
        - DINSPEC
        """
        if protocol in [Protocol.DIN_SPEC_70121, Protocol.ISO_15118_2]:
            exponent, value = PhysicalValue.get_exponent_value_repr(
                cast(int, self.evse_data_context.present_current)
            )
            return PVEVSEPresentCurrent(multiplier=exponent, value=value, unit="A")
        else:
            return RationalNumber.get_rational_repr(
                self.evse_data_context.present_current
            )

    @abstractmethod
    async def start_cable_check(self):
        """
        This method is called at the beginning of the state CableCheck.
        It requests the charger to perform a CableCheck

        Relevant for:
        - DIN SPEC 70121
        - ISO 15118-2
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def get_cable_check_status(self) -> Union[IsolationLevel, None]:
        """
        This method is called at the beginning of the state CableCheck.
        Gets's the status of a previously started CableCheck

        Relevant for:
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def send_charging_command(
        self,
        ev_target_voltage: Optional[float],
        ev_target_current: Optional[float],
        is_session_bpt: bool = False,
    ):
        """
        This method is called in the state CurrentDemand/DCChargeLoop.
        The values target current and target voltage from the EV are passed.
        The fields discharge_current and discharge_power are relevant during discharge
        in 15118-20. This information must be provided to the charger's
         power electronics.

        Relevant for:
        - DIN SPEC 70121
        - ISO 15118-2
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def is_evse_current_limit_achieved(self):
        """
        Returns true if the current limit of the charger has achieved

        Relevant for:
        - ISO 15118-2
        """
        # TODO retrieve from evse data context
        raise NotImplementedError

    @abstractmethod
    async def is_evse_voltage_limit_achieved(self):
        """
        Returns true if the current limit of the charger has achieved

        Relevant for:
        - ISO 15118-2
        """
        # TODO retrieve from evse data context
        return NotImplementedError

    @abstractmethod
    async def is_evse_power_limit_achieved(self) -> bool:
        """
        Returns true if the current limit of the charger has achieved

        Relevant for:
        - ISO 15118-2
        """
        # TODO retrieve from evse data context
        return False

    async def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
        """
        Gets the max voltage that can be provided by the charger

        Relevant for:
        - ISO 15118-2
        """
        session_limits = self.evse_data_context.session_limits
        voltage_limit = session_limits.dc_limits.max_voltage
        exponent, value = PhysicalValue.get_exponent_value_repr(voltage_limit)
        return PVEVSEMaxVoltageLimit(
            multiplier=exponent,
            value=value,
            unit=UnitSymbol.VOLTAGE,
        )

    async def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
        """
        Gets the max current that can be provided by the charger

        Relevant for:
        - ISO 15118-2
        """
        # This is currently being used by -2 only.
        session_limits = self.evse_data_context.session_limits
        if self.evse_data_context.current_type == CurrentType.AC:
            ac_limits = session_limits.ac_limits
            min_session_power_limit = ac_limits.max_charge_power
            if ac_limits.max_charge_power_l2:
                min_session_power_limit = min(
                    min_session_power_limit, ac_limits.max_charge_power_l2
                )
            if ac_limits.max_charge_power_l3:
                min_session_power_limit = min(
                    min_session_power_limit, ac_limits.max_charge_power_l3
                )
            current_limit_phase = (
                min_session_power_limit / self.evse_data_context.present_voltage
            )
            exponent, value = PhysicalValue.get_exponent_value_repr(current_limit_phase)
        elif self.evse_data_context.current_type == CurrentType.DC:
            current_limit = session_limits.dc_limits.max_charge_current
            exponent, value = PhysicalValue.get_exponent_value_repr(current_limit)
        return PVEVSEMaxCurrentLimit(
            multiplier=exponent,
            value=value,
            unit=UnitSymbol.AMPERE,
        )

    @abstractmethod
    async def get_dc_charge_params_v20(
        self, energy_service: ServiceV20
    ) -> Optional[
        Union[
            DCChargeParameterDiscoveryResParams, BPTDCChargeParameterDiscoveryResParams
        ]
    ]:
        """
        Gets the charge parameters needed for a ChargeParameterDiscoveryRes for
        DC charging.
        """
        raise NotImplementedError

    async def get_evse_max_power_limit(self) -> PVEVSEMaxPowerLimit:
        """
        Gets the max power that can be provided by the charger

        Relevant for:
        - ISO 15118-2
        """
        session_limits = self.evse_data_context.session_limits
        if session_limits.dc_limits.max_charge_power is None:
            return None
        power_limit = session_limits.dc_limits.max_charge_power
        exponent, value = PhysicalValue.get_exponent_value_repr(power_limit)
        return PVEVSEMaxPowerLimit(
            multiplier=exponent,
            value=value,
            unit=UnitSymbol.WATT,
        )

    async def get_dc_charge_loop_params_v20(
        self, control_mode: ControlMode, selected_service: ServiceV20
    ) -> Optional[
        Union[
            ScheduledDCChargeLoopResParams,
            BPTScheduledDCChargeLoopResParams,
            DynamicDCChargeLoopRes,
            BPTDynamicDCChargeLoopRes,
        ]
    ]:
        """
        Gets the parameters for the DCChargeLoopRes for the currently set control mode
         and service.
        Args:
            control_mode: Control mode for this session - Scheduled/Dynamic
            selected_service: Enum for this Service - DC/DC_BPT
        Returns:
            ChargeLoop params depending on the selected mode. Return object could be
            one of the following types:
            [
                ScheduledDCChargeLoopResParams,
                BPTScheduledDCChargeLoopResParams,
                DynamicDCChargeLoopRes,
                BPTDynamicDCChargeLoopRes,
            ]
        Relevant for:
        - ISO 15118-20
        """
        evse_session_limits = self.evse_data_context.session_limits.dc_limits
        evse_max_charge_power = evse_session_limits.max_charge_power
        evse_min_charge_power = evse_session_limits.min_charge_power
        evse_max_charge_current = evse_session_limits.max_charge_current
        evse_max_voltage = evse_session_limits.max_voltage
        if selected_service == ServiceV20.DC:
            if control_mode == ControlMode.SCHEDULED:
                scheduled_params = ScheduledDCChargeLoopResParams(
                    evse_maximum_charge_power=RationalNumber.get_rational_repr(
                        evse_max_charge_power
                    ),
                    evse_minimum_charge_power=RationalNumber.get_rational_repr(
                        evse_min_charge_power
                    ),
                    evse_maximum_charge_current=RationalNumber.get_rational_repr(
                        evse_max_charge_current
                    ),
                    evse_maximum_voltage=RationalNumber.get_rational_repr(
                        evse_max_voltage
                    ),
                )
                return scheduled_params
            elif control_mode == ControlMode.DYNAMIC:
                dynamic_params = DynamicDCChargeLoopRes(
                    departure_time=self.evse_data_context.departure_time,  # noqa
                    min_soc=self.evse_data_context.min_soc,
                    target_soc=self.evse_data_context.target_soc,
                    ack_max_delay=self.evse_data_context.ack_max_delay,
                    evse_maximum_charge_power=RationalNumber.get_rational_repr(
                        evse_max_charge_power
                    ),
                    evse_minimum_charge_power=RationalNumber.get_rational_repr(
                        evse_min_charge_power
                    ),
                    evse_maximum_charge_current=RationalNumber.get_rational_repr(
                        evse_max_charge_current
                    ),
                    evse_maximum_voltage=RationalNumber.get_rational_repr(
                        evse_max_voltage
                    ),
                )
                return dynamic_params
            return None
        elif selected_service == ServiceV20.DC_BPT:
            evse_max_discharge_power = evse_session_limits.max_discharge_power
            evse_min_discharge_power = evse_session_limits.min_discharge_power
            evse_max_discharge_current = evse_session_limits.max_discharge_current
            evse_min_voltage = evse_session_limits.min_voltage
            if control_mode == ControlMode.SCHEDULED:
                bpt_scheduled_params = BPTScheduledDCChargeLoopResParams(
                    evse_maximum_charge_power=RationalNumber.get_rational_repr(
                        evse_max_charge_power
                    ),
                    evse_minimum_charge_power=RationalNumber.get_rational_repr(
                        evse_min_charge_power
                    ),
                    evse_maximum_charge_current=RationalNumber.get_rational_repr(
                        evse_max_charge_current
                    ),
                    evse_maximum_voltage=RationalNumber.get_rational_repr(
                        evse_max_voltage
                    ),
                    evse_max_discharge_power=RationalNumber.get_rational_repr(
                        evse_max_discharge_power
                    ),
                    evse_min_discharge_power=RationalNumber.get_rational_repr(
                        evse_min_discharge_power
                    ),
                    evse_max_discharge_current=RationalNumber.get_rational_repr(
                        evse_max_discharge_current
                    ),
                    evse_min_voltage=RationalNumber.get_rational_repr(evse_min_voltage),
                )
                return bpt_scheduled_params
            else:
                bpt_dynamic_params = BPTDynamicDCChargeLoopRes(
                    departure_time=self.evse_data_context.departure_time,  # noqa
                    min_soc=self.evse_data_context.min_soc,
                    target_soc=self.evse_data_context.target_soc,
                    ack_max_delay=self.evse_data_context.ack_max_delay,
                    evse_maximum_charge_power=RationalNumber.get_rational_repr(
                        evse_max_charge_power
                    ),
                    evse_minimum_charge_power=RationalNumber.get_rational_repr(
                        evse_min_charge_power
                    ),
                    evse_maximum_charge_current=RationalNumber.get_rational_repr(
                        evse_max_charge_current
                    ),
                    evse_maximum_voltage=RationalNumber.get_rational_repr(
                        evse_max_voltage
                    ),
                    evse_max_discharge_power=RationalNumber.get_rational_repr(
                        evse_max_discharge_power
                    ),
                    evse_min_discharge_power=RationalNumber.get_rational_repr(
                        evse_min_discharge_power
                    ),
                    evse_max_discharge_current=RationalNumber.get_rational_repr(
                        evse_max_discharge_current
                    ),
                    evse_min_voltage=RationalNumber.get_rational_repr(evse_min_voltage),
                )
                return bpt_dynamic_params
        else:
            logger.error(f"Energy service {selected_service.name} not yet supported")
            return None

    @abstractmethod
    async def get_15118_ev_certificate(
        self, base64_encoded_cert_installation_req: str, namespace: str
    ) -> str:
        """
        Used to fetch base64 encoded CertificateInstallationRes from CPO backend.
        Args:
         base64_encoded_cert_installation_req : This is the CertificateInstallationReq
         from the EV in base64 encoded form.
         namespace: This would be the namespace to be passed to the backend and depends
          on the protocol.
         15118-2:  "urn:iso:15118:2:2013:MsgDef"
         15118-20: "urn:iso:std:iso:15118:-20:CommonMessages"
        Returns:
         CertificateInstallationRes EXI stream in base64 encoded form.

        Relevant for:
        - ISO 15118-20 and ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def update_data_link(self, action: SessionStopAction) -> None:
        """
        Called when EV requires termination or pausing of the charging session.
        Args:
            action : SessionStopAction
        Relevant for:
        - ISO 15118-20 and ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    def ready_to_charge(self) -> bool:
        """
        Used by Authorization state to indicate if we are
        ready to start charging.
        """
        raise NotImplementedError

    @abstractmethod
    async def session_ended(self, current_state: str, reason: str):
        """
        Indicate the reason for stopping charging.
        """
        raise NotImplementedError
