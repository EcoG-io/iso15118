from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union

from iso15118.secc.controller.common import Limits, UnknownEnergyService
from iso15118.shared.messages.datatypes import DCEVSEChargeParameter
from iso15118.shared.messages.enums import ControlMode, ServiceV20
from iso15118.shared.messages.iso15118_2.datatypes import ACEVSEChargeParameter
from iso15118.shared.messages.iso15118_20.ac import (
    ACChargeParameterDiscoveryRes,
    ACChargeParameterDiscoveryResParams,
    BPTACChargeParameterDiscoveryResParams,
)
from iso15118.shared.messages.iso15118_20.common_messages import ScheduleExchangeRes
from iso15118.shared.messages.iso15118_20.dc import (
    BPTDCChargeParameterDiscoveryResParams,
    DCChargeParameterDiscoveryRes,
    DCChargeParameterDiscoveryResParams,
)


@dataclass
class EVSEACCPDLimits(Limits):
    """Holds the EVSE's rated AC limits to be returned during
    Charge Parameter Discovery state."""

    max_current: Optional[float] = None  # Required

    # 15118-20 AC CPD (Required)
    max_charge_power: Optional[float] = None
    min_charge_power: Optional[float] = None

    # 15118-20 AC CPD (Optional)
    max_charge_power_l2: Optional[float] = None
    max_charge_power_l3: Optional[float] = None
    min_charge_power_l2: Optional[float] = None
    min_charge_power_l3: Optional[float] = None

    max_discharge_power: Optional[float] = None  # Required
    max_discharge_power_l2: Optional[float] = None  # Optional
    max_discharge_power_l3: Optional[float] = None  # Optional

    min_discharge_power: Optional[float] = None  # Required
    min_discharge_power_l2: Optional[float] = None  # Optional
    min_discharge_power_l3: Optional[float] = None  # Optional


@dataclass
class EVSEDCCPDLimits(Limits):
    """Holds the EVSE's rated DC limits to be returned during
    Charge Parameter Discovery state."""

    # Required in 15118-20 DC CPD
    max_charge_power: Optional[float] = None  # Required for -2 DC, DIN CPD
    min_charge_power: Optional[float] = None  # Not Required for -2 DC, DIN CPD
    max_charge_current: Optional[float] = None  # Required for -2 DC, DIN CPD
    min_charge_current: Optional[float] = None  # Required for -2 DC, DIN CPD
    max_voltage: Optional[float] = None  # Required for -2 DC, DIN CPD
    min_voltage: Optional[float] = None  # Required for -2 DC, DIN CPD

    # Required in 15118-20 DC BPT CPD
    max_discharge_power: Optional[float] = None
    min_discharge_power: Optional[float] = None
    max_discharge_current: Optional[float] = None
    min_discharge_current: Optional[float] = None


@dataclass
class EVSEACCLLimits(Limits):
    # Optional in both Scheduled and Dynamic CL (both AC CL and BPT AC CL)
    # ISO 15118-20 defines Targets instead of maximums, but
    # in order to keep consistency with other data structures,
    # we will use maximums here. Besides, in -20 the targets can be positive
    # (charging) or negative (discharging), which is a different command
    # structure than the one used in DC where we have charge and discharge.

    max_charge_power: Optional[float] = None
    max_charge_power_l2: Optional[float] = None
    max_charge_power_l3: Optional[float] = None
    max_charge_reactive_power: Optional[float] = None
    max_charge_reactive_power_l2: Optional[float] = None
    max_charge_reactive_power_l3: Optional[float] = None

    # BPT attributes
    max_discharge_power: Optional[float] = None
    max_discharge_power_l2: Optional[float] = None
    max_discharge_power_l3: Optional[float] = None
    max_discharge_reactive_power: Optional[float] = None
    max_discharge_active_power_l2: Optional[float] = None
    max_discharge_active_power_l3: Optional[float] = None


@dataclass
class EVSEDCCLLimits(Limits):
    # Optional in 15118-20 DC Scheduled CL
    max_charge_power: Optional[float] = None  # Required in 15118-20 Dynamic CL
    min_charge_power: Optional[float] = None  # Required in 15118-20 Dynamic CL
    max_charge_current: Optional[float] = None  # Required in 15118-20 Dynamic CL
    max_voltage: Optional[float] = None  # Required in 15118-20 Dynamic CL
    min_voltage: Optional[float] = None  # Required in 15118-20 Dynamic BPT CL
    # Optional and present in 15118-20 DC BPT CL (Scheduled)
    max_discharge_power: Optional[float] = None  # Req in 15118-20 Dynamic BPT CL
    min_discharge_power: Optional[float] = None  # Req in 15118-20 Dynamic BPT CL
    max_discharge_current: Optional[float] = None  # Req in 15118-20 Dynamic BPT CL


@dataclass
class EVSERatedLimits(Limits):
    def __init__(
        self,
        ac_limits: Optional[EVSEACCPDLimits] = EVSEACCPDLimits(),
        dc_limits: Optional[EVSEDCCPDLimits] = EVSEDCCPDLimits(),
    ):
        self.ac_limits = ac_limits
        self.dc_limits = dc_limits


@dataclass
class EVSESessionLimits(Limits):
    def __init__(
        self,
        ac_limits: Optional[EVSEACCLLimits] = EVSEACCLLimits(),
        dc_limits: Optional[EVSEDCCLLimits] = EVSEDCCLLimits(),
    ):
        self.ac_limits = ac_limits
        self.dc_limits = dc_limits


class CurrentType(str, Enum):
    AC = "AC"
    DC = "DC"


@dataclass
class EVSEDataContext:
    def __init__(
        self,
        rated_limits: EVSERatedLimits = EVSERatedLimits(),
        session_limits: EVSESessionLimits = EVSESessionLimits(),
        departure_time: Optional[int] = None,
        target_soc: Optional[int] = None,
        min_soc: Optional[int] = None,
        ack_max_delay: Optional[int] = None,
        power_ramp_limit: Optional[float] = None,
        nominal_voltage: Optional[float] = None,
        nominal_frequency: Optional[float] = None,
        max_power_asymmetry: Optional[float] = None,
        current_regulation_tolerance: Optional[float] = None,
        peak_current_ripple: Optional[float] = None,
        energy_to_be_delivered: Optional[float] = None,
        present_active_power: Optional[float] = 0,
        present_active_power_l2: Optional[float] = 0,
        present_active_power_l3: Optional[float] = 0,
        present_current: Union[float, int] = 0,
        present_voltage: Union[float, int] = 0,
    ):
        self.rated_limits = rated_limits
        self.session_limits = session_limits

        self.current_type: Optional[CurrentType] = None

        # Emobility Needs
        self.departure_time: Optional[int] = departure_time
        self.target_soc: Optional[int] = target_soc  # 0-100
        self.min_soc: Optional[int] = min_soc  # 0-100
        self.ack_max_delay: Optional[int] = ack_max_delay

        #  Optional in 15118-20 DC and AC CPD
        self.power_ramp_limit: Optional[float] = power_ramp_limit
        # Only used in -20 and -2 AC CPD
        self.nominal_voltage: Optional[float] = nominal_voltage
        self.nominal_frequency: Optional[float] = nominal_frequency
        self.max_power_asymmetry: Optional[float] = max_power_asymmetry

        #  Optional in 15118-2 CPD
        self.current_regulation_tolerance: Optional[float] = (
            current_regulation_tolerance
        )
        self.peak_current_ripple: Optional[float] = peak_current_ripple
        self.energy_to_be_delivered: Optional[float] = energy_to_be_delivered
        # Metering
        self.present_active_power: Optional[float] = (
            present_active_power  # Optional in AC Scheduled CL
        )
        self.present_active_power_l2: Optional[float] = (
            present_active_power_l2  # Optional in AC Scheduled CL
        )
        self.present_active_power_l3: Optional[float] = (
            present_active_power_l3  # Optional in AC Scheduled CL
        )

        # Required for -2 DC CurrentDemand, -20 DC CL
        self.present_current: Union[float, int] = present_current
        self.present_voltage: Union[float, int] = present_voltage

    # Note that there are no methods to update the session limits as
    # those are updated by the interaction
    # with an external interface like a smart charging application, that
    # gets access to the session limits
    # and updates them accordingly. The limits are then naturally
    # passed to the EV/EVSE during the Charging Loop.

    def update_schedule_exchange_parameters(
        self, control_mode: ControlMode, schedule_exchange_res: ScheduleExchangeRes
    ):
        """Update the EVSE data context with the ScheduleExchangeReq parameters"""
        if control_mode == ControlMode.DYNAMIC:
            se_params = schedule_exchange_res.dynamic_params
            if se_params.departure_time:
                self.departure_time = se_params.departure_time
            if se_params.target_soc:
                self.target_soc = se_params.target_soc
            if se_params.min_soc:
                self.min_soc = se_params.min_soc

    def update_ac_charge_parameters_v2(
        self, ac_charge_parameter: ACEVSEChargeParameter
    ) -> None:
        """Update the EVSE data context with the AC charge parameters."""
        self.current_type = CurrentType.AC
        if self.rated_limits.ac_limits is None:
            self.rated_limits.ac_limits = EVSEACCPDLimits()
        rated_limits = self.rated_limits.ac_limits
        if self.session_limits.ac_limits is None:
            self.session_limits.ac_limits = EVSEACCLLimits()
        session_limits = self.session_limits.ac_limits
        self.nominal_voltage = (
            ac_charge_parameter.evse_nominal_voltage.get_decimal_value()
        )  # noqa: E501
        rated_limits.max_current = (
            ac_charge_parameter.evse_max_current.get_decimal_value()
        )

        rated_limits.max_charge_power = rated_limits.max_current * self.nominal_voltage
        rated_limits.max_charge_power_l2 = rated_limits.max_charge_power
        rated_limits.max_charge_power_l3 = rated_limits.max_charge_power
        rated_limits.max_discharge_power = 0
        rated_limits.min_charge_power = 0
        rated_limits.min_discharge_power = 0
        # Create the session limits based on the rated limits
        # without exceeding the rated limits
        for value in vars(rated_limits):
            if hasattr(session_limits, value):
                rated_value = getattr(rated_limits, value)
                session_value = getattr(session_limits, value)
                try:
                    if not session_value or (session_value > rated_value):
                        setattr(session_limits, value, rated_value)
                except TypeError:
                    pass

    def update_dc_charge_parameters(
        self, dc_charge_parameter: DCEVSEChargeParameter
    ) -> None:
        """Update the EVSE data context with the DC charge parameters."""
        self.current_type = CurrentType.DC
        if not self.rated_limits.dc_limits:
            self.rated_limits.dc_limits = EVSEDCCPDLimits()
        rated_limits = self.rated_limits.dc_limits
        if not self.session_limits.dc_limits:
            self.session_limits.dc_limits = EVSEDCCLLimits()
        rated_limits.max_charge_power = (
            dc_charge_parameter.evse_maximum_power_limit.get_decimal_value()
        )
        rated_limits.max_charge_current = (
            dc_charge_parameter.evse_maximum_current_limit.get_decimal_value()
        )
        rated_limits.min_charge_current = (
            dc_charge_parameter.evse_minimum_current_limit.get_decimal_value()
        )
        rated_limits.max_voltage = (
            dc_charge_parameter.evse_maximum_voltage_limit.get_decimal_value()
        )
        rated_limits.min_voltage = (
            dc_charge_parameter.evse_minimum_voltage_limit.get_decimal_value()
        )

        self.peak_current_ripple = (
            dc_charge_parameter.evse_peak_current_ripple.get_decimal_value()
        )
        if dc_charge_parameter.evse_current_regulation_tolerance:
            self.current_regulation_tolerance = (
                dc_charge_parameter.evse_current_regulation_tolerance.get_decimal_value()  # noqa: E501
            )
        if dc_charge_parameter.evse_energy_to_be_delivered:
            self.energy_to_be_delivered = (
                dc_charge_parameter.evse_energy_to_be_delivered.get_decimal_value()
            )
            # Create the session limits based on the rated limits
            # without exceeding the rated limits
            for value in vars(rated_limits):
                if hasattr(self.session_limits.dc_limits, value):
                    rated_value = getattr(rated_limits, value)
                    session_value = getattr(self.session_limits.dc_limits, value)
                    try:
                        if not session_value or (session_value > rated_value):
                            setattr(self.session_limits.dc_limits, value, rated_value)
                    except TypeError:
                        pass

    def update_ac_charge_parameters_v20(
        self,
        energy_service: ServiceV20,
        charge_parameter: ACChargeParameterDiscoveryRes,
    ) -> None:
        """Update the EVSE data context with the
        ACChargeParameterDiscoveryRes parameters"""
        self.current_type = CurrentType.AC
        ac_rated_limits = self.rated_limits.ac_limits = EVSEACCPDLimits()
        self.session_limits = EVSESessionLimits()
        self.session_limits.ac_limits = EVSEACCLLimits()
        params: Union[
            ACChargeParameterDiscoveryResParams, BPTACChargeParameterDiscoveryResParams
        ] = None
        if energy_service == ServiceV20.AC:
            params = charge_parameter.ac_params
            self._update_common_ac_charge_parameters_v20(ac_rated_limits, params)
        elif energy_service == ServiceV20.AC_BPT:
            params = charge_parameter.bpt_ac_params
            self._update_acbpt_charge_parameters_v20(ac_rated_limits, params)
        else:
            raise UnknownEnergyService(f"Unknown Service {energy_service}")
        # Create the session limits based on the rated limits
        self.session_limits.dc_limits.update(ac_rated_limits.as_dict())

    def _update_common_ac_charge_parameters_v20(
        self,
        ac_rated_limits: EVSEACCPDLimits,
        params: Union[
            ACChargeParameterDiscoveryResParams, BPTACChargeParameterDiscoveryResParams
        ],
    ) -> None:
        """Update the EVSE data context with the common
        ACChargeParameterDiscoveryRes parameters"""
        ac_rated_limits.max_charge_power = (
            params.evse_max_charge_power.get_decimal_value()
        )  # noqa: E501
        if params.evse_max_charge_power_l2:
            ac_rated_limits.max_charge_power_l2 = (
                params.evse_max_charge_power_l2.get_decimal_value()
            )  # noqa: E501
        if params.evse_max_charge_power_l3:
            ac_rated_limits.max_charge_power_l3 = (
                params.evse_max_charge_power_l3.get_decimal_value()
            )
        ac_rated_limits.min_charge_power = (
            params.evse_min_charge_power.get_decimal_value()
        )  # noqa: E501
        if params.evse_min_charge_power_l2:
            ac_rated_limits.min_charge_power_l2 = (
                params.evse_min_charge_power_l2.get_decimal_value()
            )  # noqa: E501
        if params.evse_min_charge_power_l3:
            ac_rated_limits.min_charge_power_l3 = (
                params.evse_min_charge_power_l3.get_decimal_value()
            )  # noqa: E501
        self.nominal_frequency = (
            params.evse_nominal_frequency.get_decimal_value()
        )  # noqa: E501
        if params.max_power_asymmetry:
            self.max_power_asymmetry = (
                params.max_power_asymmetry.get_decimal_value()
            )  # noqa: E501
        if params.evse_power_ramp_limit:
            self.power_ramp_limit = (
                params.evse_power_ramp_limit.get_decimal_value()
            )  # noqa: E501
        if params.evse_present_active_power:
            self.present_active_power = (
                params.evse_present_active_power.get_decimal_value()
            )  # noqa: E501
        if params.evse_present_active_power_l2:
            self.present_active_power_l2 = (
                params.evse_present_active_power_l2.get_decimal_value()
            )  # noqa: E501
        if params.evse_present_active_power_l3:
            self.present_active_power_l3 = (
                params.evse_present_active_power_l3.get_decimal_value()
            )  # noqa: E501

    def _update_acbpt_charge_parameters_v20(
        self,
        ac_rated_limits: EVSEACCPDLimits,
        params: BPTACChargeParameterDiscoveryResParams,
    ) -> None:
        """Update the EVSE data context with the
        BPTACChargeParameterDiscoveryRes parameters"""
        self._update_common_ac_charge_parameters_v20(ac_rated_limits, params)
        ac_rated_limits.max_discharge_power = (
            params.evse_max_discharge_power.get_decimal_value()
        )  # noqa: E501
        if params.evse_max_discharge_power_l2:
            ac_rated_limits.max_discharge_power_l2 = (
                params.evse_max_discharge_power_l2.get_decimal_value()
            )  # noqa: E501
        if params.evse_max_discharge_power_l3:
            ac_rated_limits.max_discharge_power_l3 = (
                params.evse_max_discharge_power_l3.get_decimal_value()
            )  # noqa: E501
        ac_rated_limits.min_discharge_power = (
            params.evse_min_discharge_power.get_decimal_value()
        )  # noqa: E501
        if params.evse_min_discharge_power_l2:
            ac_rated_limits.min_discharge_power_l2 = (
                params.evse_min_discharge_power_l2.get_decimal_value()
            )  # noqa: E501
        if params.evse_min_discharge_power_l3:
            ac_rated_limits.min_discharge_power_l3 = (
                params.evse_min_discharge_power_l3.get_decimal_value()
            )  # noqa: E501

    def update_dc_charge_parameters_v20(
        self,
        energy_service: ServiceV20,
        charge_parameter: DCChargeParameterDiscoveryRes,
    ) -> None:
        """Update the EVSE data context with the
        DCChargeParameterDiscoveryRes parameters"""
        self.current_type = CurrentType.DC
        dc_rated_limits = self.rated_limits.dc_limits = EVSEDCCPDLimits()
        self.session_limits = EVSESessionLimits()
        self.session_limits.dc_limits = EVSEDCCLLimits()
        params: Union[
            DCChargeParameterDiscoveryResParams, BPTDCChargeParameterDiscoveryResParams
        ] = None
        if energy_service == ServiceV20.DC:
            params = charge_parameter.dc_params
            self._update_common_dc_charge_parameters_v20(dc_rated_limits, params)
        elif energy_service == ServiceV20.DC_BPT:
            params = charge_parameter.bpt_dc_params
            self._update_dcbpt_charge_parameters_v20(dc_rated_limits, params)
        else:
            raise UnknownEnergyService(f"Unknown Service {energy_service}")
        # Create the session limits based on the rated limits
        self.session_limits.dc_limits.update(dc_rated_limits.as_dict())

    def _update_common_dc_charge_parameters_v20(
        self,
        dc_rated_limits: EVSEDCCPDLimits,
        params: Union[
            DCChargeParameterDiscoveryResParams, BPTDCChargeParameterDiscoveryResParams
        ],
    ) -> None:
        """Update the EVSE data context with the common
        DCChargeParameterDiscoveryRes parameters"""
        dc_rated_limits.max_charge_power = (
            params.evse_max_charge_power.get_decimal_value()
        )  # noqa: E501
        dc_rated_limits.min_charge_power = (
            params.evse_min_charge_power.get_decimal_value()
        )  # noqa: E501
        dc_rated_limits.max_charge_current = (
            params.evse_max_charge_current.get_decimal_value()
        )  # noqa: E501
        dc_rated_limits.min_charge_current = (
            params.evse_min_charge_current.get_decimal_value()
        )  # noqa: E501
        dc_rated_limits.max_voltage = (
            params.evse_max_voltage.get_decimal_value()
        )  # noqa: E501
        dc_rated_limits.min_voltage = (
            params.evse_min_voltage.get_decimal_value()
        )  # noqa: E501
        if params.evse_power_ramp_limit:
            self.power_ramp_limit = (
                params.evse_power_ramp_limit.get_decimal_value()
            )  # noqa: E501

    def _update_dcbpt_charge_parameters_v20(
        self,
        dc_rated_limits: EVSEDCCPDLimits,
        params: BPTDCChargeParameterDiscoveryResParams,
    ) -> None:
        """Update the EVSE data context with the
        BPTDCChargeParameterDiscoveryRes parameters"""
        self._update_common_dc_charge_parameters_v20(dc_rated_limits, params)
        dc_rated_limits.max_discharge_power = (
            params.evse_max_discharge_power.get_decimal_value()
        )  # noqa: E501
        dc_rated_limits.min_discharge_power = (
            params.evse_min_discharge_power.get_decimal_value()
        )  # noqa: E501
        dc_rated_limits.max_discharge_current = (
            params.evse_max_discharge_current.get_decimal_value()
        )  # noqa: E501
        dc_rated_limits.min_discharge_current = (
            params.evse_min_discharge_current.get_decimal_value()
        )  # noqa: E501
