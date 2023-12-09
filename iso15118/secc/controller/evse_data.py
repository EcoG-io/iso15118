from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union

from iso15118.secc.controller.common import Limits
from iso15118.shared.messages.datatypes import DCEVSEChargeParameter
from iso15118.shared.messages.iso15118_2.datatypes import ACEVSEChargeParameter


@dataclass
class EVSEACCPDLimits(Limits):
    """Holds the EVSE's rated AC limits to be returned during
    Charge Parameter Discovery state."""

    # 15118-2 AC CPD
    nominal_voltage: Optional[float] = None  # Also required for 15118-20 CPD
    max_current: Optional[float] = None  # Required

    # 15118-20 AC CPD (Required)
    max_charge_power: Optional[float] = None
    min_charge_power: Optional[float] = None

    # 15118-20 AC CPD (Optional)
    max_charge_power_l2: Optional[float] = None
    max_charge_power_l3: Optional[float] = None
    min_charge_power_l2: Optional[float] = None
    min_charge_power_l3: Optional[float] = None
    nominal_frequency: Optional[float] = None
    max_power_asymmetry: Optional[float] = None

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

    
    power_ramp_limit: Optional[float] = None

    #  Optional in 15118-2 CPD
    current_regulation_tolerance: Optional[float] = None
    peak_current_ripple: Optional[float] = None
    energy_to_be_delivered: Optional[float] = None

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
    ):

        self.rated_limits = rated_limits
        self.session_limits = session_limits

        self.current_type: Optional[CurrentType] = None

        #  Optional in 15118-20 DC and AC CPD
        self.power_ramp_limit: Optional[float] = None
        # Metering
        self.present_active_power: Optional[float] = None  # Optional in AC Scheduled CL
        self.present_active_power_l2: Optional[float] = None  # Optional in AC Scheduled CL
        self.present_active_power_l3: Optional[float] = None  # Optional in AC Scheduled CL


        self.ev_departure_time: Optional[int] = None
        self.ev_min_soc: Optional[int] = None
        self.ev_target_soc: Optional[int] = None
        self.ack_max_delay: Optional[int] = None

        # Required for -2 DC CurrentDemand, -20 DC CL
        self.present_current: Union[float, int] = 0
        self.present_voltage: Union[float, int] = 0
   
    def update_ac_charge_parameters_v2(self,
                                       ac_charge_parameter: ACEVSEChargeParameter):
        self.current_type = CurrentType.AC
        rated_limits =  self.rated_limits.ac_limits
        rated_limits.nominal_voltage = ac_charge_parameter.evse_nominal_voltage.get_decimal_value() # noqa: E501
        rated_limits.max_current = ac_charge_parameter.evse_max_current.get_decimal_value()
        rated_limits.max_charge_power = rated_limits.max_current * rated_limits.nominal_voltage
        rated_limits.max_discharge_power = 0
        rated_limits.min_charge_power = 0
        rated_limits.min_discharge_power = 0
        # Create the session limits based on the rated limits
        self.session_limits.ac_limits.update(rated_limits.as_dict())

    def update_dc_charge_parameters_v2(self,
                                       dc_charge_parameter: DCEVSEChargeParameter):
        self.current_type = CurrentType.DC
        rated_limits =  self.rated_limits.dc_limits
        rated_limits.max_charge_power = dc_charge_parameter.evse_maximum_power_limit.get_decimal_value() # noqa: E501
        rated_limits.max_charge_current = dc_charge_parameter.evse_maximum_current_limit.get_decimal_value() # noqa: E501
        rated_limits.max_voltage = dc_charge_parameter.evse_maximum_voltage_limit.get_decimal_value() # noqa: E501
        rated_limits.min_voltage = dc_charge_parameter.evse_minimum_voltage_limit.get_decimal_value() # noqa: E501

        rated_limits.peak_current_ripple = dc_charge_parameter.evse_peak_current_ripple.get_decimal_value() # noqa: E501
        rated_limits.energy_to_be_delivered = dc_charge_parameter.evse_energy_to_be_delivered.get_decimal_value() # noqa: E501
        if dc_charge_parameter.evse_current_regulation_tolerance:
            rated_limits.current_regulation_tolerance = dc_charge_parameter.evse_current_regulation_tolerance.get_decimal_value() # noqa: E501
        if dc_charge_parameter.evse_energy_to_be_delivered:
            rated_limits.energy_to_be_delivered = dc_charge_parameter.evse_energy_to_be_delivered.get_decimal_value() # noqa: E501
        # Create the session limits based on the rated limits
        self.session_limits.dc_limits.update(rated_limits.as_dict())

    # Note that there are no methods to update the session limits as those are updated by the interaction
    # with an external interface like smart charging application, that gets access to the session limits
    # and updates them accordingly. The limits are then natural passed to the EV/EVSE during the
    # Charging Loop.
