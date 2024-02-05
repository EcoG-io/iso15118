from dataclasses import dataclass
from typing import Optional, Union

from iso15118.secc.controller.common import Limits


@dataclass
class EVSEACCPDLimits(Limits):
    """Holds the EVSE's rated AC limits to be returned during
    Charge Parameter Discovery state."""

    # 15118-2 AC CPD
    evse_nominal_voltage: Optional[float] = None  # Also required for 15118-20 CPD
    evse_max_current: Optional[float] = None  # Required

    # 15118-20 AC CPD (Required)
    evse_max_charge_power: Optional[float] = None
    evse_min_charge_power: Optional[float] = None

    # 15118-20 AC CPD (Optional)
    evse_max_charge_power_l2: Optional[float] = None
    evse_max_charge_power_l3: Optional[float] = None
    evse_min_charge_power_l2: Optional[float] = None
    evse_min_charge_power_l3: Optional[float] = None
    evse_nominal_frequency: Optional[float] = None
    max_power_asymmetry: Optional[float] = None
    evse_power_ramp_limit: Optional[float] = None

    evse_present_active_power: Optional[float] = None  # Optional in AC Scheduled CL
    evse_present_active_power_l2: Optional[float] = None  # Optional in AC Scheduled CL
    evse_present_active_power_l3: Optional[float] = None  # Optional in AC Scheduled CL


@dataclass
class EVSEACBPTCPDLimits(EVSEACCPDLimits):
    """Holds the EVSE's rated AC BPT limits to be returned during
    Charge Parameter Discovery state."""

    evse_max_discharge_power: Optional[float] = None  # Required
    evse_max_discharge_power_l2: Optional[float] = None  # Optional
    evse_max_discharge_power_l3: Optional[float] = None  # Optional

    evse_min_discharge_power: Optional[float] = None  # Required
    evse_min_discharge_power_l2: Optional[float] = None  # Optional
    evse_min_discharge_power_l3: Optional[float] = None  # Optional


@dataclass
class EVSEDCBPTCPDLimits(Limits):
    """Holds the EVSE's rated DC BPT limits to be returned during
    Charge Parameter Discovery state."""

    # Required in 15118-20 DC BPT CPD
    evse_max_discharge_power: Optional[float] = None
    evse_min_discharge_power: Optional[float] = None
    evse_max_discharge_current: Optional[float] = None
    evse_min_discharge_current: Optional[float] = None


@dataclass
class EVSEDCCPDLimits(EVSEDCBPTCPDLimits):
    """Holds the EVSE's rated DC limits to be returned during
    Charge Parameter Discovery state."""

    # Required in 15118-20 DC CPD
    evse_max_charge_power: Optional[float] = None  # Required for -2 DC, DIN CPD
    evse_min_charge_power: Optional[float] = None  # Not Required for -2 DC, DIN CPD
    evse_max_charge_current: Optional[float] = None  # Required for -2 DC, DIN CPD
    evse_min_charge_current: Optional[float] = None  # Required for -2 DC, DIN CPD
    evse_max_voltage: Optional[float] = None  # Required for -2 DC, DIN CPD
    evse_min_voltage: Optional[float] = None  # Required for -2 DC, DIN CPD

    #  Optional in 15118-20 DC CPD
    evse_power_ramp_limit: Optional[float] = None

    #  Optional in 15118-2 CPD
    evse_current_regulation_tolerance: Optional[float] = None
    evse_peak_current_ripple: Optional[float] = None
    evse_energy_to_be_delivered: Optional[float] = None


@dataclass
class EVSERatedLimits:
    ac_limits: Optional[EVSEACCPDLimits] = None
    ac_bpt_limits: Optional[EVSEACBPTCPDLimits] = None
    dc_limits: Optional[EVSEDCCPDLimits] = None
    dc_bpt_limits: Optional[EVSEDCBPTCPDLimits] = None


@dataclass
class EVSEACCLLimits(Limits):
    # Optional in both Scheduled and Dynamic CL (both AC CL and BPT AC CL)
    evse_target_active_power: Optional[float] = None  # Required in Dynamic AC CL
    evse_target_active_power_l2: Optional[float] = None
    evse_target_active_power_l3: Optional[float] = None
    evse_target_reactive_power: Optional[float] = None
    evse_target_reactive_power_l2: Optional[float] = None
    evse_target_reactive_power_l3: Optional[float] = None
    evse_present_active_power: Optional[float] = None  # Optional in AC CPD
    evse_present_active_power_l2: Optional[float] = None  # Optional in AC CPD
    evse_present_active_power_l3: Optional[float] = None  # Optional in AC CPD


@dataclass
class EVSEDCCLLimits(Limits):
    # Optional in 15118-20 DC Scheduled CL
    evse_max_charge_power: Optional[float] = None  # Required in 15118-20 Dynamic CL
    evse_min_charge_power: Optional[float] = None  # Required in 15118-20 Dynamic CL
    evse_max_charge_current: Optional[float] = None  # Required in 15118-20 Dynamic CL
    evse_max_voltage: Optional[float] = None  # Required in 15118-20 Dynamic CL

    # Optional and present in 15118-20 DC BPT CL (Scheduled)
    evse_max_discharge_power: Optional[float] = None  # Req in 15118-20 Dynamic BPT CL
    evse_min_discharge_power: Optional[float] = None  # Req in 15118-20 Dynamic BPT CL
    evse_max_discharge_current: Optional[float] = None  # Req in 15118-20 Dynamic BPT CL
    evse_min_voltage: Optional[float] = None  # Required in 15118-20 Dynamic BPT CL


@dataclass
class EVSESessionContext:
    # Optional in -20 Dynamic CL Res
    ev_departure_time: Optional[int] = None
    ev_min_soc: Optional[int] = None
    ev_target_soc: Optional[int] = None
    ack_max_delay: Optional[int] = None

    # Required for -2 DC CurrentDemand, -20 DC CL
    evse_present_current: Union[float, int] = 0
    evse_present_voltage: Union[float, int] = 0

    ac_limits: Optional[EVSEACCLLimits] = None
    dc_limits: Optional[EVSEDCCLLimits] = None


@dataclass
class EVSEDataContext:
    rated_limits: Optional[EVSERatedLimits] = None
    session_context: Optional[EVSESessionContext] = None
