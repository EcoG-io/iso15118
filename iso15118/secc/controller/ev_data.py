from dataclasses import dataclass
from typing import List, Optional, Union

from iso15118.secc.controller.common import Limits
from iso15118.shared.messages.datatypes import (
    PVEAmount,
    PVEVEnergyRequest,
    PVEVMaxCurrent,
    PVEVMaxCurrentLimit,
    PVEVMaxPowerLimit,
    PVEVMaxVoltage,
    PVEVMaxVoltageLimit,
)
from iso15118.shared.messages.enums import AuthEnum
from iso15118.shared.messages.iso15118_2.datatypes import ChargeService


@dataclass
class EVACCPDLimits(Limits):
    """Holds the AC limits shared by the EV during ChargeParameterDiscovery"""

    ev_max_charge_power: Optional[float] = 0.0
    ev_max_charge_power_l2: Optional[float] = None
    ev_max_charge_power_l3: Optional[float] = None

    ev_min_charge_power: Optional[float] = 0.0
    ev_min_charge_power_l2: Optional[float] = None
    ev_min_charge_power_l3: Optional[float] = None

    ev_max_discharge_power: Optional[float] = None
    ev_max_discharge_power_l2: Optional[float] = None
    ev_max_discharge_power_l3: Optional[float] = None
    ev_min_discharge_power: Optional[float] = None
    ev_min_discharge_power_l2: Optional[float] = None
    ev_min_discharge_power_l3: Optional[float] = None


@dataclass
class EVDCCPDLimits(Limits):
    """Holds the DC limits shared by the EV during ChargeParameterDiscovery"""

    ev_max_charge_power: Optional[float] = 0.0
    ev_min_charge_power: Optional[float] = 0.0
    ev_max_charge_current: Optional[float] = None
    ev_min_charge_current: Optional[float] = None
    ev_max_voltage: Optional[float] = None
    ev_min_voltage: Optional[float] = None
    target_soc: Optional[int] = None

    ev_max_discharge_power: Optional[float] = None
    ev_min_discharge_power: Optional[float] = None
    ev_max_discharge_current: Optional[float] = None
    ev_min_discharge_current: Optional[float] = None


@dataclass
class EVRatedLimits(Limits):
    def __init__(
        self,
        ac_limits: Optional[EVACCPDLimits] = None,
        dc_limits: Optional[EVDCCPDLimits] = None,
    ):
        self.ac_limits = ac_limits or EVACCPDLimits()
        self.dc_limits = dc_limits or EVDCCPDLimits()


@dataclass
class EVACCLLimits(Limits):
    """Holds the AC limits shared by the EV during ChargingLoop.
    Unlike the CPD values, these could potentially change during charing loop"""

    departure_time: Optional[int] = None
    ev_target_energy_request: Optional[float] = None
    ev_max_energy_request: Optional[float] = None
    ev_min_energy_request: Optional[float] = None

    ev_max_charge_power: Optional[float] = None
    ev_max_charge_power_l2: Optional[float] = None
    ev_max_charge_power_l3: Optional[float] = None

    ev_min_charge_power: Optional[float] = None
    ev_min_charge_power_l2: Optional[float] = None
    ev_min_charge_power_l3: Optional[float] = None

    ev_present_active_power: Optional[float] = None
    ev_present_active_power_l2: Optional[float] = None
    ev_present_active_power_l3: Optional[float] = None

    ev_present_reactive_power: Optional[float] = None
    ev_present_reactive_power_l2: Optional[float] = None
    ev_present_reactive_power_l3: Optional[float] = None

    ev_max_discharge_power: Optional[float] = None
    ev_max_discharge_power_l2: Optional[float] = None
    ev_max_discharge_power_l3: Optional[float] = None

    ev_min_discharge_power: Optional[float] = None
    ev_min_discharge_power_l2: Optional[float] = None
    ev_min_discharge_power_l3: Optional[float] = None

    ev_max_v2x_energy_request: Optional[float] = None
    ev_min_v2x_energy_request: Optional[float] = None


@dataclass
class EVDCCLLimits(Limits):
    """Holds the DC limits shared by the EV during ChargingLoop.
    Unlike the CPD values, these could potentially change during charging loop"""

    departure_time: Optional[int] = None
    ev_target_energy_request: Optional[float] = None

    ev_target_current: float = 0.0
    ev_target_voltage: float = 0.0
    ev_max_charge_power: Optional[float] = None
    ev_min_charge_power: Optional[float] = None
    ev_max_charge_current: Optional[float] = None
    ev_max_voltage: Optional[float] = None
    ev_min_voltage: Optional[float] = None

    ev_max_discharge_power: Optional[float] = None
    ev_min_discharge_power: Optional[float] = None
    ev_max_discharge_current: Optional[float] = None

    ev_max_energy_request: Optional[float] = None
    ev_min_energy_request: Optional[float] = None

    ev_max_v2x_energy_request: Optional[float] = None
    ev_min_v2x_energy_request: Optional[float] = None


@dataclass
class EVSessionContext(Limits):
    def __init__(
        self,
        ac_limits: Optional[EVACCLLimits] = None,
        dc_limits: Optional[EVDCCLLimits] = None,
    ):
        self.ac_limits = ac_limits or EVACCLLimits()
        self.dc_limits = dc_limits or EVDCCLLimits()

    dc_current_request: Optional[int] = None
    dc_voltage_request: Optional[int] = None
    ac_current: Optional[dict] = None  # {"l1": 10, "l2": 10, "l3": 10}
    ac_voltage: Optional[dict] = None  # {"l1": 230, "l2": 230, "l3": 230}
    soc: Optional[int] = None  # 0-100

    remaining_time_to_full_soc_s: Optional[float] = None
    remaining_time_to_bulk_soc_s: Optional[float] = None


@dataclass
class EVDataContext:
    def __init__(
        self,
        evcc_id: Optional[str] = None,
        ev_rated_limits: Optional[EVRatedLimits] = None,
        ev_session_context: Optional[EVSessionContext] = None,
    ):
        self.evcc_id = evcc_id or None
        self.ev_rated_limits = ev_rated_limits or EVRatedLimits()
        self.ev_session_context = ev_session_context or EVSessionContext()


@dataclass
class EVChargeParamsLimits:
    ev_max_voltage: Optional[Union[PVEVMaxVoltageLimit, PVEVMaxVoltage]] = None
    ev_max_current: Optional[Union[PVEVMaxCurrentLimit, PVEVMaxCurrent]] = None
    ev_max_power: Optional[PVEVMaxPowerLimit] = None
    e_amount: Optional[PVEAmount] = None
    ev_energy_request: Optional[PVEVEnergyRequest] = None


@dataclass
class EVSessionContext15118:
    # EVSessionContext15118 holds information required to resume a paused session.
    # [V2G2-741] - In a resumed session, the following are reused:
    # 1. SessionID (SessionSetup)
    # 2. PaymentOption that was previously selected (ServiceDiscoveryRes)
    # 3. ChargeService (ServiceDiscoveryRes)
    # 4. SAScheduleTuple (ChargeParameterDiscoveryRes) -
    # Previously selected id must remain the same.
    # However, the entries could reflect the elapsed time
    session_id: Optional[str] = None
    auth_options: Optional[List[AuthEnum]] = None
    charge_service: Optional[ChargeService] = None
    sa_schedule_tuple_id: Optional[int] = None
