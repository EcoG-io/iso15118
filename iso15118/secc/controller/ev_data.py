from dataclasses import dataclass
from enum import Enum
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
from iso15118.shared.messages.iso15118_2.body import (
    ACEVChargeParameter,
    DCEVChargeParameter,
    PreChargeReq,
    CurrentDemandReq
    )
from iso15118.shared.messages.din_spec.body import (
    DCEVChargeParameter as DIN_DCEVChargeParameter,
    PreChargeReq as DIN_PreChargeReq
    )
from iso15118.shared.messages.enums import AuthEnum
from iso15118.shared.messages.iso15118_2.datatypes import ChargeService


@dataclass
class EVACCPDLimits(Limits):
    """Holds the AC limits shared by the EV during ChargeParameterDiscovery"""

    # used in -2
    max_charge_current: Optional[float] = None
    min_charge_current: Optional[float] = None
    max_voltage: Optional[float] = None

    max_charge_power: Optional[float] = 0.0
    max_charge_power_l2: Optional[float] = None
    max_charge_power_l3: Optional[float] = None

    min_charge_power: Optional[float] = 0.0
    min_charge_power_l2: Optional[float] = None
    min_charge_power_l3: Optional[float] = None

    max_discharge_power: Optional[float] = None
    max_discharge_power_l2: Optional[float] = None
    max_discharge_power_l3: Optional[float] = None
    min_discharge_power: Optional[float] = None
    min_discharge_power_l2: Optional[float] = None
    min_discharge_power_l3: Optional[float] = None


@dataclass
class EVDCCPDLimits(Limits):
    """Holds the DC limits shared by the EV during ChargeParameterDiscovery"""

    max_charge_power: Optional[float] = 0.0
    min_charge_power: Optional[float] = 0.0
    max_charge_current: Optional[float] = None
    min_charge_current: Optional[float] = None
    max_voltage: Optional[float] = None
    min_voltage: Optional[float] = None

    max_discharge_power: Optional[float] = None
    min_discharge_power: Optional[float] = None
    max_discharge_current: Optional[float] = None
    min_discharge_current: Optional[float] = None



@dataclass
class EVACCLLimits(Limits):
    """Holds the AC limits shared by the EV during ChargingLoop.
    Unlike the CPD values, these could potentially change during charing loop"""

    max_charge_power: Optional[float] = None
    max_charge_power_l2: Optional[float] = None
    max_charge_power_l3: Optional[float] = None

    min_charge_power: Optional[float] = None
    min_charge_power_l2: Optional[float] = None
    min_charge_power_l3: Optional[float] = None

    max_discharge_power: Optional[float] = None
    max_discharge_power_l2: Optional[float] = None
    max_discharge_power_l3: Optional[float] = None

    min_discharge_power: Optional[float] = None
    min_discharge_power_l2: Optional[float] = None
    min_discharge_power_l3: Optional[float] = None

@dataclass
class EVDCCLLimits(Limits):
    """Holds the DC Power, Current and Voltage limits 
    shared by the EV during ChargingLoop.
    Unlike the CPD values, these could potentially 
    change during charging loop"""

    max_charge_power: Optional[float] = None
    min_charge_power: Optional[float] = None
    max_charge_current: Optional[float] = None
    max_voltage: Optional[float] = None
    min_voltage: Optional[float] = None

    max_discharge_power: Optional[float] = None
    min_discharge_power: Optional[float] = None
    max_discharge_current: Optional[float] = None


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
class EVSessionLimits(Limits):
    def __init__(
        self,
        ac_limits: Optional[EVACCLLimits] = None,
        dc_limits: Optional[EVDCCLLimits] = None,
    ):
        self.ac_limits = ac_limits or EVACCLLimits()
        self.dc_limits = dc_limits or EVDCCLLimits()


class CurrentType(str, Enum):
    AC = "AC"
    DC = "DC"

@dataclass
class EVDataContext:
    def __init__(
        self,
        evcc_id: Optional[str] = None,
        rated_limits: Optional[EVRatedLimits] = None,
        session_limits: Optional[EVSessionLimits] = None,
    ):
        self.evcc_id = evcc_id or None
        self.rated_limits = rated_limits or EVRatedLimits()
        self.session_limits = session_limits or EVSessionLimits()

        current_type: Optional[CurrentType] = None

        # Target request is only set in Schedule mode during
        # Schedule exchange in -20 and in -2 AC CPD (EAmount)
        # and optionaly in -2 DC CPD (EVEnergyRequest)

        # EV driver Emobility Needs
        departure_time: Optional[int] = None
        target_energy_request: Optional[float] = None
        target_soc: Optional[int] = None   # 0-100

        # EV Battery Energy/SOC and V2X Limits
        maximum_energy_request: Optional[float] = None
        minimum_energy_request: Optional[float] = None
        minimum_soc: Optional[int] = None  # 0-100
        maximum_soc: Optional[int] = None  # 0-100
        max_v2x_energy_request: Optional[float] = None
        min_v2x_energy_request: Optional[float] = None
        remaining_time_to_target_soc: Optional[float] = None
        # In -2 is FullSOC
        remaining_time_to_maximum_soc: Optional[float] = None
        remaining_time_to_minimum_soc: Optional[float] = None
        # -20 does not have equivalent for this.
        # This is the time to achieve 80% SoC
        bulk_soc = Optional[float] = None
        remaining_time_to_bulk_soc: Optional[float] = None

        # EV Meter data
        present_soc: Optional[int] = None  # 0-100
        # Sent in -20 PreChargeReq and DC ChargeLoopReq
        present_voltage: Optional[float] = None
        # Only used in AC
        present_active_power: Optional[float] = None
        present_active_power_l2: Optional[float] = None
        present_active_power_l3: Optional[float] = None
        present_reactive_power: Optional[float] = None
        present_reactive_power_l2: Optional[float] = None
        present_reactive_power_l3: Optional[float] = None
        

        # Target EV request
        # DC Scheduled ChargeLoopReq and 
        # -2 CurrentDemand
        target_current: float = 0.0
        # Sent in -2,-20 PreChargeReq 
        # and same as above
        target_voltage: float = 0.0
    
    def update_ac_charge_parameters_v2(self,
                                       ac_ev_charge_parameter: ACEVChargeParameter):
        self.departure_time = ac_ev_charge_parameter.departure_time
        self.target_energy_request = ac_ev_charge_parameter.e_amount.get_decimal_value()
        self.rated_limits.ac_limits.max_voltage = ac_ev_charge_parameter.ev_max_voltage.get_decimal_value()
        self.rated_limits.ac_limits.max_charge_current = ac_ev_charge_parameter.ev_max_current.get_decimal_value()
        self.rated_limits.ac_limits.min_charge_current = ac_ev_charge_parameter.ev_min_current.get_decimal_value()
    

    def update_dc_charge_parameters(self,
                                    dc_ev_charge_parameter: Union[DCEVChargeParameter, DIN_DCEVChargeParameter]):
        try:
            self.departure_time = dc_ev_charge_parameter.departure_time
        except AttributeError:
            # DIN_DCEVChargeParameter does not have departure_time
            pass

        self.present_soc = dc_ev_charge_parameter.dc_ev_status.ev_ress_soc
        self.target_energy_request =  (  # noqa: E501
            None
            if dc_ev_charge_parameter.ev_energy_request is None
            else dc_ev_charge_parameter.ev_energy_request.get_decimal_value()
        )
       
        self.rated_limits.dc_limits.max_voltage = dc_ev_charge_parameter.ev_maximum_voltage_limit.get_decimal_value()

        self.rated_limits.dc_limits.max_charge_current = dc_ev_charge_parameter.ev_maximum_current_limit.get_decimal_value()

        self.rated_limits.dc_limits.max_charge_power = (  # noqa: E501
            None
            if dc_ev_charge_parameter.ev_maximum_power_limit is None
            else dc_ev_charge_parameter.ev_maximum_power_limit.get_decimal_value()
        )
        
        self.maximum_energy_request = (  # noqa: E501
            None
            if dc_ev_charge_parameter.ev_energy_capacity is None
            else dc_ev_charge_parameter.ev_energy_capacity.get_decimal_value()
        )
       
        self.maximum_soc = (  # noqa: E501
            None
            if  dc_ev_charge_parameter.full_soc is None
            else dc_ev_charge_parameter.full_soc
        )
        self.bulk_soc = (  # noqa: E501
            None
            if dc_ev_charge_parameter.bulk_soc is None
            else dc_ev_charge_parameter.bulk_soc
        )
    
    def update_pre_charge(self, pre_charge_req: Union[PreChargeReq, DIN_PreChargeReq]):
        self.present_soc = pre_charge_req.dc_ev_status.ev_ress_soc
        self.target_current = pre_charge_req.ev_target_current.get_decimal_value()
        self.target_voltage = pre_charge_req.ev_target_voltage.get_decimal_value()
    
    def update_charge_loop(self, current_demand_req: CurrentDemandReq):
        self.present_soc = current_demand_req.dc_ev_status.ev_ress_soc
        self.target_current = current_demand_req.ev_target_current.get_decimal_value()
        self.target_voltage = current_demand_req.ev_target_voltage.get_decimal_value()
        self.remaining_time_to_maximum_soc = (  # noqa: E501
            None
            if current_demand_req.remaining_time_to_full_soc is None
            else current_demand_req.remaining_time_to_full_soc.get_decimal_value()
        )
        self.remaining_time_to_bulk_soc = (  # noqa: E501
            None
            if current_demand_req.remaining_time_to_bulk_soc is None
            else current_demand_req.remaining_time_to_bulk_soc.get_decimal_value()
        )
        self.session_limits.dc_limits.max_charge_current = (  # noqa: E501
            None
            if current_demand_req.ev_max_current_limit is None
            else current_demand_req.ev_max_current_limit.get_decimal_value()
        )
        self.session_limits.dc_limits.max_charge_power = (  # noqa: E501
            None
            if current_demand_req.ev_max_power_limit is None
            else current_demand_req.ev_max_power_limit.get_decimal_value()
        )
        self.session_limits.dc_limits.max_voltage = (  # noqa: E501
            None
            if current_demand_req.ev_max_voltage_limit is None
            else current_demand_req.ev_max_voltage_limit.get_decimal_value()
        )


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
