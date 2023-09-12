from dataclasses import dataclass
from typing import List, Optional, Union

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
from iso15118.shared.messages.iso15118_20.ac import (
    ACChargeParameterDiscoveryReqParams,
    BPTACChargeParameterDiscoveryReqParams,
    BPTDynamicACChargeLoopReqParams,
    BPTScheduledACChargeLoopReqParams,
    DynamicACChargeLoopReqParams,
    ScheduledACChargeLoopReqParams,
)
from iso15118.shared.messages.iso15118_20.dc import (
    BPTDCChargeParameterDiscoveryReqParams,
    BPTDynamicDCChargeLoopReqParams,
    BPTScheduledDCChargeLoopReqParams,
    DCChargeParameterDiscoveryReqParams,
    DynamicDCChargeLoopReqParams,
    ScheduledDCChargeLoopReqParams,
)


@dataclass
class EVDataContext:
    dc_current_request: Optional[int] = None
    dc_voltage_request: Optional[int] = None
    ac_current: Optional[dict] = None  # {"l1": 10, "l2": 10, "l3": 10}
    ac_voltage: Optional[dict] = None  # {"l1": 230, "l2": 230, "l3": 230}
    soc: Optional[int] = None  # 0-100
    departure_time: Optional[int] = None

    remaining_time_to_full_soc_s: Optional[float] = None
    remaining_time_to_bulk_soc_s: Optional[float] = None
    evcc_id: Optional[str] = None

    # Common to both ISO15118-20 AC and DC
    ev_max_charge_power: Optional[float] = 0.0
    ev_min_charge_power: Optional[float] = 0.0

    # Common to both ISO15118-20 AC-BPT and DC-BPT
    ev_max_discharge_power: Optional[float] = None
    ev_min_discharge_power: Optional[float] = None

    # Specific to ISO 15118-20 AC
    ev_max_charge_power_l2: Optional[float] = None
    ev_max_charge_power_l3: Optional[float] = None
    ev_min_charge_power_l2: Optional[float] = None
    ev_min_charge_power_l3: Optional[float] = None

    # Specific to ISO 15118-20 AC BPT
    ev_max_discharge_power_l2: Optional[float] = None
    ev_max_discharge_power_l3: Optional[float] = None
    ev_min_discharge_power_l2: Optional[float] = None
    ev_min_discharge_power_l3: Optional[float] = None

    # Specific to ISO 15118-20 DC
    ev_max_charge_current: Optional[float] = None
    ev_min_charge_current: Optional[float] = None
    ev_max_voltage: Optional[float] = None
    ev_min_voltage: Optional[float] = None
    target_soc: Optional[int] = None

    # Specific to ISO 15118-20 DC BPT
    ev_max_discharge_current: Optional[float] = None
    ev_min_discharge_current: Optional[float] = None

    ev_target_energy_request: Optional[float] = None
    ev_max_energy_request: Optional[float] = None
    ev_min_energy_request: Optional[float] = None

    # Specific to ISO 151180-20 Dynamic AC CL
    ev_present_active_power: Optional[float] = None
    ev_present_active_power_l2: Optional[float] = None
    ev_present_active_power_l3: Optional[float] = None
    ev_present_reactive_power: Optional[float] = None
    ev_present_reactive_power_l2: Optional[float] = None
    ev_present_reactive_power_l3: Optional[float] = None

    ev_max_v2x_energy_request: Optional[float] = None
    ev_min_v2x_energy_request: Optional[float] = None

    # Seen in Scheduled DC CL
    ev_target_current: Optional[float] = None
    ev_target_voltage: Optional[float] = None

    def update(
        self,
        ev_params: Union[
            DCChargeParameterDiscoveryReqParams,
            BPTDCChargeParameterDiscoveryReqParams,
            ACChargeParameterDiscoveryReqParams,
            BPTACChargeParameterDiscoveryReqParams,
            DynamicACChargeLoopReqParams,
            BPTDynamicACChargeLoopReqParams,
            DynamicDCChargeLoopReqParams,
            BPTDynamicDCChargeLoopReqParams,
            ScheduledACChargeLoopReqParams,
            BPTScheduledACChargeLoopReqParams,
            ScheduledDCChargeLoopReqParams,
            BPTScheduledDCChargeLoopReqParams,
        ],
    ):
        params = ev_params.dict()
        ev_params_dict: dict[str, Union[int, float]] = {}
        for k, v in params.items():
            if type(v) is dict:
                ev_params_dict.update({k: v["value"] * 10 ** v["exponent"]})
            elif type(v) is int:
                ev_params_dict.update({k: v})

        self.__dict__.update(ev_params_dict)

    def as_dict(self):
        return self.__dict__


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
