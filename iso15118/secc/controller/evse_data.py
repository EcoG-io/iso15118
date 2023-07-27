from dataclasses import dataclass
from typing import Optional


@dataclass
class EVSEDataContext:
    # EVSE -20 DC
    evse_max_charge_power: Optional[float] = None  # Also in -20 AC
    evse_min_charge_power: Optional[float] = None  # Also in -20 AC
    evse_max_charge_current: Optional[float] = None
    evse_min_charge_current: Optional[float] = None
    evse_max_voltage: Optional[float] = None
    evse_min_voltage: Optional[float] = None
    evse_power_ramp_limit: Optional[float] = None  # Also in -20 AC

    # EVSE -20 AC and DC BPT
    evse_max_discharge_power: Optional[float] = None
    evse_min_discharge_power: Optional[float] = None
    evse_max_discharge_current: Optional[float] = None
    evse_min_discharge_current: Optional[float] = None

    # EVSE -20 AC
    evse_max_charge_power_l2: Optional[float] = None
    evse_max_charge_power_l3: Optional[float] = None
    evse_min_charge_power_l2: Optional[float] = None
    evse_min_charge_power_l3: Optional[float] = None
    evse_nominal_frequency: Optional[float] = None
    max_power_asymmetry: Optional[float] = None
    evse_present_active_power: Optional[float] = None
    evse_present_active_power_l2: Optional[float] = None
    evse_present_active_power_l3: Optional[float] = None

    # EVSE -20 AC BPT
    evse_max_discharge_power_l2: Optional[float] = None
    evse_max_discharge_power_l3: Optional[float] = None
    evse_min_discharge_power_l2: Optional[float] = None
    evse_min_discharge_power_l3: Optional[float] = None

    def update(
        self,
        params: dict,
    ):
        evse_params = {}
        for k, v in params.items():
            if type(v) is dict:
                evse_params.update({k: v["value"] * 10 ** v["exponent"]})
            elif type(v) is int:
                evse_params.update({k: v})

        self.__dict__.update(evse_params)

    def as_dict(self):
        return self.__dict__
