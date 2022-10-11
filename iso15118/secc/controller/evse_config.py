import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

import dacite
from aiofile import async_open

logger = logging.getLogger(__name__)


class EVSEIsolationStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    WARNING = "warning"
    FAULT = "fault"
    NO_IMD = "no_imd"


class EVSEStatusCode(str, Enum):
    EVSE_NOT_READY = "evse_not_ready"
    EVSE_READY = "evse_ready"
    EVSE_SHUTDOWN = "evse_shutdown"
    # XSD typo in "Interrupt"
    EVSE_UTILITY_INTERUPT_EVENT = "evse_utility_interrupt_event"
    EVSE_ISOLATION_MONITORING_ACTIVE = "evse_isolation_monitoring_active"
    EVSE_EMERGENCY_SHUTDOWN = "evse_emergency_shutdown"
    EVSE_MALFUNCTION = "evse_malfunction"


@dataclass
class MaxCurrentByPhase:
    l1: float
    l2: float
    l3: float


@dataclass
class ACStatusAndLimits:
    max_current: MaxCurrentByPhase
    nominal_voltage: float
    rcd_error: bool

    def __post_init__(self) -> None:
        """After initialization, convert dicts to correct class instances."""
        if isinstance(self.max_current, dict):
            self.max_current = MaxCurrentByPhase(**self.max_current)


@dataclass
class DCStatusAndLimits:
    present_voltage: float
    present_current: float
    max_current: float
    min_current: float
    max_voltage: float
    min_voltage: float
    max_power: float
    peak_current_ripple: float
    status_code: EVSEStatusCode
    isolation_status: Optional[EVSEIsolationStatus] = None
    energy_to_be_delivered: Optional[float] = None
    current_reg_tolerance: Optional[float] = None


@dataclass
class EVSEStatusAndLimitsPayload:
    evse_id: str
    ac: Optional[ACStatusAndLimits] = None
    dc: Optional[DCStatusAndLimits] = None

    def __post_init__(self) -> None:
        """After initialization, convert dicts to correct class instances."""
        if isinstance(self.ac, dict):
            self.ac = ACStatusAndLimits(**self.ac)
        if isinstance(self.dc, dict):
            self.dc = DCStatusAndLimits(**self.dc)


@dataclass
class CsStatusAndLimitsPayload:
    evses: List[EVSEStatusAndLimitsPayload]

    def __post_init__(self) -> None:
        """After initialization, convert dicts to correct class instances."""
        self.evses = [
            EVSEStatusAndLimitsPayload(**e) if isinstance(e, dict) else e
            for e in self.evses
        ]


class EnergyTransferModeEnum(str, Enum):
    """See sections 8.5.2.4 and 8.4.3.8.2 in ISO 15118-2."""

    AC_SINGLE_PHASE_CORE = "AC_single_phase_core"
    AC_THREE_PHASE_CORE = "AC_three_phase_core"
    DC_CORE = "DC_core"
    DC_EXTENDED = "DC_extended"
    DC_COMBO_CORE = "DC_combo_core"
    DC_UNIQUE = "DC_unique"


@dataclass
class CsDCConnectorService:
    connector_type: EnergyTransferModeEnum
    control_mode: str
    mobility_needs: str
    pricing: str


@dataclass
class CsDCBptConnectorService:
    connector_type: EnergyTransferModeEnum
    control_mode: str
    mobility_needs: str
    pricing: str
    bpt_channel: str
    generator_mode: str
    free_service: bool


@dataclass
class CsACConnectorService:
    connector_type: EnergyTransferModeEnum
    control_mode: str
    nominal_voltage: int
    mobility_needs: str
    pricing: str
    free_service: bool


@dataclass
class CsACBptConnectorService:
    connector_type: EnergyTransferModeEnum
    control_mode: str
    nominal_voltage: int
    mobility_needs: str
    pricing: str
    bpt_channel: str
    generator_mode: str
    free_service: bool
    grid_island_detection_mode: Optional[str] = None


@dataclass
class CsConnectorServices:
    dc: Optional[CsDCConnectorService] = None
    dc_bpt: Optional[CsDCBptConnectorService] = None
    ac: Optional[CsACConnectorService] = None
    ac_bpt: Optional[CsACBptConnectorService] = None

    def __post_init__(self) -> None:
        """After initialization, convert dicts to correct class instances."""
        if isinstance(self.dc, dict):
            self.dc = CsDCConnectorService(**self.dc)
        if isinstance(self.dc_bpt, dict):
            self.dc_bpt = CsDCBptConnectorService(**self.dc_bpt)
        if isinstance(self.ac, dict):
            self.ac = CsACConnectorService(**self.ac)
        if isinstance(self.ac_bpt, dict):
            self.ac_bpt = CsACBptConnectorService(**self.ac_bpt)


@dataclass
class CsConnectorParameters:
    id: int
    services: CsConnectorServices

    def __post_init__(self) -> None:
        """After initialization, convert dicts to correct class instances."""
        if isinstance(self.services, dict):
            self.services = CsConnectorServices(**self.services)


@dataclass
class CsEvseParameters:
    evse_id: str
    connectors: List[CsConnectorParameters]
    supports_eim: bool
    network_interface: str

    def __post_init__(self) -> None:
        """After initialization, convert dicts to correct class instances."""
        self.connectors = [
            CsConnectorParameters(**c) if isinstance(c, dict) else c
            for c in self.connectors
        ]


@dataclass
class CsParametersPayload:
    sw_version: str
    hw_version: str
    number_of_evses: int
    parameters: List[CsEvseParameters]

    def __post_init__(self) -> None:
        """After initialization, convert dicts to correct class instances."""
        self.parameters = [
            CsEvseParameters(**p) if isinstance(p, dict) else p for p in self.parameters
        ]


@dataclass
class EVSEConfig:
    cs_config: CsParametersPayload
    cs_limits: CsStatusAndLimitsPayload


async def load_object(path: str, data_class: str):
    try:
        async with async_open(path, "r") as f:
            json_content = await f.read()
            data = json.loads(json_content)
            return dacite.from_dict(
                data_class=data_class,
                data=data,
                config=dacite.Config(cast=[Enum]),
            )
    except Exception as e:
        raise Exception(
            f"Error loading {data_class} from file ({e}). Path used: {path}"
        )


async def get_cs_config_and_limits(cs_config_path: str, cs_limits_path: str):
    logger.info("Getting CS configuration through cs_config file")
    cs_config = await load_object(cs_config_path, CsParametersPayload)
    logger.info("Getting CS limits through cs_limits file")
    cs_limits = await load_object(cs_limits_path, CsStatusAndLimitsPayload)
    return cs_config, cs_limits


async def build_evse_configs(cs_config_path: str, cs_limits_path: str):
    evses_cs_config, evses_cs_limits = await get_cs_config_and_limits(
        cs_config_path, cs_limits_path
    )
    evse_cs_limits = {}
    for evse_limit in evses_cs_limits.evses:
        evse_cs_limits[evse_limit.evse_id] = evse_limit

    evse_configs = {}
    for cs_config in evses_cs_config.parameters:
        try:
            cs_limits = evse_cs_limits[cs_config.evse_id]
        except KeyError:
            raise KeyError(f"CS limits missing for this EVSE: {cs_config.evse_id}")
        evse_config = EVSEConfig(cs_config=cs_config, cs_limits=cs_limits)
        evse_configs[cs_config.network_interface] = evse_config
    return evse_configs
