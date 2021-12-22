"""
This module contains the code to retrieve (hardware-related) data from the EVSE
(Electric Vehicle Supply Equipment).
"""
import logging
import time
from typing import List, Optional, Union

from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.shared.exceptions import InvalidProtocolError
from iso15118.shared.messages.enums import Namespace, Protocol
from iso15118.shared.messages.iso15118_2.datatypes import (
    ACEVSEChargeParameter,
    ACEVSEStatus,
    DCEVSEChargeParameter,
    DCEVSEStatus,
    DCEVSEStatusCode,
    EnergyTransferMode,
    EnergyTransferModeEnum,
    EVSENotification,
    IsolationLevel,
)
from iso15118.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118.shared.messages.iso15118_2.datatypes import (
    PMaxScheduleEntry,
    PMaxScheduleEntryDetails,
    PVEVSEMaxCurrent,
    PVEVSENominalVoltage,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
    PVPMax,
    RelativeTimeInterval,
    SalesTariff,
    SalesTariffEntry,
    SAScheduleTuple,
    SAScheduleTupleEntry,
    UnitSymbol,
)
from iso15118.shared.messages.iso15118_20.common_messages import ProviderID
from iso15118.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20

logger = logging.getLogger(__name__)


class SimEVSEController(EVSEControllerInterface):
    """
    A simulated version of an EVSE controller
    """

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================

    def get_evse_id(self) -> str:
        """Overrides EVSEControllerInterface.get_evse_id()."""
        return "UK123E1234"

    def get_supported_energy_transfer_modes(
        self, as_enums: bool = False
    ) -> Union[List[EnergyTransferMode], List[EnergyTransferModeEnum]]:
        """Overrides EVSEControllerInterface.get_supported_energy_transfer_modes()."""
        ac_single_phase = EnergyTransferMode(
            value=EnergyTransferModeEnum.AC_SINGLE_PHASE_CORE
        )
        ac_three_phase = EnergyTransferMode(
            value=EnergyTransferModeEnum.AC_THREE_PHASE_CORE
        )

        if as_enums:
            return [ac_single_phase.value, ac_three_phase.value]

        return [ac_single_phase, ac_three_phase]

    def is_authorised(self) -> bool:
        """Overrides EVSEControllerInterface.is_authorised()."""
        return True

    def get_sa_schedule_list(
        self, max_schedule_entries: Optional[int], departure_time: int = 0
    ) -> Optional[List[SAScheduleTuple]]:
        """Overrides EVSEControllerInterface.get_sa_schedule_list()."""
        sa_schedule_list: List[SAScheduleTuple] = []
        p_max_schedule_entries: List[PMaxScheduleEntry] = []

        # PMaxSchedule
        p_max = PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT)
        entry_details = PMaxScheduleEntryDetails(
            p_max=p_max, time_interval=RelativeTimeInterval(start=0, duration=3600)
        )
        p_max_schedule_entries.append(PMaxScheduleEntry(entry_details=entry_details))

        # SalesTariff
        sales_tariff_entries: List[SalesTariffEntry] = []
        sales_tariff_entry_1 = SalesTariffEntry(
            e_price_level=1, time_interval=RelativeTimeInterval(start=0)
        )
        sales_tariff_entry_2 = SalesTariffEntry(
            e_price_level=2,
            time_interval=RelativeTimeInterval(start=1801, duration=1799),
        )
        sales_tariff_entries.append(sales_tariff_entry_1)
        sales_tariff_entries.append(sales_tariff_entry_2)
        sales_tariff = SalesTariff(
            id="id1",
            sales_tariff_id=10,  # a random id
            sales_tariff_entry=sales_tariff_entries,
            num_e_price_levels=2,
        )

        # Putting the list of SAScheduleTuple entries together
        sa_schedule_tuple_entry = SAScheduleTupleEntry(
            sa_schedule_tuple_id=1,
            p_max_schedule=p_max_schedule_entries,
            sales_tariff=sales_tariff,
        )
        sa_schedule_tuple = SAScheduleTuple(tuple=sa_schedule_tuple_entry)
        # TODO We could also implement an optional SalesTariff, but for the sake of
        #      time we'll do that later (after the basics are implemented).
        #      When implementing the SalesTariff, we also need to apply a digital
        #      signature to it.
        sa_schedule_list.append(sa_schedule_tuple)

        # TODO We need to take care of [V2G2-741], which says that the SECC needs to
        #      resend a previously agreed SAScheduleTuple and the "period of time
        #      this SAScheduleTuple applies for shall be reduced by the time already
        #      elapsed".

        return sa_schedule_list

    def get_meter_info(self, protocol: Protocol) -> Union[MeterInfoV2, MeterInfoV20]:
        """Overrides EVSEControllerInterface.get_meter_info()."""
        if protocol == Protocol.ISO_15118_2:
            return MeterInfoV2(
                meter_id="Switch-Meter-123", meter_reading=12345, t_meter=time.time()
            )

        if protocol.ns.startswith(Namespace.ISO_V20_BASE):
            return MeterInfoV20(
                meter_id="Switch-Meter-123",
                charged_energy_reading_wh=10,
                meter_timestamp=time.time(),
            )

        logger.error(f"Unknown protocol {protocol}, can't determine MeterInfo type")
        raise InvalidProtocolError

    def get_supported_providers(self) -> Optional[List[ProviderID]]:
        """Overrides EVSEControllerInterface.get_supported_providers()."""
        return None

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    def get_ac_evse_status(self) -> ACEVSEStatus:
        """Overrides EVSEControllerInterface.get_ac_evse_status()."""
        return ACEVSEStatus(
            notification_max_delay=0, evse_notification=EVSENotification.NONE, rcd=False
        )

    def get_ac_evse_charge_parameter(self) -> ACEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_ac_evse_charge_parameter()."""
        evse_nominal_voltage = PVEVSENominalVoltage(
            multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
        )
        evse_max_current = PVEVSEMaxCurrent(
            multiplier=0, value=32, unit=UnitSymbol.AMPERE
        )
        return ACEVSEChargeParameter(
            ac_evse_status=self.get_ac_evse_status(),
            evse_nominal_voltage=evse_nominal_voltage,
            evse_max_current=evse_max_current,
        )

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    def get_dc_evse_status(self) -> DCEVSEStatus:
        """Overrides EVSEControllerInterface.get_dc_evse_status()."""
        return DCEVSEStatus(
            evse_notification=EVSENotification.NONE,
            notification_max_delay=0,
            evse_isolation_status=IsolationLevel.VALID,
            evse_status_code=DCEVSEStatusCode.EVSE_READY,
        )

    def get_dc_evse_charge_parameter(self) -> DCEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_dc_evse_charge_parameter()."""
        pass

    def get_evse_present_voltage(self) -> PVEVSEPresentVoltage:
        """Overrides EVSEControllerInterface.get_evse_present_voltage()."""
        return PVEVSEPresentVoltage(multiplier=0, value=230, unit="V")

    def get_evse_present_current(self) -> PVEVSEPresentCurrent:
        """Overrides EVSEControllerInterface.get_evse_present_current()."""
        return PVEVSEPresentCurrent(multiplier=0, value=10, unit="A")
